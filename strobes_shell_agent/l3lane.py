"""Packet-level egress enforcement — the lane where real tools work.

The proxy lane can only carry traffic a tool is willing to hand it. That covers
HTTP clients, but it fails exactly where a pentest bridge needs to work: a port
scanner's whole job is to open raw connections, so it either ignores the proxy
or, with the sandbox blocking it, reports every port as ``filtered``. Those are
confident, wrong answers about the target — worse than an error.

Here the tool uses ordinary sockets and the *kernel* decides. Commands run as a
dedicated account, and nftables rules keyed on that account's uid enforce the
policy on the packets themselves. That is both correct for the tool and
stricter than a proxy: a raw SYN is matched the same as a ``connect``, so
nothing gets out by declining to cooperate.

Verified: with a policy allowing one address, ``nmap -sS`` against it returns
``open`` while the out-of-scope address returns ``filtered``, and the nftables
counters show the raw packets hitting the uid rule.

Requirements: Linux, and ``CAP_NET_ADMIN`` to load the ruleset (root in
practice). Where that is unavailable the bridge falls back to the proxy lane,
which is weaker but needs no privileges — :func:`available` is what decides.

SYN scanning additionally needs ``CAP_NET_RAW`` on the scanner binary. nmap
checks ``euid == 0`` rather than its capabilities, so it refuses to SYN scan as
a non-root uid; its own ``NMAP_PRIVILEGED`` variable is the supported way to
tell it to trust its capabilities instead, and :func:`environment` sets it.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from typing import Optional

from strobes_shell_agent.netpolicy import NetworkPolicy

#: The account commands run as. The nftables rules are keyed on its uid, so it
#: exists for no other purpose and nothing else should run as it.
ACCOUNT = "strobes-scan"

#: Our own nftables table. Owned entirely by the bridge: loaded, replaced and
#: deleted as a unit, so it never disturbs the host's other rules.
TABLE = "strobes_scope"

#: Binaries granted CAP_NET_RAW so the sandboxed account can send raw packets.
#: Without this a SYN scan is impossible for a non-root uid.
RAW_CAPABLE = ("nmap", "naabu", "masscan")


class L3Unavailable(RuntimeError):
    """This host cannot enforce at the packet level."""


def available() -> bool:
    """True when this host can enforce with nftables."""
    if not sys.platform.startswith("linux"):
        return False
    if shutil.which("nft") is None:
        return False
    return _can_load_rules()


def _can_load_rules() -> bool:
    """Probe for CAP_NET_ADMIN by listing rules, which needs the same right."""
    try:
        return subprocess.run(["nft", "list", "ruleset"],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def status() -> dict:
    uid = account_uid()
    return {
        "platform_supported": sys.platform.startswith("linux"),
        "nft_present": shutil.which("nft") is not None,
        "can_load_rules": _can_load_rules() if sys.platform.startswith("linux") else False,
        "account": ACCOUNT,
        "uid": uid,
        "table_loaded": table_loaded(),
    }


# ---------------------------------------------------------------------------
# The account
# ---------------------------------------------------------------------------

def account_uid() -> Optional[int]:
    try:
        return pwd.getpwnam(ACCOUNT).pw_uid
    except KeyError:
        return None


def ensure_account() -> int:
    """Create the scan account if missing, and return its uid."""
    uid = account_uid()
    if uid is not None:
        return uid
    for argv in (
        ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", ACCOUNT],
        ["adduser", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", ACCOUNT],
    ):
        if shutil.which(argv[0]) is None:
            continue
        if subprocess.run(argv, capture_output=True).returncode == 0:
            break
    uid = account_uid()
    if uid is None:
        raise L3Unavailable(f"could not create the {ACCOUNT} account")
    return uid


def grant_raw_capabilities(search_path: Optional[str] = None) -> dict:
    """Give the scanners CAP_NET_RAW so the scan account can SYN scan.

    Without it nmap falls back to a connect scan, which still works and is still
    filtered — so a failure here degrades the lane rather than breaking it.
    """
    granted, skipped = [], []
    if shutil.which("setcap") is None:
        return {"granted": [], "skipped": list(RAW_CAPABLE), "reason": "setcap not installed"}
    for tool in RAW_CAPABLE:
        path = shutil.which(tool, path=search_path)
        if not path:
            skipped.append(tool)
            continue
        rc = subprocess.run(
            ["setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", path],
            capture_output=True,
        ).returncode
        (granted if rc == 0 else skipped).append(tool)
    return {"granted": granted, "skipped": skipped}


# ---------------------------------------------------------------------------
# The ruleset
# ---------------------------------------------------------------------------

def table_loaded() -> bool:
    try:
        out = subprocess.run(["nft", "list", "tables"], capture_output=True,
                             text=True, timeout=10)
        return TABLE in (out.stdout or "")
    except (OSError, subprocess.SubprocessError):
        return False


def apply_policy(policy: NetworkPolicy, uid: Optional[int] = None) -> dict:
    """Render ``policy`` to nftables and load it, replacing any previous rules.

    Host entries are resolved here, because packets carry addresses and not
    names. That is the one thing the proxy lane does better — it sees the name
    the client asked for — so a scope written in hostnames is enforced here
    against whatever those names resolved to at load time.
    """
    if uid is None:
        uid = ensure_account()
    resolved = policy.resolve()
    ruleset = resolved.to_nftables(uid=uid, table=TABLE)

    # Replace atomically: delete-then-load in a single nft invocation, so there
    # is no window where the old scope or no scope at all is in force.
    script = f"table inet {TABLE} {{}}\ndelete table inet {TABLE}\n{ruleset}\n"
    proc = subprocess.run(["nft", "-f", "-"], input=script, text=True,
                          capture_output=True)
    if proc.returncode != 0:
        raise L3Unavailable(f"could not load the ruleset: {proc.stderr.strip()}")

    return {
        "uid": uid,
        "table": TABLE,
        "allow": sorted(resolved.allow_cidrs),
        "unresolved": list(resolved.unresolved),
        "default_egress": policy.default_egress,
    }


def clear_policy() -> None:
    """Remove the bridge's table, leaving the host's other rules alone."""
    subprocess.run(["nft", "-f", "-"], text=True, capture_output=True,
                   input=f"table inet {TABLE} {{}}\ndelete table inet {TABLE}\n")


# ---------------------------------------------------------------------------
# Running a command
# ---------------------------------------------------------------------------

def environment(base: Optional[dict] = None) -> dict:
    """Environment for a command in this lane.

    No proxy variables: the point of this lane is that tools use real sockets.
    Any left over from the proxy lane are stripped, or a tool would try to reach
    a proxy that is not listening.
    """
    env = dict(base or os.environ)
    for var in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
                "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"):
        env.pop(var, None)
    # nmap checks euid rather than its capabilities, so it needs telling that a
    # non-root uid holding CAP_NET_RAW may raw-scan. Without this it silently
    # downgrades to a connect scan.
    env["NMAP_PRIVILEGED"] = "1"
    return env


def wrap_shell(command: str, uid: Optional[int] = None) -> list:
    """argv that runs ``command`` as the scan account.

    ``setpriv`` is preferred over ``su``: it drops to the uid without a login
    shell, a PAM stack or a new session, so nothing between here and the command
    can put it back under a different identity — and identity is what the rules
    are keyed on.
    """
    if uid is None:
        uid = account_uid()
        if uid is None:
            raise L3Unavailable("the scan account does not exist; call ensure_account()")
    if shutil.which("setpriv"):
        return ["setpriv", "--reuid", str(uid), "--regid", str(uid),
                "--clear-groups", "--", "/bin/sh", "-c", command]
    if shutil.which("runuser"):
        return ["runuser", "-u", ACCOUNT, "--", "/bin/sh", "-c", command]
    return ["su", "-s", "/bin/sh", ACCOUNT, "-c", command]
