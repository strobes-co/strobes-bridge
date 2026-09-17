"""Windows egress confinement — a dedicated account fenced by a WFP filter.

Windows has no Seatbelt and no bubblewrap, so the boundary is drawn around a
*identity* instead of a process tree: commands run as a dedicated low-privilege
local account, and a Windows Filtering Platform rule blocks that account's
outbound traffic. Because the filter matches the account's SID it follows every
child process automatically, which is what makes it equivalent to the sandboxes
on the other two platforms — a tool that ignores the proxy environment is still
fenced.

Windows Firewall is used as the WFP front end rather than ``fwpuclnt.dll``
directly: its rules compile down to the same engine, they are inspectable with
``Get-NetFirewallRule`` (so an operator can audit what the bridge installed),
and they survive reboots without a service to babysit. The cost is one real
limitation, documented in :func:`setup` — the firewall does not filter loopback,
so the account can reach *any* local port, not only the proxy's.

Nothing here runs outside Windows. Every entry point is import-safe on other
platforms so the module can be unit-tested anywhere; the parts that touch the
OS check :data:`IS_WINDOWS` and refuse politely.

**Unverified.** This backend has not been executed on Windows. It is written
from the documented APIs, and :func:`strobes_shell_agent.sandbox.selftest` is
the thing that proves or disproves it on a real host — run it after ``setup``.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

#: The local account commands run as. Deliberately not an existing account:
#: the firewall rule is written against this SID and nothing else should
#: inherit it.
ACCOUNT = "strobes-sandbox"

#: Firewall rules the bridge owns, by display name, so setup is idempotent and
#: teardown can find them again.
RULE_BLOCK = "Strobes bridge - sandbox egress block"

_STATE_FILE = "winsandbox.json"


class WindowsSetupError(RuntimeError):
    """Setup could not complete — usually missing elevation."""


# ---------------------------------------------------------------------------
# PowerShell plumbing
# ---------------------------------------------------------------------------

def _powershell(script: str, check: bool = True) -> str:
    """Run a PowerShell snippet and return stdout."""
    if not IS_WINDOWS:
        raise WindowsSetupError("Windows-only")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise WindowsSetupError(
            f"powershell failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def is_elevated() -> bool:
    """True when the current process can install firewall rules."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Rule construction (pure — unit-testable on any platform)
# ---------------------------------------------------------------------------

def _sddl(sid: str) -> str:
    """The SDDL form ``-LocalUser`` expects for a single account."""
    return f"D:(A;;CC;;;{sid})"


def block_rules(sid: str) -> list:
    """The PowerShell that fences ``sid`` — block every outbound connection.

    One unconditional rule, and deliberately so. The tempting alternative is
    "block everything except the proxy port", but Windows Firewall matches
    ``-RemotePort`` regardless of address, so excepting 60080 would also permit
    ``evil.com:60080``. Blocking outright avoids that hole.

    The proxy stays reachable because **Windows Firewall does not filter
    loopback traffic** — it is exempt in the engine, so 127.0.0.1 is unaffected
    by any rule written here.

    That exemption is also this backend's one real weakness, and it cannot be
    fixed at this layer: the sandbox account can reach *any* local port, not
    just the proxy's. Narrowing it needs a custom WFP sublayer via
    ``fwpuclnt.dll``, which can filter loopback where the firewall cannot.
    Mitigating for now: the account is low-privilege and separate, so local
    services that authenticate are still protected from it.
    """
    return [
        f"New-NetFirewallRule -DisplayName '{RULE_BLOCK}' "
        "-Direction Outbound -Action Block -Profile Any "
        f"-LocalUser '{_sddl(sid)}' -Enabled True"
    ]


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------

def _state_path() -> Path:
    from strobes_shell_agent.config import CONFIG_DIR
    return Path(CONFIG_DIR) / _STATE_FILE


def _protect(secret: str) -> str:
    """DPAPI-encrypt at machine scope so the password is not stored in clear."""
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    raw = secret.encode("utf-16-le")
    src = BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw),
                                     ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    # 4 = CRYPTPROTECT_LOCAL_MACHINE: any admin on this host can read it, which
    # is the same trust boundary that installed the account in the first place.
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(src), None, None, None, None, 4, ctypes.byref(out)
    ):
        raise WindowsSetupError("CryptProtectData failed")
    return base64.b64encode(
        ctypes.string_at(out.pbData, out.cbData)
    ).decode()


def _unprotect(blob_b64: str) -> str:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    raw = base64.b64decode(blob_b64)
    src = BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw),
                                     ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)
    ):
        raise WindowsSetupError("CryptUnprotectData failed")
    return ctypes.string_at(out.pbData, out.cbData).decode("utf-16-le")


def _save_state(sid: str, password: str, port_range: tuple) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "account": ACCOUNT,
        "sid": sid,
        "password": _protect(password),
        "port_range": list(port_range),
    }))
    # Readable only by the installing administrator and SYSTEM.
    _powershell(
        f"$p='{path}'; $a=Get-Acl $p; $a.SetAccessRuleProtection($true,$false); "
        "$a.Access | ForEach-Object { $a.RemoveAccessRule($_) | Out-Null }; "
        "$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        "'BUILTIN\\Administrators','FullControl','Allow'))); "
        "$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        "'NT AUTHORITY\\SYSTEM','FullControl','Allow'))); Set-Acl $p $a",
        check=False,
    )


def load_state() -> Optional[dict]:
    path = _state_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Setup / teardown / verification
# ---------------------------------------------------------------------------

def setup(port_range: tuple) -> dict:
    """Create the sandbox account and install its egress filter.

    Requires elevation, and is idempotent: re-running repairs a missing account
    or a deleted rule rather than failing.
    """
    if not IS_WINDOWS:
        raise WindowsSetupError("Windows-only")
    if not is_elevated():
        raise WindowsSetupError(
            "run this from an elevated prompt — creating a local account and "
            "installing firewall rules both require Administrator"
        )

    password = secrets.token_urlsafe(24) + "aA1!"  # satisfies complexity policy
    existing = load_state()

    if not _account_exists():
        _powershell(
            f"$p = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
            f"New-LocalUser -Name '{ACCOUNT}' -Password $p "
            "-Description 'Strobes bridge sandboxed command execution' "
            "-PasswordNeverExpires -UserMayNotChangePassword | Out-Null"
        )
    elif existing:
        # Account is already there; reuse the stored password rather than
        # resetting it, so a half-finished setup does not orphan credentials.
        password = _unprotect(existing["password"])
    else:
        _powershell(
            f"$p = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
            f"Set-LocalUser -Name '{ACCOUNT}' -Password $p"
        )

    sid = _account_sid()

    # Rebuild from scratch so a partial previous run cannot leave a stale rule.
    _remove_rules()
    for script in block_rules(sid):
        _powershell(script + " | Out-Null")

    _save_state(sid, password, port_range)
    return {
        "account": ACCOUNT,
        "sid": sid,
        "port_range": list(port_range),
        "rules": [RULE_BLOCK],
    }


def teardown() -> dict:
    """Remove the rules and the account."""
    if not IS_WINDOWS:
        raise WindowsSetupError("Windows-only")
    if not is_elevated():
        raise WindowsSetupError("teardown requires Administrator")
    _remove_rules()
    _powershell(f"Remove-LocalUser -Name '{ACCOUNT}' -ErrorAction SilentlyContinue",
                check=False)
    path = _state_path()
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
    return {"removed": True}


def _remove_rules() -> None:
    for name in (RULE_BLOCK,):
        _powershell(
            f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue",
            check=False,
        )


def _account_exists() -> bool:
    out = _powershell(
        f"if (Get-LocalUser -Name '{ACCOUNT}' -ErrorAction SilentlyContinue) "
        "{'yes'} else {'no'}", check=False)
    return out.strip() == "yes"


def _account_sid() -> str:
    sid = _powershell(f"(Get-LocalUser -Name '{ACCOUNT}').SID.Value")
    if not sid.startswith("S-1-"):
        raise WindowsSetupError(f"could not read the {ACCOUNT} SID (got {sid!r})")
    return sid


def ready() -> bool:
    """True when the account and both rules are in place."""
    if not IS_WINDOWS:
        return False
    state = load_state()
    if not state:
        return False
    try:
        if not _account_exists():
            return False
        found = _powershell(
            f"if (Get-NetFirewallRule -DisplayName '{RULE_BLOCK}' "
            "-ErrorAction SilentlyContinue) {'1'} else {'0'}", check=False)
        return found.strip() == "1"
    except WindowsSetupError:
        return False


def status() -> dict:
    state = load_state()
    return {
        "platform_supported": IS_WINDOWS,
        "configured": bool(state),
        "ready": ready(),
        "account": ACCOUNT,
        "sid": (state or {}).get("sid"),
        "port_range": (state or {}).get("port_range"),
        "elevated": is_elevated(),
    }


# ---------------------------------------------------------------------------
# Running a command as the sandbox account
# ---------------------------------------------------------------------------

def run_as_sandbox(command: str, env: dict, cwd: Optional[str],
                   timeout: int) -> tuple:
    """Run ``command`` as the sandbox account. Returns ``(rc, stdout, stderr)``.

    Uses ``CreateProcessWithLogonW`` because the bridge itself must keep its own
    (unrestricted) identity — it needs the network to report results. Output is
    redirected to temporary files rather than pipes: the command is awaited to
    completion anyway, and files avoid the deadlock-prone business of pumping
    two inherited pipe handles by hand.
    """
    if not IS_WINDOWS:
        raise WindowsSetupError("Windows-only")
    state = load_state()
    if not state:
        raise WindowsSetupError("windows sandbox is not set up; run `sandbox-setup`")

    import ctypes
    import tempfile
    from ctypes import wintypes

    password = _unprotect(state["password"])

    out_path = tempfile.mktemp(prefix="strobes-out-")
    err_path = tempfile.mktemp(prefix="strobes-err-")

    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ_WRITE = 0x00000003
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", wintypes.LPVOID),
                    ("bInheritHandle", wintypes.BOOL)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", wintypes.LPVOID), ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    kernel32 = ctypes.windll.kernel32

    def _open(path):
        h = kernel32.CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ_WRITE,
                                 ctypes.byref(sa), CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, None)
        if h == wintypes.HANDLE(-1).value:
            raise WindowsSetupError(f"could not create {path}")
        return h

    h_out, h_err = _open(out_path), _open(err_path)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    si.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
    si.hStdOutput, si.hStdError = h_out, h_err
    pi = PROCESS_INFORMATION()

    # The environment must be a NUL-separated, NUL-terminated block, sorted.
    block = "".join(f"{k}={v}\0" for k, v in sorted(env.items())) + "\0"
    env_buf = ctypes.create_unicode_buffer(block)

    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    LOGON_WITH_PROFILE = 0x00000001

    ok = ctypes.windll.advapi32.CreateProcessWithLogonW(
        ACCOUNT, ".", password,
        LOGON_WITH_PROFILE,
        None, ctypes.create_unicode_buffer(f'cmd.exe /c {command}'),
        CREATE_UNICODE_ENVIRONMENT,
        ctypes.byref(env_buf), cwd,
        ctypes.byref(si), ctypes.byref(pi),
    )
    if not ok:
        err = ctypes.get_last_error()
        for h in (h_out, h_err):
            kernel32.CloseHandle(h)
        raise WindowsSetupError(f"CreateProcessWithLogonW failed (error {err})")

    WAIT_TIMEOUT = 0x00000102
    waited = kernel32.WaitForSingleObject(pi.hProcess, int(timeout * 1000))
    if waited == WAIT_TIMEOUT:
        kernel32.TerminateProcess(pi.hProcess, 1)
        rc = -1
    else:
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        rc = int(code.value)

    for h in (h_out, h_err, pi.hProcess, pi.hThread):
        kernel32.CloseHandle(h)

    def _read(path):
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    return rc, _read(out_path), _read(err_path)
