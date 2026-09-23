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

**Verified** on Windows Server 2022: the firewall block, the loopback exemption,
and :func:`strobes_shell_agent.sandbox.selftest` all confirmed against a live
host. Two host-level preconditions had to be fixed to get there and matter for
any Windows version, not just this one:

* the sandbox account needs :data:`LOGON_RIGHTS` — Windows Server's default
  local security policy grants a new local account neither "Log on as a batch
  job" nor "Allow log on locally", so :func:`setup` grants both explicitly
  rather than assuming a default that varies by SKU.
* commands run as the account via a Scheduled Task rather than
  ``CreateProcessWithLogonW`` — see :func:`run_as_sandbox` for why the latter
  does not reliably work here.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

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


#: Rights the sandbox account needs to be logged on at all. Windows Server's
#: default local security policy grants neither to a freshly created local
#: user — without them every logon this module needs (Task Scheduler's batch
#: logon, and an interactive-style logon) fails outright, which is a
#: precondition failure and easy to mistake for the egress filter itself being
#: broken. Client SKUs are usually more permissive by default, but granting
#: both explicitly keeps behavior identical across Windows versions instead of
#: depending on which default the target happens to ship with.
LOGON_RIGHTS = ("SeBatchLogonRight", "SeInteractiveLogonRight")


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
    """Where the sandbox account's credentials live.

    Deliberately machine-wide (``%ProgramData%``), not the per-user config dir
    ``setup()`` would otherwise inherit from :mod:`config`. ``setup()`` requires
    elevation and is typically run once by an administrator, but ``connect``
    is designed to run as whatever ordinary user is logged into the host (the
    installer needs no elevation and installs per-user, under
    ``%LOCALAPPDATA%``) — a per-user path would mean that user's own
    ``connect`` can never find the state a *different* admin account set up.
    The password is still DPAPI-protected at machine scope, and the file's own
    ACL (:func:`_save_state`) keeps it read-only for anyone but the admin who
    wrote it.
    """
    root = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(root) / "StrobesShellAgent" / _STATE_FILE


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
    # Explicit rather than relying on inheriting %ProgramData%'s own ACL: any
    # local user must be able to traverse into this directory to reach the
    # state file, on whatever this host's default happens to be.
    _powershell(f'icacls "{path.parent}" /grant "*S-1-5-32-545:(OI)(CI)RX" | Out-Null',
                check=False)
    path.write_text(json.dumps({
        "account": ACCOUNT,
        "sid": sid,
        "password": _protect(password),
        "port_range": list(port_range),
    }))
    # Writable only by admins and SYSTEM (setup/teardown), but readable by any
    # local user: connect() runs as whatever ordinary user is logged in and
    # must be able to load this to find the sandbox account at all. That's
    # safe because run_as_sandbox's read is exactly the access it needs
    # anyway (it operates as this account by design), and the password inside
    # is still DPAPI-protected at machine scope, not stored in clear.
    _powershell(
        f"$p='{path}'; $a=Get-Acl $p; $a.SetAccessRuleProtection($true,$false); "
        "$a.Access | ForEach-Object { $a.RemoveAccessRule($_) | Out-Null }; "
        "$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        "'BUILTIN\\Administrators','FullControl','Allow'))); "
        "$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        "'NT AUTHORITY\\SYSTEM','FullControl','Allow'))); "
        "$a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("
        "'BUILTIN\\Users','Read','Allow'))); Set-Acl $p $a",
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

    # Without these, every logon this backend needs — the scheduled task that
    # runs sandboxed commands, and CreateProcessWithLogonW as a fallback — fails
    # with ERROR_LOGON_TYPE_NOT_GRANTED before a single command ever runs.
    # Windows Server does not grant them to a new local account by default;
    # granting explicitly avoids depending on which SKU's default this is.
    _grant_logon_rights(sid)

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
        "logon_rights": list(LOGON_RIGHTS),
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


def _grant_logon_rights(sid: str) -> None:
    """Grant :data:`LOGON_RIGHTS` to ``sid`` via the local security policy.

    ``secedit`` round-trips the *entire* user-rights policy through a text
    file, which sounds heavier than it is: this only ever adds ``sid`` to the
    handful of lines it targets, so it cannot drop a right some other account
    already holds, and running it again when the account already holds a
    right is a no-op. There is no narrower supported API for this —
    ``LsaAddAccountRights`` is the alternative, but it demands hand-rolled
    ``LSA_UNICODE_STRING``/SID marshaling for a one-time setup step, which is
    worse to get subtly wrong than one securely-generated policy file.

    A currently-existing account is rendered by *name*, not by the SID this
    function is called with — ``secedit`` resolves it on export — so the
    already-granted check matches either form; matching the SID alone would
    treat an already-granted right as missing and add it again on every call.
    """
    script = f"""
$ErrorActionPreference = 'Stop'
$sid = '{sid}'
$account = '{_ps_single_quote(ACCOUNT)}'
$rights = @({", ".join(f"'{r}'" for r in LOGON_RIGHTS)})
$cfgPath = Join-Path $env:TEMP ("strobes-secpol-{{0}}.cfg" -f ([guid]::NewGuid()))
try {{
    secedit /export /cfg $cfgPath /areas USER_RIGHTS | Out-Null
    $lines = Get-Content $cfgPath
    foreach ($right in $rights) {{
        $found = $false
        $lines = $lines | ForEach-Object {{
            if ($_ -match "^\\s*$right\\s*=") {{
                $found = $true
                $hasSid = $_ -match [regex]::Escape($sid)
                $hasName = $_ -match "(?i)(^|,)\\s*$([regex]::Escape($account))\\s*(,|$)"
                if (-not $hasSid -and -not $hasName) {{ "$_,*$sid" }} else {{ $_ }}
            }} else {{ $_ }}
        }}
        if (-not $found) {{
            $idx = 0
            for ($i = 0; $i -lt $lines.Count; $i++) {{
                if ($lines[$i] -match '^\\[Privilege Rights\\]') {{ $idx = $i; break }}
            }}
            $lines = $lines[0..$idx] + "$right = *$sid" + $lines[($idx + 1)..($lines.Count - 1)]
        }}
    }}
    Set-Content -Path $cfgPath -Value $lines
    secedit /configure /db "$env:windir\\security\\local.sdb" /cfg $cfgPath /areas USER_RIGHTS | Out-Null
}} finally {{
    Remove-Item $cfgPath -ErrorAction SilentlyContinue
}}
"""
    _powershell(script)


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


def _has_logon_rights(sid: str) -> Optional[bool]:
    """Whether ``sid`` currently holds every right in :data:`LOGON_RIGHTS``.

    Local security policy is machine-wide state outside this module's control
    — a GPO refresh or another tool can reset it — so :func:`ready` checks the
    live policy rather than trusting that :func:`setup` once granted it.

    A currently-existing account is rendered by *name*, not by ``sid`` —
    ``secedit`` resolves it on export — so this matches either form; matching
    the SID alone would report an already-granted right as missing.

    Returns ``None``, not ``False``, when the check itself could not run —
    ``secedit /export`` needs elevation, but ``connect`` (unlike ``setup``) is
    designed to run as an ordinary user, and that user cannot be expected to
    audit a policy it has no rights to even read. ``None`` means "can't tell",
    which :func:`ready` treats as "assume setup already got this right" rather
    than as a missing grant — the distinction that matters, since the two
    would otherwise look identical from an unprivileged caller and only one
    of them is actually a problem.
    """
    script = f"""
$account = '{_ps_single_quote(ACCOUNT)}'
$cfgPath = Join-Path $env:TEMP ("strobes-secpol-check-{{0}}.cfg" -f ([guid]::NewGuid()))
try {{
    secedit /export /cfg $cfgPath /areas USER_RIGHTS | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cfgPath)) {{
        'UNKNOWN'
    }} else {{
        $lines = Get-Content $cfgPath
        $missing = @()
        foreach ($right in @({", ".join(f"'{r}'" for r in LOGON_RIGHTS)})) {{
            $line = $lines | Where-Object {{ $_ -match "^\\s*$right\\s*=" }}
            $hasSid = $line -match [regex]::Escape('{sid}')
            $hasName = $line -match "(?i)(^|,)\\s*$([regex]::Escape($account))\\s*(,|$)"
            if (-not $line -or (-not $hasSid -and -not $hasName)) {{ $missing += $right }}
        }}
        if ($missing.Count -eq 0) {{ 'yes' }} else {{ 'no' }}
    }}
}} finally {{
    Remove-Item $cfgPath -ErrorAction SilentlyContinue
}}
"""
    try:
        outcome = _powershell(script, check=False).strip()
    except WindowsSetupError:
        return None
    if outcome == "UNKNOWN":
        return None
    return outcome == "yes"


def ready() -> bool:
    """True when the account and the block rule are in place, and — where this
    caller has enough privilege to tell — its logon rights too."""
    if not IS_WINDOWS:
        return False
    state = load_state()
    if not state:
        return False
    try:
        if not _account_exists():
            return False
        if _has_logon_rights(state["sid"]) is False:
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

#: Task Scheduler's own status codes, distinct from a launched process's exit
#: code. ``0x00041301`` is "currently running" (what the poll loop waits out);
#: the others mean the action never started at all — most commonly a logon
#: failure, which after :func:`setup` has run should not happen, but is
#: reported precisely rather than mistaken for the sandboxed command's own
#: (nonexistent) exit code.
_TASK_RUNNING = 0x00041301
_TASK_NOT_SCHEDULED_TO_RUN = 0x00041303  # SCHED_S_TASK_HAS_NOT_RUN
_TASK_NOT_YET_RUN = 267011  # decimal form of the same code, seen in the wild


def _ps_single_quote(value: str) -> str:
    """Escape ``value`` for embedding in a PowerShell single-quoted string."""
    return value.replace("'", "''")


def grant_read_access(path: str, sid: str) -> None:
    """Grant ``sid`` read access to a file the bridge's own account wrote.

    The Windows equivalent of handing a file's *ownership* to the l3 lane's
    uid: the sandbox account is a different Windows identity too, so a file
    the bridge writes for a sandboxed command to read (an interpreter source
    file, an input fixture) is otherwise unreadable to it. Read-only and
    scoped to this one file, not the containing directory, so it grants
    nothing beyond what the caller asked to share.
    """
    if not IS_WINDOWS:
        return
    _powershell(f'icacls "{path}" /grant "*{sid}:(R)" | Out-Null', check=False)


def run_as_sandbox(command: str, env: dict, cwd: Optional[str],
                   timeout: int) -> tuple:
    """Run ``command`` as the sandbox account. Returns ``(rc, stdout, stderr)``.

    Launched via an ephemeral Scheduled Task rather than ``CreateProcessWithLogonW``.
    The latter goes through the Secondary Logon service, which — independent of
    this account's rights — does not reliably launch a process when the caller
    has no interactive desktop (a Windows service, or this bridge itself run
    non-interactively): the child is created but crashes immediately with
    ``STATUS_DLL_INIT_FAILED``. Task Scheduler's "run whether user is logged on
    or not" logon uses a different, batch-oriented path that does not have this
    dependency, and it is what this project's own installer already uses to run
    the bridge — so it is a proven-reliable mechanism in this exact deployment
    shape, not a new one.

    A Scheduled Task action has no equivalent of ``lpEnvironment``, so the
    environment (most importantly ``ALL_PROXY`` — this is what makes the
    sandboxed command use the egress proxy at all) is set inside the launched
    script instead of passed to the launcher. Output is captured with
    PowerShell's own redirection operators rather than inherited handles,
    sidestepping the handle-inheritance fragility documented for
    ``CreateProcessWithLogonW`` entirely instead of working around it.
    """
    if not IS_WINDOWS:
        raise WindowsSetupError("Windows-only")
    state = load_state()
    if not state:
        raise WindowsSetupError("windows sandbox is not set up; run `sandbox-setup`")

    import shutil
    import tempfile
    import uuid

    password = _unprotect(state["password"])
    sid = state["sid"]
    task_name = f"strobes-sandbox-run-{uuid.uuid4().hex}"

    work_dir = tempfile.mkdtemp(prefix="strobes-sbx-")
    script_path = os.path.join(work_dir, "run.ps1")
    out_path = os.path.join(work_dir, "stdout.txt")
    err_path = os.path.join(work_dir, "stderr.txt")

    try:
        # The task runs as a different, lower-privileged account than whatever
        # created work_dir (this process); it needs its own write access to
        # read the script and create the output files.
        #
        # The caller's own account is granted here too, and not just relied
        # on implicitly: the output files are created by the sandbox
        # account's own redirect (PowerShell's own "1>"/"2>", not this
        # process), so it — not the caller — ends up as their owner, and
        # "OWNER RIGHTS" inherited onto them resolves to that owner, not to
        # whoever is about to try to read them back. An admin caller is
        # unaffected (BUILTIN\Administrators already covers it), but a
        # non-admin one has nothing else granting it access at all.
        _powershell(
            f'icacls "{work_dir}" /grant "*{sid}:(OI)(CI)F" | Out-Null',
            check=False,
        )
        caller = os.environ.get("USERNAME", "")
        if caller:
            _powershell(
                f'icacls "{work_dir}" /grant "{caller}:(OI)(CI)F" | Out-Null',
                check=False,
            )

        # Windows keeps a few hidden, non-identifier environment entries (the
        # per-drive current directory, e.g. "=C:") that ``$env:NAME`` syntax
        # cannot target and the sandboxed command has no use for anyway.
        env_lines = "\n".join(
            f"$env:{name} = '{_ps_single_quote(str(value))}'"
            for name, value in sorted(env.items())
            if name.isidentifier()
        )
        cd_line = (f"Set-Location -LiteralPath '{_ps_single_quote(cwd)}'"
                   if cwd and os.path.isdir(cwd) else "")
        inner_script = f"""
{env_lines}
{cd_line}
& cmd.exe /c '{_ps_single_quote(command)}' 1> '{out_path}' 2> '{err_path}'
exit $LASTEXITCODE
"""
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(inner_script)

        register_and_wait = f"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_path}"'
Register-ScheduledTask -TaskName '{task_name}' -Action $action `
    -User '{ACCOUNT}' -Password '{_ps_single_quote(password)}' -RunLevel Limited -Force | Out-Null
Start-ScheduledTask -TaskName '{task_name}'

$deadline = (Get-Date).AddSeconds({int(timeout)})
do {{
    Start-Sleep -Milliseconds 200
    $r = (Get-ScheduledTaskInfo -TaskName '{task_name}').LastTaskResult
}} while ($r -eq {_TASK_RUNNING} -and (Get-Date) -lt $deadline)

if ($r -eq {_TASK_RUNNING}) {{
    Stop-ScheduledTask -TaskName '{task_name}' -ErrorAction SilentlyContinue
    'TIMEOUT'
}} else {{
    "RESULT:$r"
}}
"""
        outcome = _powershell(register_and_wait).strip()

        if outcome == "TIMEOUT":
            raise asyncio.TimeoutError()

        if not outcome.startswith("RESULT:"):
            raise WindowsSetupError(f"unexpected scheduled-task outcome: {outcome!r}")

        result_code = int(outcome.split(":", 1)[1])
        if result_code in (_TASK_NOT_SCHEDULED_TO_RUN, _TASK_NOT_YET_RUN):
            raise WindowsSetupError(
                "scheduled task never ran (commonly a logon failure — rerun "
                "`sandbox-setup` to reapply the sandbox account's logon rights)"
            )

        def _read(path):
            # Windows PowerShell's ">" file redirection writes UTF-16LE with a
            # BOM regardless of console/system codepage; the "utf-16" codec
            # both detects that BOM and falls back to native order if a file
            # happens to be empty (no BOM at all), so it is always the right
            # choice for a file this script's own redirection produced.
            #
            # A brief retry, not a single attempt: Task Scheduler reports the
            # task done as soon as its action process (powershell.exe) exits,
            # but that is a different kernel object than the NTFS directory
            # entry for a file it just created, and nothing guarantees the
            # second is visible to another process the instant the first is —
            # confirmed in practice by a real-time antivirus scan holding a
            # brief lock on a just-written file. Without this a genuinely
            # successful command intermittently reports empty output.
            last_error = None
            for attempt in range(10):
                try:
                    with open(path, "r", encoding="utf-16", errors="replace") as fh:
                        return fh.read()
                except OSError as e:
                    last_error = e
                    time.sleep(0.1 * (attempt + 1))
            logger.warning("could not read %s after retrying: %s", path, last_error)
            return ""

        return result_code, _read(out_path), _read(err_path)
    finally:
        _powershell(
            f"Unregister-ScheduledTask -TaskName '{task_name}' -Confirm:$false "
            "-ErrorAction SilentlyContinue",
            check=False,
        )
        shutil.rmtree(work_dir, ignore_errors=True)
