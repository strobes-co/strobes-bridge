"""System service / daemon installation for the Strobes Shell Bridge agent.

Supports:
  - systemd (Linux, user or system scope)
  - launchd (macOS, user scope by default)
  - simple double-fork daemon mode (any UNIX)

Windows service registration is out of scope here — on Windows, use NSSM
or Task Scheduler with the same `connect` command.
"""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path


LABEL = "co.strobes.shell-agent"


def _resolve_executable() -> str:
    """Return the best command path to put in the unit file.

    Preference order:
      1. PyInstaller-bundled binary (sys.frozen)
      2. `strobes-shell-agent` on PATH
      3. `<sys.executable> -m strobes_shell_agent`
    """
    if getattr(sys, "frozen", False):
        return sys.executable
    on_path = shutil.which("strobes-shell-agent")
    if on_path:
        return on_path
    return f"{sys.executable} -m strobes_shell_agent"


def _build_command(args: dict) -> str:
    """Build the `... connect <flags>` command from a dict of options."""
    exe = _resolve_executable()
    parts = [exe, "connect"]
    for key, val in args.items():
        if val is None or val == "":
            continue
        if isinstance(val, bool):
            if val:
                parts.append(f"--{key}")
            continue
        parts.append(f"--{key}")
        parts.append(str(val))
    return " ".join(_quote(p) for p in parts)


def _quote(s: str) -> str:
    if not s or any(c.isspace() for c in s) or '"' in s:
        return '"' + s.replace('"', r'\"') + '"'
    return s


# ---------------------- systemd ----------------------

SYSTEMD_UNIT = """\
[Unit]
Description=Strobes Shell Bridge Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={command}
Restart=always
RestartSec=5
# Reasonable resource caps
LimitNOFILE=65536
{env_lines}

[Install]
WantedBy={target}
"""


def install_systemd(args: dict, scope: str = "user") -> str:
    """Install a systemd unit. scope: 'user' (default) or 'system'.

    Returns the unit file path that was written.
    """
    if shutil.which("systemctl") is None:
        raise RuntimeError("systemctl not found — this host doesn't use systemd.")

    env_lines = "\n".join(
        f"Environment={k}={v}" for k, v in args.pop("_env", {}).items()
    )

    if scope == "system":
        unit_dir = Path("/etc/systemd/system")
        target = "multi-user.target"
        scope_arg = []
    else:
        unit_dir = Path.home() / ".config/systemd/user"
        target = "default.target"
        scope_arg = ["--user"]

    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / f"{LABEL}.service"
    unit_path.write_text(SYSTEMD_UNIT.format(
        command=_build_command(args),
        target=target,
        env_lines=env_lines,
    ))

    subprocess.run(["systemctl", *scope_arg, "daemon-reload"], check=False)
    subprocess.run(["systemctl", *scope_arg, "enable", f"{LABEL}.service"], check=False)
    subprocess.run(["systemctl", *scope_arg, "restart", f"{LABEL}.service"], check=False)
    return str(unit_path)


def uninstall_systemd(scope: str = "user") -> str:
    """Stop, disable, and remove the systemd unit."""
    scope_arg = ["--user"] if scope == "user" else []
    subprocess.run(["systemctl", *scope_arg, "stop", f"{LABEL}.service"], check=False)
    subprocess.run(["systemctl", *scope_arg, "disable", f"{LABEL}.service"], check=False)

    if scope == "system":
        unit_path = Path("/etc/systemd/system") / f"{LABEL}.service"
    else:
        unit_path = Path.home() / ".config/systemd/user" / f"{LABEL}.service"
    if unit_path.exists():
        unit_path.unlink()
    subprocess.run(["systemctl", *scope_arg, "daemon-reload"], check=False)
    return str(unit_path)


# ---------------------- launchd (macOS) ----------------------

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{program_args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
{env_block}
</dict>
</plist>
"""


def install_launchd(args: dict) -> str:
    """Install a per-user launchd LaunchAgent (~/Library/LaunchAgents)."""
    if sys.platform != "darwin":
        raise RuntimeError("launchd is macOS-only.")
    if shutil.which("launchctl") is None:
        raise RuntimeError("launchctl not found.")

    env_dict = args.pop("_env", {})

    # Build ProgramArguments individually.
    exe = _resolve_executable()
    # If exe is "python -m strobes_shell_agent" we need to split.
    exe_parts = exe.split() if " " in exe else [exe]
    pa = [*exe_parts, "connect"]
    for key, val in args.items():
        if val is None or val == "" or isinstance(val, bool):
            if isinstance(val, bool) and val:
                pa.append(f"--{key}")
            continue
        pa.append(f"--{key}")
        pa.append(str(val))

    program_args = "\n".join(f"    <string>{x}</string>" for x in pa)

    log_dir = Path.home() / "Library/Logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout = log_dir / "strobes-shell-agent.out.log"
    stderr = log_dir / "strobes-shell-agent.err.log"

    env_block = ""
    if env_dict:
        env_block = "  <key>EnvironmentVariables</key>\n  <dict>\n"
        for k, v in env_dict.items():
            env_block += f"    <key>{k}</key>\n    <string>{v}</string>\n"
        env_block += "  </dict>"

    plist_dir = Path.home() / "Library/LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / f"{LABEL}.plist"
    plist_path.write_text(LAUNCHD_PLIST.format(
        label=LABEL,
        program_args=program_args,
        stdout=str(stdout),
        stderr=str(stderr),
        env_block=env_block,
    ))

    # Unload first in case a stale one is registered, then load.
    subprocess.run(["launchctl", "unload", str(plist_path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["launchctl", "load", "-w", str(plist_path)], check=False)
    return str(plist_path)


def uninstall_launchd() -> str:
    plist_path = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
    if shutil.which("launchctl") is not None:
        subprocess.run(["launchctl", "unload", str(plist_path)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if plist_path.exists():
        plist_path.unlink()
    return str(plist_path)


# ---------------------- double-fork daemon ----------------------

def daemonize(pid_file: Path, log_file: Path) -> None:
    """Detach from the terminal so the process keeps running after logout.

    Uses the classic double-fork. Redirects stdio to log_file.
    """
    if sys.platform == "win32":
        raise RuntimeError("--daemon is not supported on Windows; use a service.")

    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)

    # Close fd 0/1/2 and redirect to log file.
    os.chdir("/")
    sys.stdout.flush()
    sys.stderr.flush()

    log_file.parent.mkdir(parents=True, exist_ok=True)
    devnull = os.open(os.devnull, os.O_RDONLY)
    out = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(devnull, 0)
    os.dup2(out, 1)
    os.dup2(out, 2)
    os.close(devnull)
    if out > 2:
        os.close(out)

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()))
