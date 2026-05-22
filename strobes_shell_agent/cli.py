"""CLI entry point for the Strobes Shell Bridge Agent."""

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import click

from strobes_shell_agent.config import CONFIG_DIR, get_or_create_bridge_id, get_env
from strobes_shell_agent.client import ShellBridgeClient
from strobes_shell_agent import service as svc


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Strobes Shell Bridge Agent — connect your machine to Strobes."""
    pass


@main.command()
@click.option("--url", default=None, envvar="STROBES_URL",
              help="Strobes platform URL (env: STROBES_URL)")
@click.option("--api-key", default=None, envvar="STROBES_API_KEY",
              help="Strobes API key (env: STROBES_API_KEY)")
@click.option("--org-id", default=None, envvar="STROBES_ORG_ID",
              help="Organization ID (env: STROBES_ORG_ID)")
@click.option("--bridge-id", default=None, envvar="STROBES_BRIDGE_ID",
              help="Bridge ID — auto-generated if not provided (env: STROBES_BRIDGE_ID)")
@click.option("--name", default=None, envvar="STROBES_SHELL_NAME",
              help="Display name for this shell (env: STROBES_SHELL_NAME)")
@click.option("--cwd", default=None, envvar="STROBES_CWD",
              help="Working directory for commands (env: STROBES_CWD)")
@click.option("--ssl-verify/--no-ssl-verify", default=True, envvar="STROBES_SSL_VERIFY",
              help="Verify SSL certificates (env: STROBES_SSL_VERIFY)")
@click.option("-v", "--verbose", is_flag=True, envvar="STROBES_VERBOSE",
              help="Enable debug logging (env: STROBES_VERBOSE)")
@click.option("--daemon", is_flag=True, envvar="STROBES_DAEMON",
              help="Detach and run in the background (UNIX only). "
                   "Writes PID to ~/.strobes-shell-agent/agent.pid and "
                   "logs to ~/.strobes-shell-agent/agent.log.")
@click.option("--pid-file", default=None, envvar="STROBES_PID_FILE",
              help="PID file path when --daemon is set.")
@click.option("--log-file", default=None, envvar="STROBES_LOG_FILE",
              help="Log file path when --daemon is set.")
def connect(url, api_key, org_id, bridge_id, name, cwd, ssl_verify, verbose,
            daemon, pid_file, log_file):
    """Connect to Strobes and start accepting commands.

    All options can be set via environment variables or a .env file.
    Place a .env file in the current directory or ~/.strobes-shell-agent/.env

    \b
    Example .env:
        STROBES_URL=https://app.strobes.co
        STROBES_API_KEY=sk-xxxxxxxxxxxx
        STROBES_ORG_ID=your-org-uuid
        STROBES_SHELL_NAME=my-server
    """
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    if not url:
        click.echo("Error: --url or STROBES_URL is required", err=True)
        sys.exit(1)
    if not api_key:
        click.echo("Error: --api-key or STROBES_API_KEY is required", err=True)
        sys.exit(1)
    if not org_id:
        click.echo("Error: --org-id or STROBES_ORG_ID is required", err=True)
        sys.exit(1)

    # Use persistent bridge_id if not provided
    if not bridge_id:
        bridge_id = get_or_create_bridge_id()

    if daemon:
        pid_path = Path(pid_file) if pid_file else CONFIG_DIR / "agent.pid"
        log_path = Path(log_file) if log_file else CONFIG_DIR / "agent.log"
        # If an existing pid file points at a live process, refuse.
        if pid_path.exists():
            try:
                old_pid = int(pid_path.read_text().strip())
                os.kill(old_pid, 0)
                click.echo(f"Already running (pid {old_pid}). Stop it first.", err=True)
                sys.exit(2)
            except (ProcessLookupError, ValueError, OSError):
                pass  # Stale pid file — overwrite.
        click.echo(f"Daemonising. pid -> {pid_path}, log -> {log_path}")
        svc.daemonize(pid_path, log_path)
        setup_logging(verbose)  # Re-init logging now that stdio is redirected.

    client = ShellBridgeClient(
        url=url,
        api_key=api_key,
        org_id=org_id,
        bridge_id=bridge_id,
        name=name or "",
        cwd=cwd,
        ssl_verify=ssl_verify,
    )

    click.echo("Strobes Shell Bridge Agent v0.1.0")
    click.echo(f"  Bridge ID:  {bridge_id}")
    click.echo(f"  Name:       {client.name}")
    click.echo(f"  Org:        {org_id}")
    click.echo(f"  Server:     {url}")
    click.echo(f"  CWD:        {client.cwd}")
    click.echo()

    # Handle graceful shutdown
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown_handler():
        logger.info("Shutting down...")
        client.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_handler)
        except (NotImplementedError, AttributeError):
            # Windows path: signal handlers run synchronously in the OS thread,
            # so call client.stop() via the loop to make sure the cancellable
            # asyncio.wait_for in connect_forever wakes up.
            signal.signal(sig, lambda s, f: loop.call_soon_threadsafe(shutdown_handler))

    try:
        loop.run_until_complete(client.connect_forever())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        click.echo("Disconnected.")


@main.command()
def show_id():
    """Show the persistent bridge ID for this machine."""
    bridge_id = get_or_create_bridge_id()
    click.echo(bridge_id)


def _detect_default_scope() -> str:
    """systemd: user scope unless we're running as root."""
    return "system" if os.geteuid() == 0 else "user"


@main.command("install-service")
@click.option("--url", required=True, envvar="STROBES_URL")
@click.option("--api-key", required=True, envvar="STROBES_API_KEY")
@click.option("--org-id", required=True, envvar="STROBES_ORG_ID")
@click.option("--bridge-id", default=None, envvar="STROBES_BRIDGE_ID")
@click.option("--name", default=None, envvar="STROBES_SHELL_NAME")
@click.option("--cwd", default=None, envvar="STROBES_CWD")
@click.option("--ssl-verify/--no-ssl-verify", default=True)
@click.option("--scope", type=click.Choice(["user", "system", "auto"]), default="auto",
              help="systemd scope: 'user' (default for non-root), 'system' (default for root), "
                   "or 'auto'. Ignored on macOS.")
def install_service(url, api_key, org_id, bridge_id, name, cwd, ssl_verify, scope):
    """Register the agent as a system service that starts on boot.

    \b
    Linux  → systemd unit at ~/.config/systemd/user/co.strobes.shell-agent.service
             (or /etc/systemd/system/ when run as root)
    macOS  → launchd LaunchAgent at ~/Library/LaunchAgents/co.strobes.shell-agent.plist
    """
    if not bridge_id:
        bridge_id = get_or_create_bridge_id()

    flags = {
        "url": url,
        "api-key": api_key,
        "org-id": org_id,
        "bridge-id": bridge_id,
    }
    if name:
        flags["name"] = name
    if cwd:
        flags["cwd"] = cwd
    if not ssl_verify:
        flags["no-ssl-verify"] = True

    try:
        if sys.platform == "darwin":
            path = svc.install_launchd(flags)
            click.echo(f"Installed launchd LaunchAgent: {path}")
            click.echo("Manage with: launchctl unload/load -w " + path)
        elif sys.platform.startswith("linux"):
            if scope == "auto":
                scope = _detect_default_scope()
            path = svc.install_systemd(flags, scope=scope)
            click.echo(f"Installed systemd unit: {path}")
            unit = "co.strobes.shell-agent.service"
            prefix = "systemctl --user" if scope == "user" else "sudo systemctl"
            click.echo(f"Manage with: {prefix} status|restart|stop {unit}")
        else:
            click.echo(f"install-service is not supported on platform '{sys.platform}'", err=True)
            click.echo("On Windows, use NSSM or Task Scheduler with the `connect` command.", err=True)
            sys.exit(1)
    except RuntimeError as e:
        click.echo(f"install-service failed: {e}", err=True)
        sys.exit(1)


@main.command("uninstall-service")
@click.option("--scope", type=click.Choice(["user", "system", "auto"]), default="auto")
def uninstall_service(scope):
    """Remove the previously-installed system service."""
    if sys.platform == "darwin":
        path = svc.uninstall_launchd()
        click.echo(f"Removed launchd LaunchAgent: {path}")
    elif sys.platform.startswith("linux"):
        if scope == "auto":
            scope = _detect_default_scope()
        path = svc.uninstall_systemd(scope=scope)
        click.echo(f"Removed systemd unit: {path}")
    else:
        click.echo(f"uninstall-service is not supported on platform '{sys.platform}'", err=True)
        sys.exit(1)


@main.command()
def status():
    """Show whether a daemonised agent (from --daemon) is running."""
    pid_path = CONFIG_DIR / "agent.pid"
    if not pid_path.exists():
        click.echo("Not running (no pid file).")
        return
    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, 0)
        click.echo(f"Running (pid {pid}).")
    except (ProcessLookupError, ValueError, OSError):
        click.echo("Not running (stale pid file).")
        sys.exit(1)


@main.command()
def stop():
    """Stop a daemonised agent started with `connect --daemon`."""
    pid_path = CONFIG_DIR / "agent.pid"
    if not pid_path.exists():
        click.echo("Not running (no pid file).")
        return
    try:
        pid = int(pid_path.read_text().strip())
    except ValueError:
        click.echo("Corrupted pid file.", err=True)
        sys.exit(1)
    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Sent SIGTERM to pid {pid}.")
    except ProcessLookupError:
        click.echo("Process not found — removing stale pid file.")
    finally:
        try:
            pid_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()
