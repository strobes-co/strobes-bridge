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
from strobes_shell_agent import sandbox
from strobes_shell_agent import service as svc
from strobes_shell_agent import __version__


# Windows consoles often default to a legacy code page (e.g. cp1252) that
# cannot encode characters used in help text/logs, which makes `--help`
# crash with UnicodeEncodeError. Force UTF-8 at import time, before click
# renders anything. Guarded because stdout/stderr may be None or
# non-reconfigurable (frozen/windowed builds).
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


def _split_net_list(values) -> list:
    """Flatten repeated and comma-separated egress entries into one list."""
    out = []
    for value in values or ():
        out.extend(c for c in str(value).replace(",", " ").split() if c.strip())
    return out


def _describe_egress(policy: dict) -> str:
    """One line describing the egress posture, for the startup banner."""
    sb = policy["sandbox"]
    if not sb["available"]:
        return f"NOT ENFORCED — no sandbox backend on {sb['platform']}"
    if not policy["enforced"]:
        tail = "" if policy["block_metadata"] else ", metadata blocking OFF"
        return f"open — all destinations allowed ({sb['backend']}{tail})"
    bits = [f"default {policy['default_egress']}"]
    if policy["allow"]:
        bits.append(f"{len(policy['allow'])} allowed")
    if policy["deny"]:
        bits.append(f"{len(policy['deny'])} denied")
    if not policy["block_metadata"]:
        bits.append("metadata blocking OFF")
    return ", ".join(bits) + f" ({sb['backend']})"


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version=__version__)
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
@click.option("--net-allow", multiple=True, envvar="STROBES_NET_ALLOW",
              help="Egress allowlist entry — hostname, IP or CIDR. Repeatable or "
                   "comma-separated. Adding any entry switches the bridge to "
                   "default-deny. (env: STROBES_NET_ALLOW)")
@click.option("--net-deny", multiple=True, envvar="STROBES_NET_DENY",
              help="Egress denylist entry. Deny always wins over allow. "
                   "(env: STROBES_NET_DENY)")
@click.option("--net-default", type=click.Choice(["allow", "deny"]), default=None,
              envvar="STROBES_NET_DEFAULT",
              help="What happens to traffic no rule matched. Defaults to allow "
                   "when no --net-allow is given, deny when one is.")
@click.option("--net-block-metadata/--no-net-block-metadata", default=None,
              help="Keep cloud-metadata and link-local shut regardless of the "
                   "rules above. On by default.")
def connect(url, api_key, org_id, bridge_id, name, cwd, ssl_verify, verbose,
            daemon, pid_file, log_file, net_allow, net_deny, net_default,
            net_block_metadata):
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

    # Egress scope, set once by the operator. The platform can replace it at
    # runtime via ``sandbox_configure``; both write the same policy.
    allow = _split_net_list(net_allow)
    deny = _split_net_list(net_deny)
    # Naming targets without saying what to do with everything else almost
    # always means "only these" — staying open would ignore the scope just typed.
    sandbox.set_initial_policy(
        allow=allow or None,
        deny=deny or None,
        default_egress=net_default or ("deny" if allow else None),
        block_metadata=net_block_metadata,
    )
    policy = sandbox.describe_policy()

    client = ShellBridgeClient(
        url=url,
        api_key=api_key,
        org_id=org_id,
        bridge_id=bridge_id,
        name=name or "",
        cwd=cwd,
        ssl_verify=ssl_verify,
    )

    click.echo(f"Strobes Shell Bridge Agent v{__version__}")
    click.echo(f"  Bridge ID:  {bridge_id}")
    click.echo(f"  Name:       {client.name}")
    click.echo(f"  Org:        {org_id}")
    click.echo(f"  Server:     {url}")
    click.echo(f"  CWD:        {client.cwd}")
    click.echo(f"  Egress:     {_describe_egress(policy)}")
    click.echo()
    if not policy["sandbox"]["available"]:
        click.echo("WARNING: no process sandbox on this platform — commands "
                   "will be refused rather than run unconfined.", err=True)
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


@main.command()
def selftest():
    """Verify the bundled sandbox pack works offline (nmap, nuclei+templates, python).

    Provisions the pack (from the embedded/baked bundle — no network) and runs a few
    real commands through the same executor the agent uses. Exit 0 if all pass.
    """
    from strobes_shell_agent import pack, executor

    pack.ensure_pack()
    st = pack.status()
    click.echo(f"pack: {st}")
    if not st.get("present"):
        click.echo("FAIL: no sandbox pack found", err=True)
        sys.exit(1)

    async def _run():
        ok = True
        # nmap connect scan
        r = await executor.execute_shell_command("nmap -sT -Pn -p 80 127.0.0.1")
        good = "Nmap done" in (r["stdout"] + r["stderr"])
        click.echo(f"  [{'ok' if good else 'FAIL'}] nmap connect scan")
        ok &= good
        # nuclei templates load offline
        r = await executor.execute_shell_command("nuclei -tl -duc")
        n = len([l for l in r["stdout"].splitlines() if l.strip().endswith(".yaml")])
        click.echo(f"  [{'ok' if n else 'FAIL'}] nuclei templates: {n}")
        ok &= n > 0
        # python with agent packages
        r = await executor.execute_code(
            "python", "import boto3, reportlab; print(boto3.__version__)")
        click.echo(f"  [{'ok' if r['success'] else 'FAIL'}] python/boto3: {r['stdout'].strip()}")
        ok &= r["success"]
        return ok

    if asyncio.run(_run()):
        click.echo("selftest: ALL OK")
    else:
        click.echo("selftest: FAILURES", err=True)
        sys.exit(1)


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
    Linux  -> systemd unit at ~/.config/systemd/user/co.strobes.shell-agent.service
             (or /etc/systemd/system/ when run as root)
    macOS  -> launchd LaunchAgent at ~/Library/LaunchAgents/co.strobes.shell-agent.plist
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
            # auto → a root LaunchDaemon when installed with sudo (privileged SYN
            # scanning), else a per-user LaunchAgent.
            mac_scope = scope
            if mac_scope == "auto":
                mac_scope = "system" if os.geteuid() == 0 else "user"
            path = svc.install_launchd(flags, scope=mac_scope)
            kind = "LaunchDaemon (root)" if mac_scope == "system" else "LaunchAgent"
            sudo = "sudo " if mac_scope == "system" else ""
            click.echo(f"Installed launchd {kind}: {path}")
            click.echo(f"Manage with: {sudo}launchctl unload/load -w {path}")
            if mac_scope != "system":
                click.echo("Tip: install with `sudo … --scope system` for a root "
                           "LaunchDaemon so naabu can SYN-scan (faster recon).")
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
        mac_scope = scope
        if mac_scope == "auto":
            mac_scope = "system" if os.geteuid() == 0 else "user"
        path = svc.uninstall_launchd(scope=mac_scope)
        click.echo(f"Removed launchd {'LaunchDaemon' if mac_scope == 'system' else 'LaunchAgent'}: {path}")
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


# ---------------------------------------------------------------------------
# Sandbox provisioning and verification
# ---------------------------------------------------------------------------

@main.command("sandbox-check")
def sandbox_check():
    """Verify that egress is actually confined on this host.

    Runs a real command that tries to reach a deliberately out-of-scope address
    and reports whether it was refused. This is the check that matters on a
    platform the bridge has not been proven on — it exercises the live backend
    rather than trusting that the code is right.
    """
    import asyncio
    import json as _json
    from strobes_shell_agent import l3lane, procsandbox, sandbox

    info = procsandbox.describe()
    l3 = l3lane.available()
    click.echo(f"platform: {info['platform']}")
    click.echo(f"mode:     {'l3 (packet filter)' if l3 else 'proxy'}")
    click.echo(f"backend:  {info['backend'] or ('nftables' if l3 else 'NONE')}")
    if info.get("windows"):
        click.echo("windows:  " + _json.dumps(info["windows"]))
    if info.get("hint"):
        click.echo(f"hint:     {info['hint']}")

    # Packet-level enforcement needs no process sandbox, so either is enough.
    if not (info["available"] or l3):
        click.echo("\nEgress is NOT enforced on this host — commands will be refused.",
                   err=True)
        sys.exit(1)

    report = asyncio.run(sandbox.selftest())
    click.echo(f"\nselftest: {'PASS' if report['ok'] else 'FAIL'} "
               f"[{report.get('mode')}] — {report['detail']}")
    sys.exit(0 if report["ok"] else 1)


@main.command("sandbox-setup")
def sandbox_setup():
    """Provision the Windows sandbox account and its egress filter (elevated).

    Only Windows needs this: macOS and Linux confine a process directly, but
    Windows has no equivalent primitive, so the boundary is drawn around a
    dedicated local account whose outbound traffic a firewall rule blocks.
    Creating that account and installing the rule both require Administrator.
    """
    from strobes_shell_agent import winsandbox
    from strobes_shell_agent.egress_proxy import DEFAULT_PORT_RANGE

    if not winsandbox.IS_WINDOWS:
        click.echo("Only Windows needs setup; this host confines processes directly.")
        sys.exit(0)
    try:
        result = winsandbox.setup(DEFAULT_PORT_RANGE)
    except winsandbox.WindowsSetupError as e:
        click.echo(f"Setup failed: {e}", err=True)
        sys.exit(1)
    click.echo(f"Created account {result['account']} ({result['sid']})")
    click.echo(f"Installed firewall rule: {', '.join(result['rules'])}")
    click.echo(f"Proxy port range: {result['port_range'][0]}-{result['port_range'][1]}")
    click.echo("\nNow run `strobes-shell-agent sandbox-check` to confirm it works.")


@main.command("sandbox-teardown")
def sandbox_teardown():
    """Remove the Windows sandbox account and its egress filter (elevated)."""
    from strobes_shell_agent import winsandbox

    if not winsandbox.IS_WINDOWS:
        click.echo("Nothing to remove on this platform.")
        sys.exit(0)
    try:
        winsandbox.teardown()
    except winsandbox.WindowsSetupError as e:
        click.echo(f"Teardown failed: {e}", err=True)
        sys.exit(1)
    click.echo("Removed the sandbox account and its firewall rule.")
