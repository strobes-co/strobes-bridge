"""End-to-end tests for egress control.

These are deliberately *not* mocked. The whole claim being tested is that the
operating system refuses traffic a policy does not permit, and a fake cannot
establish that — so every test here starts a real proxy, launches a real
sandboxed process, and asserts on what that process could actually reach.

The counterpart to each denial test is a control that proves the destination was
reachable in the first place; otherwise a test passes just as well when the
network is down.

Everything runs against a loopback origin the test owns, so no external network
is required. Tests needing a sandbox backend skip where there is none.
"""

import asyncio
import os
import shutil
import sys

import pytest

from strobes_shell_agent import procsandbox, sandbox as sb
from strobes_shell_agent.client import ShellBridgeClient
from strobes_shell_agent.egress_proxy import EgressProxy
from strobes_shell_agent.netpolicy import Checker, Entry, NetworkPolicy

needs_sandbox = pytest.mark.skipif(
    not procsandbox.available(),
    reason=f"no process sandbox backend on {sys.platform}",
)

METADATA = "169.254.169.254"
BLACKHOLE = "198.51.100.42"  # TEST-NET-2

# "/dev/null" and single-quoted "-w" values are POSIX shell syntax; cmd.exe
# (which runs sandboxed commands on Windows) handles neither the same way.
NULL_DEVICE = "NUL" if sys.platform == "win32" else "/dev/null"


@pytest.fixture(autouse=True)
def clean_policy(monkeypatch):
    for var in ("STROBES_NET_ALLOW", "STROBES_NET_DENY",
                "STROBES_NET_DEFAULT", "STROBES_NET_BLOCK_METADATA"):
        monkeypatch.delenv(var, raising=False)
    sb._policy = None
    sb._lane = None
    yield
    sb._policy = None
    sb._lane = None


@pytest.fixture
async def origin():
    """A loopback HTTP origin the sandbox may be allowed to reach."""
    async def handle(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()


def client() -> ShellBridgeClient:
    return ShellBridgeClient(url="https://x", api_key="K", org_id="O",
                             bridge_id="B", name="n")


# ---------------------------------------------------------------------------
# The policy decision itself
# ---------------------------------------------------------------------------

def test_checker_allows_by_name_and_by_address():
    policy = NetworkPolicy.from_lists(allow=["example.com", "10.0.0.0/8"])
    c = Checker(policy)
    assert c.check("10.0.0.5", 80)
    assert not c.check("11.0.0.5", 80)


def test_checker_deny_beats_allow():
    c = Checker(NetworkPolicy.from_lists(allow=["10.0.0.0/8"], deny=["10.1.0.0/16"]))
    assert c.check("10.0.0.5", 80)
    assert not c.check("10.1.0.5", 80)


def test_checker_blocks_metadata_even_when_open():
    c = Checker(NetworkPolicy.from_lists(default_egress="allow"))
    decision = c.check(METADATA, 80)
    assert not decision
    assert "hard-denied" in decision.reason


def test_checker_reports_a_wrong_port_precisely():
    # "not in scope" would send the caller hunting for the wrong problem.
    policy = NetworkPolicy(allow=(Entry.parse("10.0.0.5", ports=[443]),),
                           default_egress="deny")
    decision = Checker(policy).check("10.0.0.5", 22)
    assert not decision
    assert "port 22" in decision.reason


def test_checker_carries_the_addresses_it_validated():
    # The proxy must connect to these rather than resolving again, which is what
    # closes the rebinding window.
    decision = Checker(NetworkPolicy.from_lists(allow=["10.0.0.0/8"])).check("10.0.0.5", 80)
    assert decision.addresses == ("10.0.0.5",)


def test_checker_default_allow_permits_the_unlisted():
    assert Checker(NetworkPolicy.from_lists(default_egress="allow")).check("1.2.3.4", 80)


def test_checker_default_deny_refuses_the_unlisted():
    assert not Checker(NetworkPolicy.from_lists(default_egress="deny")).check("1.2.3.4", 80)


# ---------------------------------------------------------------------------
# The proxy
# ---------------------------------------------------------------------------

async def curl(*args, timeout=10):
    proc = await asyncio.create_subprocess_exec(
        "curl", "-s", "-m", "6", "-o", NULL_DEVICE, "-w", "%{http_code}", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    return proc.returncode, out.decode().strip()


@pytest.mark.asyncio
async def test_proxy_allows_an_in_scope_destination(origin):
    policy = NetworkPolicy(allow=(Entry.parse("127.0.0.1", ports=[origin]),),
                           default_egress="deny")
    proxy = EgressProxy(policy)
    port = await proxy.start()
    try:
        rc, code = await curl("--socks5-hostname", f"127.0.0.1:{port}",
                              f"http://127.0.0.1:{origin}/")
        assert (rc, code) == (0, "200")
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_proxy_refuses_an_out_of_scope_destination_over_socks(origin):
    proxy = EgressProxy(NetworkPolicy.from_lists(default_egress="deny"))
    port = await proxy.start()
    try:
        rc, _ = await curl("--socks5-hostname", f"127.0.0.1:{port}",
                           f"http://127.0.0.1:{origin}/")
        assert rc != 0, "SOCKS5 must reject, not tunnel"
        assert proxy.denied_count == 1
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_proxy_refusal_over_http_explains_itself(origin):
    proxy = EgressProxy(NetworkPolicy.from_lists(default_egress="deny"))
    port = await proxy.start()
    try:
        _, code = await curl("-x", f"http://127.0.0.1:{port}",
                             f"http://127.0.0.1:{origin}/")
        assert code == "403"
        assert proxy.denials[0].reason
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_proxy_policy_swap_takes_effect_on_the_next_connection(origin):
    """Scope pushed mid-session must not need a restart."""
    proxy = EgressProxy(NetworkPolicy.from_lists(default_egress="deny"))
    port = await proxy.start()
    try:
        rc, _ = await curl("--socks5-hostname", f"127.0.0.1:{port}",
                           f"http://127.0.0.1:{origin}/")
        assert rc != 0

        proxy.set_policy(NetworkPolicy.from_lists(allow=["127.0.0.1"],
                                                  default_egress="deny"))
        rc, code = await curl("--socks5-hostname", f"127.0.0.1:{port}",
                              f"http://127.0.0.1:{origin}/")
        assert (rc, code) == (0, "200")
    finally:
        await proxy.stop()


# ---------------------------------------------------------------------------
# The sandbox profile
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="seatbelt is macOS-only")
def test_seatbelt_profile_permits_only_the_proxy_port():
    profile = procsandbox.seatbelt_profile(12345)
    assert "(deny network*)" in profile
    assert 'network-outbound (remote ip "localhost:12345")' in profile
    # No blanket escape hatch.
    assert '"*:*"' not in profile


def test_no_backend_means_refusing_to_run_not_running_unconfined(monkeypatch):
    """The most important failure mode: never run a command unconfined.

    A bridge that silently falls back to host execution would report a scope it
    is not applying, which is worse than refusing outright.
    """
    monkeypatch.setattr(procsandbox, "detect_backend", lambda: None)
    with pytest.raises(procsandbox.SandboxUnavailable):
        procsandbox.ProcSandbox(proxy_port=1)


@pytest.mark.asyncio
async def test_lane_reports_sandbox_unavailable_rather_than_executing(monkeypatch):
    # Both enforcement modes must be unavailable, or the lane legitimately
    # falls back to the other one.
    monkeypatch.setattr(procsandbox, "detect_backend", lambda: None)
    monkeypatch.setattr(l3lane, "available", lambda: False)
    lane = sb.Lane(NetworkPolicy.from_lists(default_egress="deny"))
    result = await lane.run_shell("echo should-not-run", timeout=10)
    assert result["success"] is False
    assert result["error"] == "sandbox_unavailable"
    assert "should-not-run" not in result["stdout"]


def test_sandbox_env_points_clients_at_the_proxy_with_remote_dns():
    if not procsandbox.available():
        pytest.skip("no backend")
    s = procsandbox.ProcSandbox(proxy_port=9999, socket_path="/tmp/x.sock")
    env = s.env({})
    # socks5h, not socks5: the proxy resolves, which is what makes hostname
    # rules exact and closes the rebinding window.
    assert env["ALL_PROXY"].startswith("socks5h://")
    # No destination may be reached directly, so no exemptions.
    assert "NO_PROXY" not in env and "no_proxy" not in env


# ---------------------------------------------------------------------------
# End to end: cloud agent -> bridge -> command -> network
# ---------------------------------------------------------------------------

@needs_sandbox
@pytest.mark.asyncio
async def test_default_policy_lets_a_command_reach_the_network(origin):
    """Out of the box the bridge runs commands without restricting them."""
    result = await client()._dispatch_command("shell_execute", {
        "command": f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" http://127.0.0.1:{origin}/',
        "timeout": 25,
    })
    assert result["stdout"].strip() == "200"
    assert not result.get("egress_denied")
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_metadata_is_refused_even_under_the_open_default():
    result = await client()._dispatch_command("shell_execute", {
        "command": f'curl -s -m 5 -o {NULL_DEVICE} -w "%{{http_code}}" http://{METADATA}/',
        "timeout": 25,
    })
    denied = result.get("egress_denied") or []
    assert any(d["host"] == METADATA for d in denied), result
    assert "hard-denied" in denied[0]["reason"]
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_cloud_pushed_scope_blocks_out_of_scope_and_keeps_in_scope(origin):
    """The full chain, both directions, in one test."""
    c = client()
    status = await c._dispatch_command("sandbox_configure", {
        "allow": ["127.0.0.1"], "default_egress": "deny",
    })
    assert status["enforced"] is True

    ok = await c._dispatch_command("shell_execute", {
        "command": f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" http://127.0.0.1:{origin}/',
        "timeout": 25,
    })
    assert ok["stdout"].strip() == "200", "in-scope traffic must still flow"

    blocked = await c._dispatch_command("shell_execute", {
        "command": f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" http://{BLACKHOLE}/',
        "timeout": 25,
    })
    denied = blocked.get("egress_denied") or []
    assert any(d["host"] == BLACKHOLE for d in denied), blocked
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_a_tool_that_ignores_the_proxy_gets_no_network(origin):
    """The property that separates this from a cooperative HTTP_PROXY.

    ``nc`` knows nothing about proxies. Under a permissive policy it must still
    fail, because the sandbox — not the tool's goodwill — is what confines it.
    The control below proves the port was reachable to begin with.
    """
    await sb.configure(allow=[], deny=[], default_egress="allow")
    result = await client()._dispatch_command("shell_execute", {
        "command": f"nc -z -w3 127.0.0.1 {origin} && echo REACHED || echo BLOCKED",
        "timeout": 25,
    })
    assert result["stdout"].strip() == "BLOCKED"
    await sb.get_lane().stop()

    # Control: the same connection succeeds outside the sandbox.
    proc = await asyncio.create_subprocess_shell(
        f"nc -z -w3 127.0.0.1 {origin}",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    assert await proc.wait() == 0, "the origin must be reachable unsandboxed"


@needs_sandbox
@pytest.mark.asyncio
async def test_a_refusal_reaches_the_caller_as_a_reason(origin):
    """A bare failure makes an agent retry; a reason makes it retarget."""
    await sb.configure(allow=["127.0.0.1"], default_egress="deny")
    result = await client()._dispatch_command("shell_execute", {
        "command": f"curl -s -m 6 -o {NULL_DEVICE} http://{BLACKHOLE}/", "timeout": 25,
    })
    assert "egress denied" in result["stderr"]
    assert BLACKHOLE in result["stderr"]
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_code_execution_is_sandboxed_too(origin):
    """shell_execute_code goes through the same lane, not around it."""
    await sb.configure(allow=[], deny=[], default_egress="deny")
    result = await client()._dispatch_command("shell_execute_code", {
        "language": "python",
        "code": (
            "import socket\n"
            "s=socket.socket(); s.settimeout(3)\n"
            "try:\n"
            f"    s.connect(('127.0.0.1',{origin})); print('REACHED')\n"
            "except Exception: print('BLOCKED')\n"
        ),
        "timeout": 30,
    })
    assert "BLOCKED" in result["stdout"], result
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_selftest_confirms_enforcement_on_this_host():
    """The check that makes the bridge trustworthy on a platform we cannot test.

    It exercises the real backend, so a port to another OS either proves itself
    here or reports that it cannot.
    """
    report = await sb.selftest()
    assert report["ok"] is True, report
    assert report["backend"] == procsandbox.detect_backend()


@needs_sandbox
@pytest.mark.asyncio
async def test_status_reports_the_backend_actually_in_use():
    status = await client()._dispatch_command("sandbox_status", {})
    assert status["sandbox"]["available"] is True
    assert status["default_egress"] == "allow"


# ---------------------------------------------------------------------------
# Windows backend
#
# The backend itself cannot run here, so these cover what is verifiable off
# Windows: the rule it would install, the refusal to pretend it is configured,
# and the port discipline its filter depends on. `sandbox-check` is what proves
# the rest, on a real Windows host.
# ---------------------------------------------------------------------------

from strobes_shell_agent import winsandbox  # noqa: E402
from strobes_shell_agent.egress_proxy import DEFAULT_PORT_RANGE  # noqa: E402


def test_windows_module_is_import_safe_off_windows():
    # It is imported unconditionally by procsandbox.describe(), so it must not
    # explode on macOS or Linux.
    assert winsandbox.IS_WINDOWS is (sys.platform == "win32")
    assert winsandbox.ready() is False or sys.platform == "win32"


def test_windows_rule_blocks_outbound_for_the_account_sid():
    sid = "S-1-5-21-1111-2222-3333-1004"
    rules = winsandbox.block_rules(sid)
    assert len(rules) == 1
    rule = rules[0]
    assert "-Direction Outbound" in rule
    assert "-Action Block" in rule
    assert f"D:(A;;CC;;;{sid})" in rule, "must scope the rule to the sandbox account"
    assert "-Profile Any" in rule


def test_windows_rule_has_no_port_exception():
    """The hole this design deliberately avoids.

    Excepting the proxy port would be the obvious way to let the proxy through,
    but Windows Firewall matches -RemotePort regardless of address, so it would
    also permit evil.com:60080. Loopback is exempt from filtering anyway, so the
    rule must stay unconditional.
    """
    rule = winsandbox.block_rules("S-1-5-21-1-2-3-1004")[0]
    assert "-RemotePort" not in rule
    assert "-RemoteAddress" not in rule


def test_windows_status_is_honest_when_unconfigured():
    status = winsandbox.status()
    assert status["ready"] is False
    assert status["account"] == "strobes-sandbox"


def test_windows_without_setup_reports_no_backend(monkeypatch):
    """An un-provisioned Windows host must not claim to confine anything."""
    monkeypatch.setattr(procsandbox.sys, "platform", "win32")
    monkeypatch.setattr(winsandbox, "ready", lambda: False)
    assert procsandbox.detect_backend() is None

    monkeypatch.setattr(winsandbox, "ready", lambda: True)
    assert procsandbox.detect_backend() == procsandbox.WINDOWS


def test_windows_backend_requires_a_proxy_port():
    with pytest.raises(ValueError):
        procsandbox.ProcSandbox(backend=procsandbox.WINDOWS)


def test_windows_backend_points_clients_at_loopback_proxy():
    s = procsandbox.ProcSandbox(proxy_port=60080, backend=procsandbox.WINDOWS)
    assert s.inner_proxy == "127.0.0.1:60080"
    assert s.env({})["ALL_PROXY"] == "socks5h://127.0.0.1:60080"
    # Windows launches under another account's token, so there is no argv form.
    with pytest.raises(RuntimeError):
        s.wrap_shell("echo hi")


@pytest.mark.asyncio
async def test_proxy_claims_a_port_from_the_fixed_range():
    """The Windows filter is written against a range, so the proxy must sit in it."""
    a = EgressProxy(NetworkPolicy.from_lists(), port_range=DEFAULT_PORT_RANGE)
    b = EgressProxy(NetworkPolicy.from_lists(), port_range=DEFAULT_PORT_RANGE)
    try:
        pa, pb = await a.start(), await b.start()
        lo, hi = DEFAULT_PORT_RANGE
        assert lo <= pa <= hi and lo <= pb <= hi
        assert pa != pb, "a second bridge must step to the next free port"
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_proxy_reports_an_exhausted_range_rather_than_falling_back():
    """Silently taking an ephemeral port would sit outside the egress filter."""
    held = [EgressProxy(NetworkPolicy.from_lists(), port_range=(60080, 60081))
            for _ in range(2)]
    for p in held:
        await p.start()
    try:
        with pytest.raises(RuntimeError, match="no free port"):
            await EgressProxy(NetworkPolicy.from_lists(),
                              port_range=(60080, 60081)).start()
    finally:
        for p in held:
            await p.stop()


# ---------------------------------------------------------------------------
# selftest honesty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_selftest_fails_when_the_sandbox_passes_no_traffic(monkeypatch):
    """A sandbox where nothing works must not look like one that is enforcing.

    Without a positive control these are indistinguishable: both refuse the
    out-of-scope address. This is the failure the control exists to catch.
    """
    async def nothing_works(self, command, timeout=60, cwd=None):
        return {"success": False, "stdout": "", "stderr": "", "exit_code": 7,
                "egress_denied": []}

    monkeypatch.setattr(sb.Lane, "run_shell", nothing_works)
    report = await sb.selftest()
    assert report["ok"] is False
    assert report["allowed_reachable"] is False
    assert "NOT PASSING TRAFFIC" in report["detail"]


@pytest.mark.asyncio
async def test_selftest_fails_when_out_of_scope_is_reachable(monkeypatch):
    """The other direction: traffic flows, but the policy is not applied."""
    async def everything_works(self, command, timeout=60, cwd=None):
        return {"success": True, "stdout": "200", "stderr": "", "exit_code": 0,
                "egress_denied": []}

    monkeypatch.setattr(sb.Lane, "run_shell", everything_works)
    report = await sb.selftest()
    assert report["ok"] is False
    assert "not enforced" in report["detail"].lower()


# ---------------------------------------------------------------------------
# Every execution path, not just the obvious one
#
# The bridge can launch work four ways, and only shell_execute goes through the
# lane's own spawn — background jobs and sessions own their process. Each was
# unconfined until they were wired through sandbox.confine(); these tests exist
# so the next path that gets added cannot quietly skip it.
# ---------------------------------------------------------------------------

@needs_sandbox
@pytest.mark.asyncio
async def test_background_jobs_are_confined(origin):
    """Background jobs carry the long-running scan traffic — the most important
    path to confine, and the one that was silently escaping."""
    c = client()
    await c._dispatch_command("sandbox_configure",
                              {"allow": ["127.0.0.1"], "default_egress": "deny"})

    async def run_bg(task_id, command):
        started = await c._dispatch_command(
            "shell_bg_start", {"task_id": task_id, "command": command})
        assert started.get("success"), started
        for _ in range(60):
            await asyncio.sleep(0.25)
            poll = await c._dispatch_command("shell_bg_poll", {"task_id": task_id})
            if not poll.get("running"):
                return (poll.get("stdout") or "").strip()
        pytest.fail("background job did not finish")

    assert (await run_bg("t-in", f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" '
                                 f"http://127.0.0.1:{origin}/")) == "200"
    assert (await run_bg("t-out", f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" '
                                  f"http://{BLACKHOLE}/")) != "200"
    # A proxy-blind tool must get nothing, not unfiltered access.
    assert "BLOCKED" in (await run_bg(
        "t-nc", f"nc -z -w3 {BLACKHOLE} 443 && echo REACHED || echo BLOCKED"))
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_sessions_are_confined(origin):
    """A session confines the shell itself, so everything typed into it — for as
    long as the foothold lives — inherits the scope."""
    c = client()
    await c._dispatch_command("sandbox_configure",
                              {"allow": ["127.0.0.1"], "default_egress": "deny"})
    sid = (await c._dispatch_command("session_create", {"label": "t"}))["session_id"]
    try:
        async def run(cmd):
            r = await c._dispatch_command(
                "session_exec", {"session_id": sid, "command": cmd})
            return (r.get("output") or "").strip()

        assert (await run("echo $ALL_PROXY")).startswith("socks5h://")
        assert (await run(f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" '
                          f"http://127.0.0.1:{origin}/")) == "200"
        assert (await run(f'curl -s -m 6 -o {NULL_DEVICE} -w "%{{http_code}}" '
                          f"http://{BLACKHOLE}/")) != "200"
        assert "BLOCKED" in (await run(
            f"nc -z -w3 {BLACKHOLE} 443 && echo REACHED || echo BLOCKED"))
    finally:
        await c._dispatch_command("session_delete", {"session_id": sid})
        await sb.get_lane().stop()


def test_every_spawning_command_waits_for_the_lane():
    """Detached launches run off the event loop, so the lane must be up first.

    A command that spawns its own process but is missing from this set would be
    dispatched before the proxy is listening, and `confine` would refuse it.
    """
    from strobes_shell_agent.client import ShellBridgeClient as C
    assert {"shell_bg_start", "session_create", "session_exec"} <= C._NEEDS_LANE


@pytest.mark.asyncio
async def test_confine_refuses_rather_than_returning_a_bare_command(monkeypatch):
    """The failure that must never happen: handing back an unconfined argv.

    A background scan that escaped the scope would be the worst case, since it
    is precisely the traffic a scope exists to bound.
    """
    monkeypatch.setattr(procsandbox, "detect_backend", lambda: None)
    monkeypatch.setattr(l3lane, "available", lambda: False)
    sb._lane = None
    with pytest.raises(sb.SandboxUnavailable):
        sb.confine("curl http://example.com")


# ---------------------------------------------------------------------------
# Packet-level lane
#
# The lane that makes scanners work. A proxy cannot carry a raw SYN, so under
# the proxy lane nmap reports every port as filtered whether or not the target
# is in scope — confident, wrong answers. Filtering packets instead means the
# tool uses ordinary sockets and the kernel decides.
# ---------------------------------------------------------------------------

from strobes_shell_agent import l3lane  # noqa: E402

needs_l3 = pytest.mark.skipif(not l3lane.available(),
                              reason="needs Linux with CAP_NET_ADMIN")


def test_l3_module_is_import_safe_off_linux():
    assert isinstance(l3lane.available(), bool)
    assert l3lane.status()["account"] == "strobes-scan"


def test_l3_ruleset_lets_the_bridge_keep_its_own_network():
    """The bridge must survive its own rules, or it cannot report results."""
    nft = NetworkPolicy.from_lists(allow=["1.2.3.4"]).resolve().to_nftables(uid=4242)
    assert "meta skuid != 4242 accept" in nft


def test_l3_environment_strips_proxy_variables():
    """Leftover proxy settings would point tools at a proxy that is not running.

    The whole point of this lane is that tools use real sockets.
    """
    env = l3lane.environment({"ALL_PROXY": "socks5h://127.0.0.1:1", "PATH": "/bin"})
    assert "ALL_PROXY" not in env
    # nmap checks euid rather than its capabilities, so it needs telling that a
    # non-root uid holding CAP_NET_RAW may raw-scan.
    assert env["NMAP_PRIVILEGED"] == "1"


def test_l3_wrap_drops_privilege_without_a_login_shell():
    """Identity is what the rules key on, so nothing may re-elevate in between."""
    argv = l3lane.wrap_shell("echo hi", uid=4242)
    assert argv[0] in ("setpriv", "runuser", "su")
    if argv[0] == "setpriv":
        assert "--reuid" in argv and "4242" in argv


@needs_l3
def test_l3_nmap_reports_the_truth_in_scope_and_is_blocked_out_of_scope():
    """The whole reason this lane exists, asserted against real nmap."""
    import socket as _socket
    import subprocess
    import threading

    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")

    def serve(sock):
        while True:
            try:
                c, _ = sock.accept()
                c.close()
            except OSError:
                return

    srv = _socket.socket()
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(16)
    threading.Thread(target=serve, args=(srv,), daemon=True).start()

    uid = l3lane.ensure_account()
    l3lane.grant_raw_capabilities()
    try:
        # Loopback is not carved out, so it must be named to be reachable.
        l3lane.apply_policy(
            NetworkPolicy.from_lists(allow=["127.0.0.1"], default_egress="deny"), uid)
        env = l3lane.environment({"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        out = subprocess.run(
            l3lane.wrap_shell(f"nmap -Pn -sT -p {port} 127.0.0.1", uid),
            env=env, capture_output=True, text=True, timeout=120).stdout
        assert f"{port}/tcp open" in out, out

        # Now put it out of scope; the same port must stop being reported open.
        l3lane.apply_policy(
            NetworkPolicy.from_lists(allow=["10.0.0.0/8"], default_egress="deny"), uid)
        out = subprocess.run(
            l3lane.wrap_shell(f"nmap -Pn -sT -p {port} 127.0.0.1", uid),
            env=env, capture_output=True, text=True, timeout=120).stdout
        assert f"{port}/tcp open" not in out, out
    finally:
        l3lane.clear_policy()
        srv.close()


# ---------------------------------------------------------------------------
# Lane capabilities
#
# What a lane can carry is a property of the lane, not something to be guessed
# from the text of a command. Callers need it to interpret results: a port
# scanner under the proxy lane reaches nothing and reports every port filtered,
# so raw_sockets=false is the fact that makes that output meaningless.
# ---------------------------------------------------------------------------

def test_capabilities_describe_the_lane_not_the_command():
    proxy = sb.capabilities("proxy")
    assert proxy["raw_sockets"] is False and proxy["udp"] is False
    assert "not trustworthy" in proxy["note"]

    l3 = sb.capabilities("l3")
    assert l3["raw_sockets"] is True and l3["udp"] is True
    assert l3["enforced_at"] == "packet"


@needs_sandbox
@pytest.mark.asyncio
async def test_every_result_carries_the_lane_that_produced_it():
    """So a caller can interpret output without knowing which host it ran on."""
    result = await sb.get_lane().run_shell("echo hi", timeout=20)
    assert result["lane"]["mode"] in ("proxy", "l3")
    assert isinstance(result["lane"]["raw_sockets"], bool)
    await sb.get_lane().stop()


@needs_sandbox
@pytest.mark.asyncio
async def test_selftest_verifies_the_capability_claim_against_the_host():
    """The claim is measured, not asserted.

    A lane that advertised raw_sockets wrongly would have callers trusting
    scanner output that means nothing, so selftest probes with a real socket
    and fails if the advertisement does not match.
    """
    report = await sb.selftest()
    assert report["capabilities_verified"] is True, report
    assert report["raw_sockets"] == sb.capabilities(report["mode"])["raw_sockets"]


@needs_l3
@pytest.mark.asyncio
async def test_packet_filter_lane_runs_scanners_normally():
    """Where scope is enforced on packets, nmap just runs — nothing intercepts it."""
    result = await sb.get_lane().run_shell("nmap --version", timeout=30)
    assert "Nmap version" in result["stdout"], result
    assert result["lane"]["raw_sockets"] is True
    await sb.get_lane().stop()
