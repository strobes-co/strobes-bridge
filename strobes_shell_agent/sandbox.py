"""The execution lane — every AI-issued command runs here, under egress scope.

Two mechanisms, each doing the half it is good at:

* :mod:`procsandbox` puts the command in an OS sandbox (Seatbelt on macOS,
  bubblewrap on Linux) whose only permitted network destination is loopback's
  egress proxy. This is what makes the policy unavoidable — a tool that ignores
  proxy settings gets no network rather than unfiltered access.
* :mod:`egress_proxy` decides, per connection, whether the destination is in
  scope, and records why when it is not.

The policy itself is a :class:`~strobes_shell_agent.netpolicy.NetworkPolicy`,
set either by the operator on the command line (:func:`set_initial_policy`) or
pushed by the platform at runtime (:func:`configure`). Both write the same
module-level policy, so there is one answer to "what is enforced".

**The bridge does not run commands unsandboxed.** If no backend is available,
execution fails with a clear error instead of quietly running with unrestricted
egress while reporting a scope that is not being applied.

Out of scope for this module, deliberately: the bridge's *own* traffic (the
websocket to the platform, self-update, artifact push) is not proxied — it
cannot be, or the bridge could not report results.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from typing import Optional

from strobes_shell_agent import config, l3lane, pack, procsandbox
from strobes_shell_agent.egress_proxy import DEFAULT_PORT_RANGE, EgressProxy
from strobes_shell_agent.netpolicy import NetworkPolicy
from strobes_shell_agent.procsandbox import ProcSandbox, SandboxUnavailable

logger = logging.getLogger(__name__)


def _result(success: bool, stdout: str = "", stderr: str = "", exit_code: int = 0,
            start: float = 0.0, error: Optional[str] = None, **extra) -> dict:
    out = {
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "duration_ms": int((time.monotonic() - start) * 1000) if start else 0,
    }
    if error is not None:
        out["error"] = error
    out.update(extra)
    return out


#: Tools that work by opening raw sockets, and so cannot function through a
#: proxy at all. This is a compatibility fact, not a policy: under the proxy
#: lane the sandbox blocks their probes and they report every port as
#: ``filtered`` — plausible, professional-looking, and wrong. Refusing is the
#: only honest answer, because a false negative in a scan is worse than an
#: error. They work normally in the packet-filter lane.
RAW_SOCKET_TOOLS = frozenset({
    "nmap", "masscan", "naabu", "zmap", "unicornscan", "hping3", "arp-scan",
    "traceroute", "ping", "fping",
})


def _raw_socket_tool(command: str) -> Optional[str]:
    """The first raw-socket tool invoked by ``command``, if any.

    Looks at every position a command can start — after a pipe, a semicolon, a
    boolean operator — because ``echo x | nmap ...`` is still an nmap run.
    """
    import re
    for segment in re.split(r"[|;&]+|\$\(|`", command):
        for token in segment.split():
            if token.startswith("-"):
                continue
            name = os.path.basename(token).lower()
            if name in ("sudo", "env", "time", "nohup", "stdbuf"):
                continue  # a wrapper; keep looking at the real command
            if name in RAW_SOCKET_TOOLS:
                return name
            break  # first real word of the segment decides
    return None


class Lane:
    """Owns the proxy and the sandbox, and runs commands through both."""

    def __init__(self, policy: NetworkPolicy):
        self.policy = policy
        self._proxy: Optional[EgressProxy] = None
        self._sandbox: Optional[ProcSandbox] = None
        self._socket_path: Optional[str] = None
        self._l3_uid: Optional[int] = None
        self._lock = asyncio.Lock()

    # -- lifecycle ----------------------------------------------------------

    @property
    def mode(self) -> str:
        """``l3`` (packet filter) or ``proxy`` — which enforcement is in force."""
        return "l3" if self._l3_uid is not None else "proxy"

    async def ensure(self):
        """Bring up enforcement on first use; reuse it thereafter.

        Packet-level enforcement is preferred wherever the host allows it,
        because it is the only mode in which scanners produce correct results —
        a proxy cannot carry a raw SYN, so under the proxy lane nmap reports
        every port as filtered whether or not the target is in scope. The proxy
        lane remains the fallback for hosts without CAP_NET_ADMIN, where it is
        weaker but needs no privileges.
        """
        async with self._lock:
            if self._sandbox is not None or self._l3_uid is not None:
                return self._sandbox

            if l3lane.available():
                uid = await asyncio.to_thread(l3lane.ensure_account)
                caps = await asyncio.to_thread(l3lane.grant_raw_capabilities,
                                               pack.build_env().get("PATH"))
                await asyncio.to_thread(l3lane.apply_policy, self.policy, uid)
                self._l3_uid = uid
                logger.info(
                    "Execution lane ready (mode=l3, uid=%s, raw-capable=%s, egress=%s)",
                    uid, ",".join(caps.get("granted") or []) or "none",
                    "open" if self.policy.is_open else "scoped allowlist",
                )
                return None

            backend = procsandbox.detect_backend()
            if backend is None:
                raise SandboxUnavailable(
                    "no process sandbox available on this host "
                    f"(platform={os.sys.platform}); refusing to run commands "
                    "with unrestricted network access"
                )

            # The Linux sandbox lives in its own network namespace and reaches
            # the proxy over a filesystem UNIX socket; macOS reaches it on
            # loopback directly.
            if backend == procsandbox.BUBBLEWRAP:
                self._socket_path = os.path.join(
                    tempfile.mkdtemp(prefix="strobes-egress-"), "proxy.sock"
                )

            # Windows filters egress by account, and the filter is written
            # against a port range, so the proxy must bind inside it there.
            port_range = (DEFAULT_PORT_RANGE
                          if backend == procsandbox.WINDOWS else None)
            self._proxy = EgressProxy(self.policy, socket_path=self._socket_path,
                                      port_range=port_range)
            port = await self._proxy.start()
            self._sandbox = ProcSandbox(
                proxy_port=port, socket_path=self._socket_path, backend=backend
            )
            logger.info(
                "Execution lane ready (backend=%s, proxy=127.0.0.1:%s, egress=%s)",
                backend, port,
                "open" if self.policy.is_open else "scoped allowlist",
            )
            return self._sandbox

    async def stop(self) -> None:
        if self._l3_uid is not None:
            await asyncio.to_thread(l3lane.clear_policy)
            self._l3_uid = None
        if self._proxy is not None:
            await self._proxy.stop()
            self._proxy = None
        if self._sandbox is not None:
            self._sandbox.cleanup()
            self._sandbox = None
        if self._socket_path:
            try:
                os.rmdir(os.path.dirname(self._socket_path))
            except OSError:
                pass
            self._socket_path = None

    def set_policy(self, policy: NetworkPolicy) -> None:
        """Apply a new policy without restarting anything.

        The proxy consults the policy per connection, so a scope pushed
        mid-session takes effect on the very next connection.
        """
        self.policy = policy
        if self._l3_uid is not None:
            # Replaces the table atomically, so there is no window in which the
            # old scope, or no scope, is in force.
            l3lane.apply_policy(policy, self._l3_uid)
        if self._proxy is not None:
            self._proxy.set_policy(policy)

    @property
    def proxy(self) -> Optional[EgressProxy]:
        return self._proxy

    # -- execution ----------------------------------------------------------

    async def run_shell(self, command: str, timeout: int = 60,
                        cwd: Optional[str] = None) -> dict:
        start = time.monotonic()
        try:
            sandbox = await self.ensure()   # None in l3 mode — no process wrapper
        except SandboxUnavailable as e:
            return _result(False, stderr=str(e), exit_code=-1, start=start,
                           error="sandbox_unavailable")

        if cwd and not os.path.isdir(cwd):
            cwd = None

        # Under the proxy lane a scanner cannot reach anything, but it does not
        # fail — it reports every port as filtered. Refuse rather than hand back
        # results that look real.
        if self._l3_uid is None:
            tool = _raw_socket_tool(command)
            if tool:
                return _result(
                    False,
                    stderr=(
                        f"{tool} needs raw sockets, which this host cannot "
                        f"enforce scope on, so it is refused rather than run: "
                        f"it would report every port as filtered whether or not "
                        f"the target is in scope. Packet-level enforcement "
                        f"(Linux with CAP_NET_ADMIN) runs it normally."
                    ),
                    exit_code=-1, start=start, error="raw_socket_tool_unsupported",
                    tool=tool,
                )

        if self._proxy is not None:
            self._proxy.denials.clear()

        if self._l3_uid is not None:
            argv = l3lane.wrap_shell(command, self._l3_uid)
            env = l3lane.environment(pack.build_env())
            try:
                rc, stdout, stderr = await _spawn(argv, env, cwd, timeout)
            except asyncio.TimeoutError:
                return self._finish(False, "", f"Command timed out after {timeout}s",
                                    -1, start, error="timeout")
            except Exception as e:
                return _result(False, stderr=f"failed to start command: {e}",
                               exit_code=-1, start=start, error="sandbox_start_failed")
            return self._finish(rc == 0, stdout, stderr, rc, start)

        env = sandbox.env(pack.build_env())
        try:
            rc, stdout, stderr = await sandbox.run(command, env, cwd, timeout)
        except asyncio.TimeoutError:
            return self._finish(False, "", f"Command timed out after {timeout}s",
                                -1, start, error="timeout")
        except Exception as e:
            return _result(False, stderr=f"failed to start sandbox: {e}",
                           exit_code=-1, start=start, error="sandbox_start_failed")

        return self._finish(rc == 0, stdout, stderr, rc, start)

    def _finish(self, success, stdout, stderr, exit_code, start, error=None) -> dict:
        """Attach any egress refusals so the caller learns *why* a run failed.

        A command that could not reach its target otherwise looks like a network
        outage; naming the refused destination and the rule lets the agent
        retarget instead of retrying blindly.
        """
        denials = self._proxy.drain_denials() if self._proxy is not None else []
        extra = {}
        if denials:
            extra["egress_denied"] = denials
            note = "; ".join(
                f"{d['host']}:{d['port']} — {d['reason']}" for d in denials[:5]
            )
            stderr = (stderr + f"\n[strobes] egress denied: {note}").strip()
        return _result(success, stdout, stderr, exit_code, start, error=error, **extra)


async def _spawn(argv: list, env: dict, cwd, timeout: int) -> tuple:
    """Run ``argv`` to completion, killing the whole tree on timeout."""
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        procsandbox._kill_tree(proc)
        raise
    return (proc.returncode or 0,
            out.decode(errors="replace"), err.decode(errors="replace"))


# ---------------------------------------------------------------------------
# Module-level policy and lane
# ---------------------------------------------------------------------------

_lane: Optional[Lane] = None
_policy: Optional[NetworkPolicy] = None  # runtime override of the env policy


def _current_policy() -> NetworkPolicy:
    if _policy is not None:
        return _policy
    env = config.network_policy_env()
    return NetworkPolicy.from_lists(
        allow=env["allow"], deny=env["deny"],
        default_egress=env["default_egress"], block_metadata=env["block_metadata"],
    )


def get_lane() -> Lane:
    """The process-wide execution lane, constructed on first use."""
    global _lane
    if _lane is None:
        _lane = Lane(_current_policy())
    return _lane


def set_initial_policy(allow=None, deny=None, default_egress: Optional[str] = None,
                       block_metadata: Optional[bool] = None) -> NetworkPolicy:
    """Set the scope at startup (the operator's command line).

    The synchronous sibling of :func:`configure`. Anything left as ``None``
    falls back to the environment, and thus to the open default.
    """
    global _policy
    env = config.network_policy_env()
    _policy = NetworkPolicy.from_lists(
        allow=allow if allow is not None else env["allow"],
        deny=deny if deny is not None else env["deny"],
        default_egress=default_egress or env["default_egress"],
        block_metadata=env["block_metadata"] if block_metadata is None else block_metadata,
    )
    if _lane is not None:
        _lane.set_policy(_policy)
    return _policy


async def configure(allow=None, deny=None, default_egress: Optional[str] = None,
                    block_metadata: Optional[bool] = None, **_ignored) -> dict:
    """Replace the scope at runtime (the platform pushing engagement scope).

    No restart is needed: the proxy reads the policy per connection, so the next
    connection any running command makes is judged by the new scope.
    """
    global _policy
    base = _current_policy()
    _policy = NetworkPolicy.from_lists(
        allow=allow if allow is not None else [e.value for e in base.allow],
        deny=deny if deny is not None else [e.value for e in base.deny],
        default_egress=default_egress or base.default_egress,
        block_metadata=base.block_metadata if block_metadata is None else block_metadata,
    )
    if _lane is not None:
        _lane.set_policy(_policy)

    resolved = _policy.resolve()
    status = describe_policy()
    status.update({
        "success": True,
        "resolved_allow": sorted(resolved.allow_cidrs),
        "unresolved": list(resolved.unresolved),
    })
    return status


async def ensure_ready() -> None:
    """Start the lane so :func:`confine` can be used from a worker thread.

    Detached and interactive launches (background jobs, shell sessions, PTYs)
    happen synchronously off the event loop, so the proxy has to be listening
    before they are handed the confinement wrapper.
    """
    await get_lane().ensure()


def confine(command: str, base_env: Optional[dict] = None) -> tuple:
    """Return ``(argv, env)`` that runs ``command`` under the egress sandbox.

    The synchronous counterpart to :meth:`Lane.run_shell`, for the launch sites
    that own their own process (``subprocess.Popen`` for a background job, a
    PTY-attached shell) and so cannot go through the lane's own spawn.

    Raises :class:`SandboxUnavailable` rather than returning an unconfined
    command — a background scan that quietly escapes the scope would be the
    worst of both worlds, since it is exactly the long-running traffic a scope
    is meant to bound.
    """
    lane = get_lane()
    if lane._l3_uid is not None:
        return (l3lane.wrap_shell(command, lane._l3_uid),
                l3lane.environment(base_env or pack.build_env()))
    box = lane._sandbox
    if box is None:
        raise SandboxUnavailable(
            "the execution lane is not running; call ensure_ready() first"
        )
    if box.backend == procsandbox.WINDOWS:
        # Windows confines by launching under another account's token, which has
        # no argv form. Detached launches there are refused until that path
        # grows a detached variant.
        raise SandboxUnavailable(
            "background jobs and sessions are not yet supported under the "
            "Windows sandbox; use shell_execute, which is confined"
        )
    return box.wrap_shell(command), box.env(base_env or pack.build_env())


def adopt_path(path: str) -> None:
    """Make ``path`` usable by the identity commands run as.

    In the packet-filter lane commands run as a separate account, so anything
    the *bridge* writes for a command to read — an interpreter source file, an
    input fixture — is owned by the wrong user. Ownership is handed over
    explicitly rather than by loosening the mode, so the file never becomes
    world-readable just to cross that boundary.

    A no-op in the proxy lane, where the command runs as the bridge's own user.
    """
    # Resolved without needing the lane to be running: the file is written
    # before the first command starts it.
    if _lane is not None and _lane._l3_uid is not None:
        uid = _lane._l3_uid
    elif l3lane.available():
        # The account is created here if the lane has not started yet — knowing
        # the identity to hand the file to is the same thing as having one.
        uid = l3lane.account_uid() or l3lane.ensure_account()
    else:
        return
    if uid is None:
        return
    try:
        os.chown(path, uid, -1)
    except OSError:
        # Not fatal: the command will report its own permission error, which is
        # a clearer signal than a failure here would be.
        pass


def describe_policy() -> dict:
    """What is enforced right now — for the CLI banner and the platform."""
    p = _current_policy()
    return {
        "default_egress": p.default_egress,
        "allow": [e.value for e in p.allow],
        "deny": [e.value for e in p.deny],
        "block_metadata": p.block_metadata,
        "enforced": not p.is_open,
        "mode": _lane.mode if _lane is not None else (
            "l3" if l3lane.available() else "proxy"),
        "sandbox": procsandbox.describe(),
        "l3": l3lane.status(),
    }


async def selftest() -> dict:
    """Prove the sandbox confines egress — and that it still passes traffic.

    Cheap insurance against the worst failure mode: a bridge that reports a
    scope it is not applying. Two halves, and both matter:

    * a **positive control** — an allowed destination must be reachable. Without
      it a totally broken sandbox, where nothing works at all, would look
      identical to a correctly enforcing one.
    * the **negative case** — an out-of-scope destination must be refused.

    Because it exercises the real backend, this is the only check that means
    anything on a platform this code has not been proven on.
    """
    blackhole = "198.51.100.42"  # TEST-NET-2: routable-looking, black-holed

    # A target we own, so "reachable" is unambiguous and needs no internet.
    async def handle(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    lane = Lane(NetworkPolicy.from_lists(allow=["127.0.0.1"], default_egress="deny"))
    try:
        allowed = await lane.run_shell(
            f"curl -s -m 8 -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port}/",
            timeout=25,
        )
        reachable = (allowed.get("stdout") or "").strip().endswith("200")

        denied_run = await lane.run_shell(
            f"curl -s -m 8 -o /dev/null -w '%{{http_code}}' http://{blackhole}/",
            timeout=25,
        )
        # The process exit code is the wrong signal: a refusal delivered as the
        # proxy's 403 is, to curl, a perfectly successful HTTP transaction. Judge
        # on the status code, corroborated by the proxy's own denial record.
        code = (denied_run.get("stdout") or "").strip()[-3:]
        reached_blackhole = code.isdigit() and 200 <= int(code) < 400
        denials = [d for d in (denied_run.get("egress_denied") or [])
                   if d.get("host") == blackhole]

        ok = reachable and not reached_blackhole
        if not reachable:
            detail = ("SANDBOX IS NOT PASSING TRAFFIC — an allowed destination was "
                      "unreachable, so the refusal below proves nothing")
        elif reached_blackhole:
            detail = "OUT-OF-SCOPE DESTINATION WAS REACHABLE — egress is not enforced"
        elif denials:
            detail = f"in-scope reachable; out-of-scope refused: {denials[0]['reason']}"
        else:
            detail = "in-scope reachable; out-of-scope was not reachable"

        return {
            "ok": ok,
            "mode": lane.mode,
            "backend": procsandbox.detect_backend(),
            "detail": detail,
            "allowed_reachable": reachable,
            "denied": denials,
        }
    except SandboxUnavailable as e:
        return {"ok": False, "mode": None, "backend": None, "detail": str(e)}
    finally:
        await lane.stop()
        server.close()
