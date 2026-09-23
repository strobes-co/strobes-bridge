"""OS process sandboxing — the half that makes the egress proxy unavoidable.

The proxy in :mod:`egress_proxy` decides what a command may reach. This module
makes sure a command cannot decline to ask: it runs each one under an OS
sandbox whose only permitted network destination is the proxy on loopback.

That distinction is the whole point. Setting ``HTTP_PROXY`` is a request a
program is free to ignore — and Go's ``net/http`` ignores it outright unless the
transport opts in. Here the kernel refuses every other destination, so a program
that bypasses the proxy gets no network at all rather than unfiltered access.
Verified against ``nc``, which knows nothing about proxies and is simply blocked.

Backends:

* **macOS** — Seatbelt via ``sandbox-exec``. Seatbelt cannot express an IP
  allowlist (its ``remote`` filter accepts only ``*`` and ``localhost``), which
  is exactly why the allowlist lives in the proxy and Seatbelt's job is reduced
  to "loopback proxy port, nothing else".
* **Linux** — bubblewrap with ``--unshare-net``. A fresh network namespace has
  no route to the host's loopback, so the proxy is reached over a filesystem
  UNIX socket bind-mounted into the sandbox (filesystem sockets cross a network
  namespace; abstract ones do not) with a small relay presenting it as a local
  TCP port.
* **Windows** — no equivalent primitive exists, so the boundary is drawn around
  an *identity* instead: commands run as a dedicated local account whose
  outbound traffic a Windows Filtering Platform rule blocks. Matching on the
  account's SID means the rule follows every child process. Needs one-time
  elevated setup (``sandbox-setup``); until that is done the host reports no
  backend rather than pretending to confine anything. See :mod:`winsandbox`.

Coverage is honest about itself: macOS is exercised by the test suite, Linux is
implemented but unproven, and Windows has been verified against a live host
(see :mod:`winsandbox`). ``sandbox-check`` runs a real out-of-scope connection
so any of them can prove or disprove itself in place.

There is deliberately **no unsandboxed fallback**. If no backend is available
the bridge refuses to execute rather than quietly running commands with
unrestricted egress while reporting a scope it is not applying.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from typing import Optional

SEATBELT = "seatbelt"
BUBBLEWRAP = "bubblewrap"
WINDOWS = "windows-wfp"

# Presented to the sandboxed process as its proxy. Any free port works; it is
# only ever reachable from inside.
_INNER_PORT = 8118


class SandboxUnavailable(RuntimeError):
    """No usable sandbox backend on this host — execution must not proceed."""


def detect_backend() -> Optional[str]:
    """Which backend this host can use, or ``None``.

    Windows is conditional on one-time elevated setup (a dedicated account plus
    its egress filter), so an un-provisioned Windows host reports no backend
    rather than pretending to confine anything.
    """
    if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
        return SEATBELT
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return BUBBLEWRAP
    if sys.platform == "win32":
        from strobes_shell_agent import winsandbox
        return WINDOWS if winsandbox.ready() else None
    return None


def available() -> bool:
    return detect_backend() is not None


def describe() -> dict:
    backend = detect_backend()
    out = {
        "backend": backend,
        "available": backend is not None,
        "platform": sys.platform,
    }
    if sys.platform == "win32":
        from strobes_shell_agent import winsandbox
        out["windows"] = winsandbox.status()
        if backend is None:
            out["hint"] = ("run `strobes-shell-agent sandbox-setup` from an "
                           "elevated prompt to provision the sandbox account")
    return out


# ---------------------------------------------------------------------------
# Seatbelt (macOS)
# ---------------------------------------------------------------------------

def seatbelt_profile(proxy_port: int) -> str:
    """A Seatbelt profile allowing egress only to ``localhost:proxy_port``.

    ``(allow default)`` keeps this to a *network* sandbox: filesystem and
    process access are unchanged, because the bridge's tools legitimately read
    and write all over the host. Narrowing those is a separate decision, and
    pretending otherwise here would be misleading.

    UNIX sockets stay permitted — they are local IPC (syslog and friends), not
    egress, and denying them breaks ordinary tooling for no security gain.
    """
    return f"""(version 1)
;; Strobes bridge — network-confinement profile.
;; Everything except the egress proxy is refused at the socket layer, so a tool
;; that ignores proxy settings gets no network rather than unfiltered access.
(allow default)
(deny network*)
(allow network-outbound (remote unix-socket))
(allow network-bind (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:{proxy_port}"))
"""


# ---------------------------------------------------------------------------
# bubblewrap (Linux)
# ---------------------------------------------------------------------------

def _bwrap_argv(socket_path: str, inner_port: int) -> list:
    """bubblewrap arguments for a network-isolated sandbox with a proxy bridge.

    ``--unshare-net`` gives an empty network namespace: no route anywhere,
    including to the host's loopback. The proxy's UNIX socket is bind-mounted
    in, and a relay inside the namespace republishes it as ``127.0.0.1:port``
    so ordinary ``ALL_PROXY`` clients work unchanged.
    """
    return [
        "bwrap",
        "--dev-bind", "/", "/",          # network confinement only, as on macOS
        "--unshare-net",                  # no route out except the bridged socket
        "--ro-bind", socket_path, socket_path,
        "--die-with-parent",
    ]


def _relay_program(socket_path: str, inner_port: int) -> str:
    """A self-contained TCP→UNIX relay, run inside the network namespace.

    Written as a Python one-liner rather than depending on ``socat`` being
    installed, since a missing relay would silently mean "no network".
    """
    return (
        "import socket,threading,sys\n"
        f"srv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"srv.bind(('127.0.0.1',{inner_port}));srv.listen(64)\n"
        "def pipe(a,b):\n"
        "    try:\n"
        "        while True:\n"
        "            d=a.recv(65536)\n"
        "            if not d: break\n"
        "            b.sendall(d)\n"
        "    except OSError: pass\n"
        "    finally:\n"
        "        for s in (a,b):\n"
        "            try: s.close()\n"
        "            except OSError: pass\n"
        "def serve(c):\n"
        "    u=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
        "    try: u.connect(%r)\n" % socket_path +
        "    except OSError:\n"
        "        c.close(); return\n"
        "    threading.Thread(target=pipe,args=(c,u),daemon=True).start()\n"
        "    threading.Thread(target=pipe,args=(u,c),daemon=True).start()\n"
        "while True:\n"
        "    c,_=srv.accept()\n"
        "    threading.Thread(target=serve,args=(c,),daemon=True).start()\n"
    )


# ---------------------------------------------------------------------------
# The sandbox
# ---------------------------------------------------------------------------

class ProcSandbox:
    """Wraps a shell command so it runs confined to the egress proxy.

    ``proxy_port`` is the host-side TCP port for Seatbelt; ``socket_path`` is
    the host-side UNIX socket for bubblewrap. Only the one the active backend
    needs must be supplied.
    """

    def __init__(self, proxy_port: Optional[int] = None,
                 socket_path: Optional[str] = None,
                 backend: Optional[str] = None):
        self.backend = backend or detect_backend()
        if self.backend is None:
            raise SandboxUnavailable(
                "no process sandbox available on this host "
                f"(platform={sys.platform}); refusing to run commands with "
                "unrestricted network access"
            )
        self.proxy_port = proxy_port
        self.socket_path = socket_path
        self._profile_path: Optional[str] = None

        if self.backend in (SEATBELT, WINDOWS) and not proxy_port:
            raise ValueError(f"{self.backend} backend needs proxy_port")
        if self.backend == BUBBLEWRAP and not socket_path:
            raise ValueError("bubblewrap backend needs socket_path")

    # -- environment --------------------------------------------------------

    @property
    def inner_proxy(self) -> str:
        """``host:port`` the sandboxed process should use as its proxy."""
        if self.backend in (SEATBELT, WINDOWS):
            return f"127.0.0.1:{self.proxy_port}"
        return f"127.0.0.1:{_INNER_PORT}"

    def env(self, base: Optional[dict] = None) -> dict:
        """Environment for a sandboxed command, pointing every client at the proxy.

        ``socks5h`` (rather than ``socks5``) keeps name resolution on the proxy
        side, which is what makes hostname rules exact and closes the rebinding
        window. ``NO_PROXY`` is deliberately *not* set: there is no destination
        the sandbox may reach directly.
        """
        env = dict(base or os.environ)
        socks = f"socks5h://{self.inner_proxy}"
        http = f"http://{self.inner_proxy}"
        env.update({
            "ALL_PROXY": socks, "all_proxy": socks,
            "HTTP_PROXY": http, "http_proxy": http,
            "HTTPS_PROXY": http, "https_proxy": http,
        })
        env.pop("NO_PROXY", None)
        env.pop("no_proxy", None)
        return env

    # -- wrapping -----------------------------------------------------------

    async def run(self, command: str, env: dict, cwd, timeout: int) -> tuple:
        """Run ``command`` confined, returning ``(returncode, stdout, stderr)``.

        The single execution entry point. POSIX backends wrap the command in an
        argv and exec it; Windows cannot — it has to launch under a different
        account's token — so the divergence is contained here rather than
        leaking into the lane.
        """
        if self.backend == WINDOWS:
            from strobes_shell_agent import winsandbox
            import asyncio
            # Blocking Win32 calls; keep them off the event loop.
            return await asyncio.to_thread(
                winsandbox.run_as_sandbox, command, env, cwd, timeout
            )

        import asyncio
        proc = await asyncio.create_subprocess_exec(
            *self.wrap_shell(command), cwd=cwd, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # kill the whole tree on timeout
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            _kill_tree(proc)
            raise
        return (proc.returncode or 0,
                out.decode(errors="replace"), err.decode(errors="replace"))

    def wrap_shell(self, command: str) -> list:
        """Return the argv that runs ``command`` inside the sandbox (POSIX)."""
        if self.backend == WINDOWS:
            raise RuntimeError("the windows backend launches via run(), not argv")
        if self.backend == SEATBELT:
            return ["/usr/bin/sandbox-exec", "-f", self._profile(),
                    "/bin/sh", "-c", command]

        # bubblewrap: start the relay, then exec the command in its own shell.
        relay = _relay_program(self.socket_path, _INNER_PORT)
        inner = (
            f"python3 -c {_sh_quote(relay)} >/dev/null 2>&1 &\n"
            # Give the relay a moment to bind before the command runs.
            "for _ in 1 2 3 4 5 6 7 8 9 10; do\n"
            f"  (exec 3<>/dev/tcp/127.0.0.1/{_INNER_PORT}) 2>/dev/null && break\n"
            "  sleep 0.05\n"
            "done\n"
            f"{command}\n"
        )
        return _bwrap_argv(self.socket_path, _INNER_PORT) + ["/bin/sh", "-c", inner]

    def _profile(self) -> str:
        if self._profile_path and os.path.exists(self._profile_path):
            return self._profile_path
        fd, path = tempfile.mkstemp(prefix="strobes-sandbox-", suffix=".sb")
        with os.fdopen(fd, "w") as fh:
            fh.write(seatbelt_profile(self.proxy_port))
        self._profile_path = path
        return path

    def cleanup(self) -> None:
        if self._profile_path and os.path.exists(self._profile_path):
            try:
                os.unlink(self._profile_path)
            except OSError:
                pass
            self._profile_path = None


def _sh_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def _kill_tree(proc) -> None:
    """Kill the process group so a timeout takes the children too."""
    import os
    import signal
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
