"""Interactive PTY handler for the shell bridge agent.

Opens a local pseudo-terminal and streams I/O back through the WebSocket
to the Strobes platform.

Two backends, selected at runtime:
  * POSIX  — ``pty.openpty()`` + ``os.fork()`` running bash/zsh/sh.
  * Windows — ConPTY via the ``pywinpty`` package, running
    PowerShell/cmd. Requires ``pip install pywinpty`` (declared as a
    Windows-only extra in pyproject.toml). If pywinpty is missing we
    return a clear, actionable error instead of silently failing.
"""

import asyncio
import json
import logging
import os
import sys

from strobes_shell_agent import pack

IS_WINDOWS = sys.platform == "win32"

if not IS_WINDOWS:
    import fcntl
    import pty
    import signal
    import struct
    import termios
else:
    # pywinpty is imported lazily in the Windows session so the agent
    # still starts (and command execution still works) on a Windows box
    # that hasn't installed the optional dependency yet.
    try:
        import winpty  # type: ignore
    except Exception:  # pragma: no cover - exercised only on Windows
        winpty = None

logger = logging.getLogger(__name__)

# Active PTY sessions: session_id -> session object
_sessions = {}


class PtySession:
    """Manages a single POSIX PTY subprocess."""

    def __init__(self, session_id: str, ws, shell: str = "/bin/bash"):
        self.session_id = session_id
        self.ws = ws
        self.shell = shell
        self.pid = None
        self.fd = None  # master fd
        self._running = False
        self._reader_registered = False

    async def start(self, cols: int = 80, rows: int = 24):
        """Open a new PTY and start the shell process."""
        shell = self.shell
        for candidate in [os.environ.get("SHELL"), "/bin/bash", "/bin/zsh", "/bin/sh"]:
            if candidate and os.path.exists(candidate):
                shell = candidate
                break

        # Inject the sandbox pack (nmap/nuclei/... + interpreter, NMAPDIR, nuclei
        # templates) into the interactive shell's environment so terminals have the
        # same tooling as workspace_execute_shell_command. Computed in the parent so
        # the pack's one-time setup runs here, not in the forked child.
        child_env = dict(pack.build_env())
        child_env["TERM"] = "xterm-256color"

        master_fd, slave_fd = pty.openpty()
        # Set initial terminal size on the slave so SIGWINCH carries.
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
        except OSError as e:
            logger.debug(f"[PTY] initial size error: {e}")

        try:
            child_pid = os.fork()
        except OSError:
            os.close(master_fd)
            os.close(slave_fd)
            raise

        if child_pid == 0:
            # Child
            try:
                os.close(master_fd)
                os.setsid()
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                if slave_fd > 2:
                    os.close(slave_fd)
                # --login only on shells we know support it; exec with the pack env.
                if shell.endswith(("/bash", "/zsh")):
                    os.execvpe(shell, [shell, "--login"], child_env)
                else:
                    os.execvpe(shell, [shell], child_env)
            except Exception:
                os._exit(127)

        # Parent
        os.close(slave_fd)
        self.fd = master_fd
        self.pid = child_pid
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self._running = True
        # Register on the event loop directly — no executor thread per session.
        loop = asyncio.get_event_loop()
        loop.add_reader(self.fd, self._on_readable)
        self._reader_registered = True
        logger.info(f"[PTY] Session {self.session_id} started, pid={self.pid}, shell={shell}")

    async def write(self, data: str):
        """Write input data to the PTY."""
        if self.fd is not None and self._running:
            try:
                os.write(self.fd, data.encode("utf-8"))
            except OSError as e:
                logger.warning(f"[PTY] Write error: {e}")
                await self.stop()

    def resize(self, cols: int, rows: int):
        """Resize the PTY terminal."""
        if self.fd is not None:
            self._set_size(cols, rows)

    def _set_size(self, cols: int, rows: int):
        """Set terminal size via ioctl."""
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception as e:
            logger.debug(f"[PTY] Set size error: {e}")

    def _on_readable(self):
        """Called by the event loop when the master fd has data."""
        if not self._running or self.fd is None:
            return
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return
        except OSError:
            data = b""

        if not data:
            # EOF — shell exited. Schedule cleanup on the loop.
            asyncio.create_task(self._on_eof())
            return

        try:
            asyncio.create_task(self.ws.send(json.dumps({
                "type": "pty_output",
                "session_id": self.session_id,
                "data": data.decode("utf-8", errors="replace"),
            })))
        except Exception as e:
            logger.warning(f"[PTY] send error: {e}")

    async def _on_eof(self):
        if not self._running:
            return
        logger.info(f"[PTY] EOF on session {self.session_id}")
        await self.stop(notify=True)

    async def stop(self, notify: bool = True):
        """Stop the PTY session and reap the shell process."""
        if not self._running and self.fd is None and self.pid is None:
            return
        self._running = False

        loop = asyncio.get_event_loop()
        if self._reader_registered and self.fd is not None:
            try:
                loop.remove_reader(self.fd)
            except (ValueError, OSError):
                pass
            self._reader_registered = False

        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Give the shell a moment to clean up.
            await asyncio.sleep(0.3)
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                pass
            self.pid = None

        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

        if notify:
            try:
                await self.ws.send(json.dumps({
                    "type": "pty_closed",
                    "session_id": self.session_id,
                }))
            except Exception:
                pass

        logger.info(f"[PTY] Session {self.session_id} stopped")


class WindowsPtySession:
    """Manages a single Windows ConPTY subprocess via pywinpty.

    pywinpty's API is blocking, so output is drained on a dedicated
    executor thread and handed back to the asyncio loop with
    ``call_soon_threadsafe``. Input/resize/terminate are quick and run
    inline.
    """

    def __init__(self, session_id: str, ws, shell: str = ""):
        self.session_id = session_id
        self.ws = ws
        self.shell = shell
        self.proc = None
        self._running = False
        self._loop = None
        self._reader_future = None

    def _pick_shell(self) -> str:
        if self.shell:
            return self.shell
        # Prefer PowerShell, fall back to cmd.exe via COMSPEC.
        import shutil
        for candidate in ("powershell.exe", "pwsh.exe"):
            found = shutil.which(candidate)
            if found:
                return found
        return os.environ.get("COMSPEC", "cmd.exe")

    async def start(self, cols: int = 80, rows: int = 24):
        if winpty is None:
            raise RuntimeError(
                "pywinpty is not installed. Install it on the target machine "
                "with 'pip install pywinpty' (or reinstall the shell agent with "
                "the [windows] extra) to enable the interactive terminal."
            )

        shell = self._pick_shell()
        self._loop = asyncio.get_event_loop()
        # pywinpty takes (rows, cols) as dimensions. Pass the pack-augmented env so the
        # interactive terminal sees nmap/nuclei/... from the sandbox pack.
        self.proc = winpty.PtyProcess.spawn(
            shell, dimensions=(rows, cols), env=pack.build_env()
        )
        self._running = True
        # Drain output on a thread; pywinpty reads are blocking.
        self._reader_future = self._loop.run_in_executor(None, self._reader_loop)
        logger.info(
            f"[PTY] Windows session {self.session_id} started, shell={shell}"
        )

    def _reader_loop(self):
        """Blocking read loop, runs on an executor thread."""
        while self._running and self.proc is not None:
            try:
                data = self.proc.read(4096)
            except EOFError:
                break
            except Exception as e:  # process died / pipe closed
                logger.debug(f"[PTY] Windows read error: {e}")
                break
            if not data:
                # isalive() False means the shell exited.
                if not self.proc.isalive():
                    break
                continue
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._dispatch_output, data)

        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._dispatch_eof)

    def _dispatch_output(self, data: str):
        if not self._running:
            return
        try:
            asyncio.create_task(self.ws.send(json.dumps({
                "type": "pty_output",
                "session_id": self.session_id,
                "data": data,
            })))
        except Exception as e:
            logger.warning(f"[PTY] send error: {e}")

    def _dispatch_eof(self):
        if not self._running:
            return
        logger.info(f"[PTY] EOF on Windows session {self.session_id}")
        asyncio.create_task(self.stop(notify=True))

    async def write(self, data: str):
        if self.proc is not None and self._running:
            try:
                self.proc.write(data)
            except Exception as e:
                logger.warning(f"[PTY] Windows write error: {e}")
                await self.stop()

    def resize(self, cols: int, rows: int):
        if self.proc is not None:
            try:
                self.proc.setwinsize(rows, cols)
            except Exception as e:
                logger.debug(f"[PTY] Windows set size error: {e}")

    async def stop(self, notify: bool = True):
        if not self._running and self.proc is None:
            return
        self._running = False

        if self.proc is not None:
            try:
                self.proc.terminate(force=True)
            except Exception:
                pass
            self.proc = None

        if notify:
            try:
                await self.ws.send(json.dumps({
                    "type": "pty_closed",
                    "session_id": self.session_id,
                }))
            except Exception:
                pass

        logger.info(f"[PTY] Windows session {self.session_id} stopped")


def _new_session(session_id: str, ws):
    """Factory: pick the right PTY backend for this platform."""
    if IS_WINDOWS:
        return WindowsPtySession(session_id, ws)
    return PtySession(session_id, ws)


async def handle_pty_open(ws, session_id: str, cols: int = 80, rows: int = 24) -> dict:
    """Open a new PTY session."""
    if session_id in _sessions:
        await _sessions[session_id].stop()

    session = _new_session(session_id, ws)
    _sessions[session_id] = session

    try:
        await session.start(cols, rows)
        return {"success": True, "session_id": session_id}
    except Exception as e:
        _sessions.pop(session_id, None)
        logger.error(f"[PTY] Failed to open session {session_id}: {e}")
        return {"success": False, "error": str(e)}


async def handle_pty_input(session_id: str, data: str) -> None:
    """Write input to an existing PTY session."""
    session = _sessions.get(session_id)
    if session:
        await session.write(data)


def handle_pty_resize(session_id: str, cols: int, rows: int) -> None:
    """Resize an existing PTY session."""
    session = _sessions.get(session_id)
    if session:
        session.resize(cols, rows)


async def handle_pty_close(session_id: str) -> dict:
    """Close a PTY session."""
    session = _sessions.pop(session_id, None)
    if session:
        await session.stop()
        return {"success": True}
    return {"success": False, "error": "Session not found"}


async def close_all():
    """Close all PTY sessions (cleanup on disconnect)."""
    for sid in list(_sessions.keys()):
        session = _sessions.pop(sid, None)
        if session:
            await session.stop()
