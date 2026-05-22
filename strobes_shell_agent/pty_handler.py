"""Interactive PTY handler for the shell bridge agent.

Opens a local pseudo-terminal (bash/zsh) and streams I/O
back through the WebSocket to the Strobes platform.
"""

import asyncio
import json
import logging
import os
import sys

IS_WINDOWS = sys.platform == "win32"

if not IS_WINDOWS:
    import fcntl
    import pty
    import signal
    import struct
    import termios

logger = logging.getLogger(__name__)

# Active PTY sessions: session_id -> PtySession
_sessions = {}


class PtySession:
    """Manages a single PTY subprocess."""

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
                os.environ["TERM"] = "xterm-256color"
                # --login only on shells we know support it
                if shell.endswith(("/bash", "/zsh")):
                    os.execlp(shell, shell, "--login")
                else:
                    os.execlp(shell, shell)
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


async def handle_pty_open(ws, session_id: str, cols: int = 80, rows: int = 24) -> dict:
    """Open a new PTY session."""
    if IS_WINDOWS:
        return {
            "success": False,
            "error": "Interactive PTY sessions are not supported on Windows.",
        }

    if session_id in _sessions:
        await _sessions[session_id].stop()

    session = PtySession(session_id, ws)
    _sessions[session_id] = session

    try:
        await session.start(cols, rows)
        return {"success": True, "session_id": session_id}
    except Exception as e:
        _sessions.pop(session_id, None)
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
