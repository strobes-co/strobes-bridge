"""Tests for the PTY handler, focused on the cross-platform plumbing.

The POSIX fork/exec path and the Windows ConPTY path can only be fully
exercised on their own OS, but the backend selection, the missing
pywinpty error, and shell selection are testable everywhere.
"""

import sys

import pytest

from strobes_shell_agent import pty_handler


def test_factory_matches_platform():
    session = pty_handler._new_session("sid", ws=None)
    if pty_handler.IS_WINDOWS:
        assert isinstance(session, pty_handler.WindowsPtySession)
    else:
        assert isinstance(session, pty_handler.PtySession)


@pytest.mark.asyncio
async def test_windows_session_errors_without_pywinpty(monkeypatch):
    """start() must raise an actionable error when pywinpty is absent,
    rather than silently doing nothing."""
    monkeypatch.setattr(pty_handler, "winpty", None, raising=False)
    session = pty_handler.WindowsPtySession("sid", ws=None)
    with pytest.raises(RuntimeError, match="pywinpty"):
        await session.start()


def test_windows_pick_shell_prefers_powershell(monkeypatch):
    session = pty_handler.WindowsPtySession("sid", ws=None)
    monkeypatch.setattr(
        pty_handler.os.environ, "get", lambda *a, **k: "C:\\cmd.exe"
    )
    import shutil

    monkeypatch.setattr(
        shutil, "which",
        lambda name: "C:\\powershell.exe" if "powershell" in name else None,
    )
    assert session._pick_shell().endswith("powershell.exe")


def test_windows_pick_shell_falls_back_to_comspec(monkeypatch):
    session = pty_handler.WindowsPtySession("sid", ws=None)
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setenv("COMSPEC", "C:\\Windows\\System32\\cmd.exe")
    assert session._pick_shell().endswith("cmd.exe")


@pytest.mark.asyncio
async def test_handle_pty_open_reports_failure(monkeypatch):
    """A backend that fails to start surfaces success=False and does not
    leave a dangling session registered."""

    class _Boom:
        def __init__(self, *a, **k):
            pass

        async def start(self, *a, **k):
            raise RuntimeError("nope")

        async def stop(self, *a, **k):
            pass

    monkeypatch.setattr(pty_handler, "_new_session", lambda sid, ws: _Boom())
    result = await pty_handler.handle_pty_open(ws=None, session_id="x")
    assert result["success"] is False
    assert "nope" in result["error"]
    assert "x" not in pty_handler._sessions
