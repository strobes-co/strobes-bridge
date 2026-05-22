"""Tests for the command executor."""

import asyncio
import os
import sys
import time

import pytest

from strobes_shell_agent.executor import (
    execute_shell_command,
    execute_code,
    read_file,
    write_file,
    list_files,
    download_file,
    upload_file,
)

IS_WINDOWS = sys.platform == "win32"


@pytest.mark.asyncio
async def test_shell_success():
    r = await execute_shell_command("echo hello", timeout=5)
    assert r["success"] is True
    assert "hello" in r["stdout"]
    assert r["exit_code"] == 0


@pytest.mark.asyncio
async def test_shell_failure_exit_code():
    cmd = "exit 7" if not IS_WINDOWS else "exit /b 7"
    r = await execute_shell_command(cmd, timeout=5)
    assert r["success"] is False
    assert r["exit_code"] == 7


@pytest.mark.asyncio
async def test_shell_timeout():
    """Timeout must kill the parent and any children it spawned."""
    if IS_WINDOWS:
        cmd = "ping -n 60 127.0.0.1 > nul"
    else:
        cmd = "sleep 30"
    t0 = time.monotonic()
    r = await execute_shell_command(cmd, timeout=1)
    elapsed = time.monotonic() - t0
    assert r["success"] is False
    assert r.get("error") == "timeout"
    # Should return promptly, well under the sleep duration.
    assert elapsed < 5


@pytest.mark.asyncio
async def test_shell_kills_grandchildren():
    """When the shell forks a child, the timeout must reap the child too."""
    if IS_WINDOWS:
        pytest.skip("process group semantics differ on Windows")
    # Spawn a python child that sleeps 60s, capture its PID.
    py = sys.executable
    cmd = f"{py} -c 'import os,time; print(os.getpid(), flush=True); time.sleep(60)'"
    r = await execute_shell_command(cmd, timeout=1)
    assert r["success"] is False
    # After the kill, the child PID should be gone.
    pid_str = r["stdout"].strip().split()[0] if r["stdout"].strip() else None
    if pid_str:
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_str), 0)


@pytest.mark.asyncio
async def test_execute_code_python():
    r = await execute_code("python", "print(2+2)", timeout=10)
    assert r["success"] is True
    assert "4" in r["stdout"]


@pytest.mark.asyncio
async def test_execute_code_handles_missing_cwd(tmp_path):
    """If cwd is bogus, we still run (in default cwd) instead of crashing."""
    r = await execute_code("python", "print('ok')", timeout=10,
                           cwd=str(tmp_path / "does-not-exist"))
    assert r["success"] is True
    assert "ok" in r["stdout"]


def test_read_write_roundtrip(tmp_path):
    p = tmp_path / "hello.txt"
    w = write_file(str(p), "héllo world\n")
    assert w["success"] is True
    r = read_file(str(p))
    assert r["success"] is True
    assert r["content"] == "héllo world\n"


def test_list_files(tmp_path):
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "b.txt").write_text("2")
    r = list_files(str(tmp_path))
    assert r["success"] is True
    names = {f["name"] for f in r["files"]}
    assert {"a.txt", "b.txt"}.issubset(names)


def test_download_size_limit(tmp_path):
    """download_file must reject payloads that would exceed the WS frame."""
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 8_000_000)  # 8 MB raw → ~10.7 MB base64
    r = download_file(str(big))
    assert r["success"] is False
    assert "too large" in r["error"]


def test_download_under_limit(tmp_path):
    p = tmp_path / "small.bin"
    p.write_bytes(b"hello")
    r = download_file(str(p))
    assert r["success"] is True
    assert r["size"] == 5


def test_upload_roundtrip(tmp_path):
    import base64
    p = tmp_path / "uploaded.bin"
    payload = b"binary\x00data"
    r = upload_file(str(p), base64.b64encode(payload).decode())
    assert r["success"] is True
    assert p.read_bytes() == payload
