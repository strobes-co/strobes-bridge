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
    file_pull,
    file_push,
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


import hashlib
import http.server
import socketserver
import threading


class _FakeS3(http.server.BaseHTTPRequestHandler):
    """PUT stores an object, GET serves it — stands in for a presigned URL."""
    store = {}

    def log_message(self, *a):
        pass

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        _FakeS3.store[self.path] = self.rfile.read(n)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        data = _FakeS3.store.get(self.path)
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def fake_s3():
    _FakeS3.store.clear()
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeS3)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_file_push_no_size_cap(tmp_path, fake_s3):
    """file_push streams straight to S3 — no 7.7 MB base64 ceiling."""
    p = tmp_path / "big.bin"
    payload = os.urandom(9_000_000)  # 9 MB, over the old WS-frame limit
    p.write_bytes(payload)
    r = file_push(str(p), f"{fake_s3}/obj/big")
    assert r["success"] is True
    assert r["size"] == len(payload)
    assert r["sha256"] == hashlib.sha256(payload).hexdigest()


def test_file_pull_roundtrip_and_integrity(tmp_path, fake_s3):
    src = tmp_path / "src.bin"
    payload = b"binary\x00data" * 1000
    src.write_bytes(payload)
    file_push(str(src), f"{fake_s3}/obj/rt")
    sha = hashlib.sha256(payload).hexdigest()

    dst = tmp_path / "dst.bin"
    r = file_pull(str(dst), f"{fake_s3}/obj/rt", sha256=sha)
    assert r["success"] is True
    assert dst.read_bytes() == payload


def test_file_pull_bad_sha_fails_loud(tmp_path, fake_s3):
    src = tmp_path / "s.bin"
    src.write_bytes(b"hello")
    file_push(str(src), f"{fake_s3}/obj/s")
    dst = tmp_path / "out.bin"
    r = file_pull(str(dst), f"{fake_s3}/obj/s", sha256="deadbeef")
    assert r["success"] is False
    assert "sha256 mismatch" in r["error"]
    assert not dst.exists()  # partial cleaned up


def test_file_pull_missing_object_fails_loud(tmp_path, fake_s3):
    r = file_pull(str(tmp_path / "x.bin"), f"{fake_s3}/obj/missing")
    assert r["success"] is False
    assert "404" in r["error"]
