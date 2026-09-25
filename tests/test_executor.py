"""Tests for the command executor."""

import asyncio
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from strobes_shell_agent import pack
from strobes_shell_agent import executor as executor_mod
from strobes_shell_agent.executor import (
    execute_shell_command,
    execute_code,
    read_file,
    write_file,
    list_files,
    windows_shell_compat,
    file_pull,
    file_push,
)

IS_WINDOWS = sys.platform == "win32"


def _lane_available() -> bool:
    """Can this host actually execute a command at all?

    Execution goes through the egress sandbox, and there is deliberately no
    unsandboxed fallback: a host with no usable backend refuses to run
    commands rather than running them with unrestricted network access. That
    is the product behaviour, not a defect, so on such a host these tests have
    nothing to assert about exit codes and timeouts.

    CI runners are exactly that host. bubblewrap is installed but unprivileged
    user namespaces are not permitted, and an un-provisioned Windows runner has
    had no `sandbox-setup`. Skipping is the honest outcome; asserting success
    would only be asking the sandbox to stop sandboxing.
    """
    from strobes_shell_agent import l3lane, procsandbox
    return l3lane.available() or procsandbox.available()


#: Applied per-test rather than to the module, so the pure-unit tests around it
#: (windows_shell_compat, read/write/list, file_pull/file_push) keep running on
#: every platform -- they need no lane, and losing them to a blanket skip would
#: quietly halve this file's coverage on CI.
needs_lane = pytest.mark.skipif(
    not _lane_available(),
    reason="no usable execution lane on this host (no sandbox backend); "
           "the executor refuses to run commands unsandboxed by design",
)


# ---------------------------------------------------------------------------
# Windows shell compatibility
#
# These are pure string-transform tests, run on whatever host CI/the dev
# machine happens to be — windows_shell_compat() never inspects the real
# platform itself (execute_shell_command is the only IS_WINDOWS-gated call
# site), so the rewrite logic is fully exercisable from macOS/Linux too. The
# cases below are the exact shapes shell_precheck_service.py sends today.
# ---------------------------------------------------------------------------


class TestWindowsShellCompat:

    def test_dev_null_rewritten_to_nul(self, monkeypatch):
        monkeypatch.setattr(pack, "pack_python", lambda: None)
        monkeypatch.setattr(pack, "build_env", lambda: {"PATH": ""})
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

        cmd = "python3 --version 2>/dev/null || python --version 2>/dev/null"
        out = windows_shell_compat(cmd)

        assert "/dev/null" not in out
        assert out.count("NUL") == 2

    def test_dash_c_single_quoted_extracted_to_tempfile(self, monkeypatch, tmp_path):
        fake_py = tmp_path / "python.exe"
        fake_py.write_text("")
        monkeypatch.setattr(pack, "pack_python", lambda: fake_py)

        cmd = "python3 -c 'from playwright.sync_api import sync_playwright' 2>&1"
        out = windows_shell_compat(cmd)

        assert "-c" not in out
        assert "'" not in out
        assert str(fake_py) in out

        temp_paths = [p for p in out.split() if "strobes_c_" in p and p.endswith(".py")]
        assert len(temp_paths) == 1, out
        assert Path(temp_paths[0]).read_text() == (
            "from playwright.sync_api import sync_playwright"
        )

    def test_dash_c_with_embedded_double_quotes(self, monkeypatch, tmp_path):
        """The exact playwright-post-install-check shape: a single-quoted -c
        body that itself contains double quotes (print("pwok"))."""
        fake_py = tmp_path / "python.exe"
        fake_py.write_text("")
        monkeypatch.setattr(pack, "pack_python", lambda: fake_py)

        cmd = (
            "python3 -c 'from playwright.sync_api import sync_playwright; "
            'print("pwok")\' 2>&1'
        )
        out = windows_shell_compat(cmd)

        temp_paths = [p for p in out.split() if "strobes_c_" in p and p.endswith(".py")]
        assert len(temp_paths) == 1, out
        assert Path(temp_paths[0]).read_text() == (
            'from playwright.sync_api import sync_playwright; print("pwok")'
        )

    def test_bare_python_and_pip_tokens_resolved_to_pack(self, monkeypatch, tmp_path):
        fake_py = tmp_path / "python.exe"
        fake_py.write_text("")
        monkeypatch.setattr(pack, "pack_python", lambda: fake_py)

        cmd = "pip3 install --quiet playwright || pip install --quiet playwright"
        out = windows_shell_compat(cmd)

        assert "pip3" not in out
        assert out.count(f"{fake_py} -m pip install") == 2

    def test_powershell_commands_pass_through_unchanged(self):
        cmd = "powershell -NoProfile -Command \"$PY='C:\\pack\\python.exe'; & $PY probe.py\""
        assert windows_shell_compat(cmd) == cmd

    def test_falls_back_to_path_when_no_pack(self, monkeypatch):
        monkeypatch.setattr(pack, "pack_python", lambda: None)
        monkeypatch.setattr(pack, "build_env", lambda: {"PATH": "/usr/bin"})
        monkeypatch.setattr(
            shutil,
            "which",
            lambda name, path=None: "/usr/bin/python" if name == "python" else None,
        )

        out = windows_shell_compat("python --version")

        assert "/usr/bin/python" in out

    def test_unresolvable_interpreter_leaves_tokens_alone(self, monkeypatch):
        """No pack and nothing on PATH: don't invent a broken path, just skip
        the token-resolution step (the /dev/null and -c rewrites, which
        don't depend on finding an interpreter, still apply)."""
        monkeypatch.setattr(pack, "pack_python", lambda: None)
        monkeypatch.setattr(pack, "build_env", lambda: {"PATH": ""})
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

        out = windows_shell_compat("python --version 2>/dev/null")

        assert out == "python --version 2>NUL"

    def test_never_raises_on_resolution_failure(self, monkeypatch):
        def _boom():
            raise RuntimeError("boom")

        monkeypatch.setattr(executor_mod, "_win_resolve_python", _boom)

        # No /dev/null or -c shape in this one, so the only thing that could
        # fail is python-token resolution — confirms the failure is swallowed
        # rather than raised, and the command is returned as-is.
        assert windows_shell_compat("echo hi") == "echo hi"


@needs_lane
@pytest.mark.asyncio
async def test_shell_success():
    r = await execute_shell_command("echo hello", timeout=5)
    assert r["success"] is True
    assert "hello" in r["stdout"]
    assert r["exit_code"] == 0


@needs_lane
@pytest.mark.asyncio
async def test_shell_failure_exit_code():
    cmd = "exit 7" if not IS_WINDOWS else "exit /b 7"
    r = await execute_shell_command(cmd, timeout=5)
    assert r["success"] is False
    assert r["exit_code"] == 7


@needs_lane
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


@needs_lane
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


@needs_lane
@pytest.mark.asyncio
async def test_execute_code_python():
    r = await execute_code("python", "print(2+2)", timeout=10)
    assert r["success"] is True
    assert "4" in r["stdout"]


@needs_lane
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
