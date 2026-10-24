"""On a provisioned Windows bridge, can the AGENT use the workspace -- safely?

Commands run as the sandbox account. This checks the real thing end to end on
a Windows runner where `sandbox-setup` has run (the CI egress job; skipped
everywhere else):

* files the bridge pulls are readable by a sandboxed command,
* a sandboxed command can save output into the workspace,
* the scan the platform uses reports it, and the push sends it,
* a directory junction the sandbox account plants is neither scanned nor
  pushed -- transfers run as that account, so it can never reach more than
  the account itself could.

A local HTTP server stands in for S3's presigned GET/PUT (loopback is not
filtered by the Windows sandbox's egress rules).
"""

import asyncio
import http.server
import os
import subprocess
import sys
import threading

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows sandbox account")


def _ready():
    from strobes_shell_agent import procsandbox
    return procsandbox.detect_backend() == procsandbox.WINDOWS


class _Store(http.server.BaseHTTPRequestHandler):
    blobs = {}

    def do_GET(self):  # noqa: N802
        data = self.blobs.get(self.path)
        self.send_response(200 if data is not None else 404)
        self.end_headers()
        self.wfile.write(data or b"")

    def do_PUT(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.blobs[self.path] = self.rfile.read(n)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def store():
    _Store.blobs = {"/docs/scope.md": b"In-scope: app.example"}
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Store)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _sh(cmd):
    from strobes_shell_agent import executor

    return asyncio.run(executor.execute_shell_command(cmd, timeout=120))


@pytest.mark.skipif(sys.platform == "win32" and not _ready(), reason="sandbox-setup not run")
def test_sandboxed_command_reads_writes_and_pushes_the_workspace(store, tmp_path):
    from strobes_shell_agent import workspace

    from strobes_shell_agent import executor

    probe = asyncio.run(executor.execute_code(
        "python", "import urllib.request,sys;print(sys.executable);"
                  f"print(urllib.request.urlopen({store + '/docs/scope.md'!r}, timeout=20).read())",
        timeout=120))
    print("lane python probe:", probe)
    r = workspace.workspace_pull([{"path": "docs/scope.md", "url": store + "/docs/scope.md"}])
    assert r["pulled"] == 1, (r["failed"], probe)
    root = str(workspace.workspace_root())

    out = _sh(f'type "{os.path.join(root, "docs", "scope.md")}"')
    assert "app.example" in (out.get("stdout") or ""), out

    out = _sh(f'echo found> "{os.path.join(root, "notes.txt")}"')
    assert out.get("success"), out
    assert "notes.txt" in [f["path"] for f in workspace.workspace_scan()["files"]]

    r = workspace.workspace_push([{"path": "notes.txt", "url": store + "/notes.txt"}])
    assert r["pushed"] == 1, r
    assert _Store.blobs["/notes.txt"].strip() == b"found"


@pytest.mark.skipif(sys.platform == "win32" and not _ready(), reason="sandbox-setup not run")
def test_a_planted_junction_is_not_followed(store, tmp_path):
    from strobes_shell_agent import workspace

    workspace.workspace_ensure()
    root = str(workspace.workspace_root())
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "key.txt").write_text("bridge-only")
    # A junction needs only write access to the workspace -- which the sandbox
    # account has -- so plant it exactly as a sandboxed command would.
    out = _sh(f'mklink /J "{os.path.join(root, "esc")}" "{secret}"')
    assert out.get("success"), out
    assert not [f for f in workspace.workspace_scan()["files"] if f["path"].startswith("esc")]
    r = workspace.workspace_push([{"path": "esc/key.txt", "url": store + "/esc"}])
    assert "/esc" not in _Store.blobs, r
    subprocess.run(["cmd", "/c", "rmdir", os.path.join(root, "esc")], check=False)
