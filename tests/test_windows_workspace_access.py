"""On a provisioned Windows bridge, can the AGENT use the workspace?

Commands run as the sandbox account, which only gets access to a per-command
work dir. The workspace lives in the bridge user's profile, so this checks the
real thing end to end: files the bridge pulled are readable by a sandboxed
command, and a file the command writes there is picked up by the scan the
platform uses to push outputs back. Runs only where `sandbox-setup` has been
done (the CI egress job); skipped everywhere else.
"""

import asyncio
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows sandbox account")


def _ready():
    from strobes_shell_agent import procsandbox
    return procsandbox.detect_backend() == procsandbox.WINDOWS


@pytest.mark.skipif(sys.platform == "win32" and not _ready(), reason="sandbox-setup not run")
def test_sandboxed_command_reads_and_writes_the_workspace(monkeypatch):
    from strobes_shell_agent import executor, workspace

    monkeypatch.setattr(workspace, "_download", lambda url, t: iter([b"In-scope: app.example"]))

    def fake_pull(path, url, sha, timeout):
        open(path, "wb").write(b"In-scope: app.example")
        return {"success": True}

    monkeypatch.setattr(executor, "file_pull", fake_pull)
    r = workspace.workspace_pull([{"path": "docs/scope.md", "url": "https://x/y"}])
    assert r["pulled"] == 1, r
    root = str(workspace.workspace_root())

    out = asyncio.run(executor.execute_shell_command(
        f'type "{os.path.join(root, "docs", "scope.md")}"', timeout=120))
    assert "app.example" in (out.get("stdout") or ""), out

    out = asyncio.run(executor.execute_shell_command(
        f'echo found> "{os.path.join(root, "notes.txt")}"', timeout=120))
    assert out.get("success"), out
    assert "notes.txt" in [f["path"] for f in workspace.workspace_scan()["files"]]
