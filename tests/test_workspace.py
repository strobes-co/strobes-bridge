"""The bridge's stand-in for a workspace mount.

The property under test throughout is that a bridge host presents the SAME
``~/.strobes/workspace`` an S3 Files mount gives a cloud sandbox, without
having a mount -- and, critically, without the absence of a mount costing the
isolation the mount provides for free. On a sandbox the access point's root
directory makes escaping the workspace impossible; here that has to be code,
so it is what most of these tests are about.
"""

import hashlib
import os
from pathlib import Path

import pytest

from strobes_shell_agent import workspace


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """A throwaway HOME, so tests never touch the real ~/.strobes."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def _write(root: Path, rel: str, data: bytes = b"x") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


class TestWorkspaceEnsure:
    def test_creates_the_path_the_agent_expects(self, _home):
        r = workspace.workspace_ensure()
        assert r["success"]
        assert (_home / ".strobes" / "workspace").is_dir()

    def test_is_idempotent(self, _home):
        workspace.workspace_ensure()
        assert workspace.workspace_ensure()["success"]


class TestPathContainment:
    """The boundary an access point would otherwise enforce.

    A manifest entry arrives over the network. ``../../.ssh/authorized_keys``
    is a well-formed relative path, and joining it naively writes outside the
    workspace onto somebody's laptop.
    """

    @pytest.mark.parametrize("evil", [
        "../escaped.txt",
        "../../escaped.txt",
        "a/../../escaped.txt",
        "/etc/passwd",
        "/tmp/escaped.txt",
        "",
        ".",
    ])
    def test_escapes_are_refused(self, evil):
        workspace.workspace_ensure()
        assert workspace._safe_target(evil) is None

    @pytest.mark.parametrize("ok", ["a.txt", "notes/b.txt", "deep/a/b/c.bin"])
    def test_ordinary_paths_resolve_inside(self, ok):
        workspace.workspace_ensure()
        target = workspace._safe_target(ok)
        assert target is not None
        assert str(target).startswith(str(workspace.workspace_root()))

    def test_a_symlinked_parent_cannot_be_used_to_escape(self, _home, tmp_path):
        """Containment is checked after resolution, not on the raw string.

        Inspecting the path text would pass this: there is no ``..`` in
        ``out/secret.txt``. Only resolving it reveals that ``out`` leaves the
        workspace entirely.
        """
        workspace.workspace_ensure()
        outside = tmp_path / "outside"
        outside.mkdir()
        (workspace.workspace_root() / "out").symlink_to(outside, target_is_directory=True)
        assert workspace._safe_target("out/secret.txt") is None


class TestPull:
    def test_skips_files_whose_checksum_already_matches(self, monkeypatch):
        """A bridge reconnects whenever the machine sleeps.

        Re-downloading an unchanged capture on every reconnect would make this
        worse than the tools it replaces, so an already-correct file must not
        be fetched again.
        """
        workspace.workspace_ensure()
        data = b"already here"
        _write(workspace.workspace_root(), "big.pcap", data)
        digest = hashlib.sha256(data).hexdigest()

        calls = []
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_pull",
            lambda *a, **k: calls.append(a) or {"success": True},
        )
        r = workspace.workspace_pull(
            [{"path": "big.pcap", "url": "https://x/y", "sha256": digest}]
        )
        assert r["skipped"] == 1 and r["pulled"] == 0
        assert calls == [], "an unchanged file was re-downloaded"

    def test_refetches_when_the_checksum_differs(self, monkeypatch):
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "a.txt", b"stale")
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_pull",
            lambda *a, **k: {"success": True},
        )
        r = workspace.workspace_pull(
            [{"path": "a.txt", "url": "https://x/y", "sha256": "0" * 64}]
        )
        assert r["pulled"] == 1 and r["skipped"] == 0

    def test_one_bad_url_does_not_cost_the_others(self, monkeypatch):
        """The agent may only need the file that worked."""
        workspace.workspace_ensure()

        def fake(path, url, sha, timeout):
            return {"success": "good" in url, "error": "boom"}

        monkeypatch.setattr("strobes_shell_agent.executor.file_pull", fake)
        r = workspace.workspace_pull([
            {"path": "ok.txt", "url": "https://good/1"},
            {"path": "bad.txt", "url": "https://bad/2"},
        ])
        assert r["pulled"] == 1
        assert [f["path"] for f in r["failed"]] == ["bad.txt"]
        assert r["success"] is False

    def test_a_traversal_entry_is_rejected_not_written(self, monkeypatch, _home):
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_pull",
            lambda *a, **k: pytest.fail("attempted to fetch an escaping path"),
        )
        r = workspace.workspace_pull(
            [{"path": "../../pwned.txt", "url": "https://x/y"}]
        )
        assert r["pulled"] == 0 and len(r["failed"]) == 1
        assert not (_home / "pwned.txt").exists()

    def test_creates_intermediate_directories(self, monkeypatch):
        workspace.workspace_ensure()
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_pull",
            lambda *a, **k: {"success": True},
        )
        workspace.workspace_pull([{"path": "reports/2026/a.pdf", "url": "https://x/y"}])
        assert (workspace.workspace_root() / "reports" / "2026").is_dir()


class TestScan:
    def test_reports_relative_paths_with_forward_slashes(self):
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "notes/a.txt", b"hello")
        files = workspace.workspace_scan()["files"]
        assert [f["path"] for f in files] == ["notes/a.txt"]
        assert files[0]["size"] == 5
        assert files[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()

    def test_symlinks_are_not_reported(self, tmp_path):
        """Following one would upload whatever it points at -- an
        arbitrary-file-read dressed up as a workspace sync."""
        workspace.workspace_ensure()
        secret = tmp_path / "id_rsa"
        secret.write_bytes(b"PRIVATE KEY")
        (workspace.workspace_root() / "link").symlink_to(secret)
        assert workspace.workspace_scan()["files"] == []

    def test_missing_workspace_is_empty_not_an_error(self):
        r = workspace.workspace_scan()
        assert r["success"] and r["files"] == []

    def test_sha256_can_be_skipped(self):
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "a.bin", b"z" * 100)
        f = workspace.workspace_scan(include_sha256=False)["files"][0]
        assert "sha256" not in f and f["size"] == 100


class TestPush:
    def test_only_pushes_what_the_backend_named(self, monkeypatch):
        """The machine never decides what leaves it."""
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "wanted.txt")
        _write(workspace.workspace_root(), "private.txt")
        pushed = []
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_push",
            lambda path, url, ct, to: pushed.append(Path(path).name) or {"success": True},
        )
        r = workspace.workspace_push([{"path": "wanted.txt", "url": "https://x/y"}])
        assert r["pushed"] == 1 and pushed == ["wanted.txt"]

    def test_refuses_to_push_outside_the_workspace(self, monkeypatch):
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_push",
            lambda *a, **k: pytest.fail("attempted to push an escaping path"),
        )
        r = workspace.workspace_push([{"path": "../../.ssh/id_rsa", "url": "https://x/y"}])
        assert r["pushed"] == 0 and r["success"] is False

    def test_missing_file_is_reported_not_raised(self, monkeypatch):
        workspace.workspace_ensure()
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_push", lambda *a, **k: {"success": True}
        )
        r = workspace.workspace_push([{"path": "nope.txt", "url": "https://x/y"}])
        assert r["failed"][0]["error"] == "not a file on this machine"
