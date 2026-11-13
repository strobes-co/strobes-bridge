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
    # The workspace lives in the home COMMANDS see, which on a root host with
    # nftables is the scan account's, not the bridge's. Pin it so these tests
    # do not depend on the privileges of whoever runs them.
    from strobes_shell_agent import sandbox

    monkeypatch.setattr(sandbox, "command_home", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture
def net(monkeypatch):
    """A fake presigned transport for both code paths: the descriptor-based one
    (workspace._download/_upload) and the path-based one (executor.file_*).
    A URL containing "bad" fails; a GET returns b"body:" + url."""
    sent = []

    def download(url, timeout):
        if "bad" in url:
            raise OSError("boom")
        yield b"body:" + url.encode()

    def upload(url, data, ct, timeout):
        sent.append(data)
        return 200

    def file_pull(path, url, sha, timeout):
        if "bad" in url:
            return {"success": False, "error": "boom"}
        Path(path).write_bytes(b"body:" + url.encode())
        return {"success": True}

    def file_push(path, url, ct, timeout):
        sent.append(Path(path).read_bytes())
        return {"success": True}

    monkeypatch.setattr(workspace, "_download", download)
    monkeypatch.setattr(workspace, "_upload", upload)
    monkeypatch.setattr("strobes_shell_agent.executor.file_pull", file_pull)
    monkeypatch.setattr("strobes_shell_agent.executor.file_push", file_push)
    return sent


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

    def test_refetches_when_the_checksum_differs(self, net):
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "a.txt", b"stale")
        r = workspace.workspace_pull([{"path": "a.txt", "url": "https://x/y"}])
        assert r["pulled"] == 1 and r["skipped"] == 0
        assert (workspace.workspace_root() / "a.txt").read_bytes() == b"body:https://x/y"

    def test_one_bad_url_does_not_cost_the_others(self, net):
        """The agent may only need the file that worked."""
        workspace.workspace_ensure()
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

    def test_creates_intermediate_directories(self, net):
        workspace.workspace_ensure()
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
    def test_only_pushes_what_the_backend_named(self, net):
        """The machine never decides what leaves it."""
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "wanted.txt", b"wanted")
        _write(workspace.workspace_root(), "private.txt", b"private")
        r = workspace.workspace_push([{"path": "wanted.txt", "url": "https://x/y"}])
        assert r["pushed"] == 1 and net == [b"wanted"]

    def test_refuses_to_push_outside_the_workspace(self, monkeypatch):
        monkeypatch.setattr(
            "strobes_shell_agent.executor.file_push",
            lambda *a, **k: pytest.fail("attempted to push an escaping path"),
        )
        r = workspace.workspace_push([{"path": "../../.ssh/id_rsa", "url": "https://x/y"}])
        assert r["pushed"] == 0 and r["success"] is False

    def test_missing_file_is_reported_not_raised(self, net):
        workspace.workspace_ensure()
        r = workspace.workspace_push([{"path": "nope.txt", "url": "https://x/y"}])
        assert r["failed"][0]["error"] == "not a file on this machine"


def _wait_done(job_id, limit=10.0):
    import time

    deadline = time.time() + limit
    while time.time() < deadline:
        st = workspace.workspace_push_status(job_id)
        if st["done"]:
            return st
        time.sleep(0.02)
    pytest.fail("background push never finished")


class TestBackgroundPush:
    def test_returns_before_uploading_and_pushes_everything(self, net, monkeypatch):
        """The reply must not wait for the uploads -- that wait is what made
        every command behind a big write take 20-30s."""
        import threading

        gate = threading.Event()
        real = workspace._upload

        def slow(url, data, ct, timeout):
            gate.wait(5)
            return real(url, data, ct, timeout)

        monkeypatch.setattr(workspace, "_upload", slow)
        workspace.workspace_ensure()
        files = []
        for i in range(30):
            _write(workspace.workspace_root(), f"out/f{i}.txt", f"data{i}".encode())
            files.append({"path": f"out/f{i}.txt", "url": f"https://x/{i}"})

        r = workspace.workspace_push_start(files)
        assert r["success"] and r["queued"] == 30
        assert workspace.workspace_push_status(r["job_id"])["done"] is False
        gate.set()
        st = _wait_done(r["job_id"])
        assert st["pushed"] == 30 and st["failed"] == []
        assert sorted(net) == sorted(f"data{i}".encode() for i in range(30))

    def test_a_file_already_on_its_way_is_not_uploaded_twice(self, net, monkeypatch):
        import threading

        gate = threading.Event()
        real = workspace._upload
        monkeypatch.setattr(workspace, "_upload",
                            lambda *a: (gate.wait(5), real(*a))[1])
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "a.txt", b"A")
        entry = {"path": "a.txt", "url": "https://x/a"}

        first = workspace.workspace_push_start([entry])
        second = workspace.workspace_push_start([entry])
        assert first["queued"] == 1
        assert second["queued"] == 0 and second["skipped"] == 1
        assert workspace.workspace_push_status(second["job_id"])["done"] is True
        gate.set()
        _wait_done(first["job_id"])
        assert net == [b"A"]
        # Once it has landed the path is free again.
        third = workspace.workspace_push_start([entry])
        assert third["queued"] == 1
        _wait_done(third["job_id"])

    def test_failures_are_reported_per_file(self, net):
        workspace.workspace_ensure()
        _write(workspace.workspace_root(), "ok.txt", b"ok")
        r = workspace.workspace_push_start([
            {"path": "ok.txt", "url": "https://x/ok"},
            {"path": "missing.txt", "url": "https://x/m"},
            {"path": "../../.ssh/id_rsa", "url": "https://x/e"},
        ])
        st = _wait_done(r["job_id"])
        assert st["pushed"] == 1
        assert sorted(f["path"] for f in st["failed"]) == ["../../.ssh/id_rsa", "missing.txt"]

    def test_uploads_run_in_parallel(self, net, monkeypatch):
        import threading
        import time

        active, peak, lock = [0], [0], threading.Lock()
        real = workspace._upload

        def track(*a):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return real(*a)

        monkeypatch.setattr(workspace, "_upload", track)
        workspace.workspace_ensure()
        files = []
        for i in range(24):
            _write(workspace.workspace_root(), f"p{i}", b"x")
            files.append({"path": f"p{i}", "url": f"https://x/{i}"})
        _wait_done(workspace.workspace_push_start(files)["job_id"])
        assert peak[0] > 1

    def test_unknown_job(self):
        st = workspace.workspace_push_status("nope")
        assert st["success"] is False and st["done"] is True
