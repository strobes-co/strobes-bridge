"""The packet-filter lane runs commands as a separate account; it must reach its
own home, the workspace and the pack.

Found live: on a root bridge with nftables, commands ran as ``strobes-scan`` with
the bridge's HOME (/root, 0700), so ``~/.strobes/workspace``, ``pip --user`` and
every pack tool (under /root/.strobes-shell-agent) failed with EACCES.
"""

import json
import os
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from strobes_shell_agent import l3lane, pack, sandbox, workspace

# The packet-filter lane, POSIX ownership and hard/sym links are Linux/macOS
# concerns; Windows confines commands through its own account filter.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only lane behaviour")


def test_lane_environment_uses_the_accounts_own_home():
    env = l3lane.environment({"HOME": "/root", "XDG_CACHE_HOME": "/root/.cache",
                              "PYTHONUSERBASE": "/root/.local", "PATH": "/bin"})
    assert env["HOME"] == l3lane.ACCOUNT_HOME
    assert env["USER"] == env["LOGNAME"] == l3lane.ACCOUNT
    assert "XDG_CACHE_HOME" not in env and "PYTHONUSERBASE" not in env
    assert env["PATH"] == "/bin"


@pytest.fixture
def lane_home(tmp_path, monkeypatch):
    """Commands' home = tmp_path; network stubbed; no account switch by default."""
    monkeypatch.setattr(sandbox, "command_home", lambda: str(tmp_path))
    monkeypatch.setattr(sandbox, "_command_uid", lambda: None)
    monkeypatch.setattr(workspace, "_download", lambda url, t: iter([b"body:" + url.encode()]))
    sent = []
    monkeypatch.setattr(workspace, "_upload", lambda url, data, ct, t: sent.append(data) or 200)
    return SimpleNamespace(home=tmp_path, sent=sent)


def test_workspace_lives_in_the_home_commands_see(lane_home):
    assert workspace.workspace_root() == (lane_home.home / ".strobes/workspace").resolve()
    out = workspace.workspace_ensure()
    assert out["success"] and Path(out["path"]).is_dir()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="fchown needs root")
def test_pulled_files_and_their_dirs_are_handed_to_the_command_account(lane_home, monkeypatch):
    monkeypatch.setattr(sandbox, "_command_uid", lambda: 4242)
    r = workspace.workspace_pull([{"path": "docs/scope.md", "url": "https://x/y"}])
    assert r["pulled"] == 1
    root = workspace.workspace_root()
    for p in (root, root / "docs", root / "docs/scope.md"):
        assert p.stat().st_uid == 4242, p


def test_hard_linked_files_are_never_scanned_or_pushed(lane_home):
    workspace.workspace_ensure()
    root = workspace.workspace_root()
    secret = lane_home.home / "secret"
    secret.write_text("bridge-only")
    os.link(secret, root / "planted")
    (root / "ok.txt").write_text("fine")
    paths = [f["path"] for f in workspace.workspace_scan()["files"]]
    assert paths == ["ok.txt"]
    r = workspace.workspace_push([{"path": "planted", "url": "https://x/y"}])
    assert r["pushed"] == 0 and lane_home.sent == []


# -- the account controls the workspace tree; the bridge must not be steered --

def test_a_planted_workspace_home_link_is_not_followed(lane_home):
    import uuid

    ws = str(uuid.uuid4())
    target = lane_home.home / "elsewhere"   # stands in for /etc
    target.mkdir()
    (lane_home.home / ".strobes/homes").mkdir(parents=True)
    (lane_home.home / ".strobes/homes" / ws).symlink_to(target, target_is_directory=True)
    out = workspace.workspace_ensure(ws)
    assert out["success"] is False
    assert list(target.iterdir()) == []  # nothing created through the link
    r = workspace.workspace_pull([{"path": "x.txt", "url": "https://x/y"}], workspace_id=ws)
    assert r["pulled"] == 0 and list(target.iterdir()) == []


def test_a_planted_link_at_the_target_name_is_replaced_not_written_through(lane_home):
    workspace.workspace_ensure()
    root = workspace.workspace_root()
    victim = lane_home.home / "victim"
    victim.write_text("untouched")
    (root / "scope.md").symlink_to(victim)
    r = workspace.workspace_pull([{"path": "scope.md", "url": "https://x/y"}])
    assert r["pulled"] == 1
    assert victim.read_text() == "untouched"
    assert not (root / "scope.md").is_symlink()
    assert (root / "scope.md").read_bytes() == b"body:https://x/y"


def test_push_through_a_symlinked_file_or_directory_is_refused(lane_home):
    workspace.workspace_ensure()
    root = workspace.workspace_root()
    outside = lane_home.home / "outside"
    outside.mkdir()
    (outside / "shadow").write_text("root-only")
    (root / "link.txt").symlink_to(outside / "shadow")
    (root / "dir").symlink_to(outside, target_is_directory=True)
    r = workspace.workspace_push([{"path": "link.txt", "url": "https://x/1"},
                                  {"path": "dir/shadow", "url": "https://x/2"}])
    assert r["pushed"] == 0 and lane_home.sent == []
    assert [f["path"] for f in workspace.workspace_scan()["files"]] == []


def _make_pack(root: Path, version: str) -> Path:
    p = root / pack.triple()
    (p / "bin").mkdir(parents=True)
    (p / "pack.manifest.json").write_text(json.dumps({"version": version}))
    tool = p / "bin/tool"
    tool.write_text("#!/bin/sh\necho hi\n")
    tool.chmod(0o700)
    return p


@pytest.fixture
def private_pack(tmp_path, monkeypatch):
    priv = tmp_path / "home"
    priv.mkdir(mode=0o700)
    src = _make_pack(priv / "cache", "v1")
    monkeypatch.setenv(pack.PACK_DIR_ENV, str(priv / "cache"))
    monkeypatch.delenv(pack.PACK_PATH_ENV, raising=False)
    monkeypatch.setattr(pack, "SHARED_ROOT", tmp_path / "opt/pack")
    monkeypatch.setitem(pack._shared, "uid", None)
    monkeypatch.setitem(pack._shared, "pin", None)
    pack._reset_caches()
    yield src
    pack._reset_caches()


def test_an_unreachable_pack_is_shared_and_pinned(private_pack, tmp_path):
    other_uid = os.getuid() + 4242  # an account that is not the pack's owner
    dst = pack.share_with(other_uid)
    assert dst == tmp_path / "opt/pack" / private_pack.name
    assert pack.find_pack() == dst
    assert os.environ[pack.PACK_PATH_ENV] == str(dst)
    mode = (dst / "bin/tool").stat().st_mode & 0o777
    assert mode & 0o005 == 0o005 and not mode & 0o022  # r-x for others, no write


def test_a_reachable_pack_is_left_alone(private_pack, tmp_path):
    # pytest's own base temp dir is 0700 too, so open every ancestor up to /tmp.
    for p in [private_pack, *private_pack.parents]:
        if p == Path("/tmp") or Path("/tmp") not in p.parents:
            break
        p.chmod(0o755)
    assert pack.share_with(os.getuid() + 4242) == private_pack


def test_an_update_refreshes_the_shared_copy(private_pack, tmp_path):
    uid = os.getuid() + 4242
    pack.share_with(uid)
    (private_pack / "pack.manifest.json").write_text(json.dumps({"version": "v2"}))
    pack.reshare()
    dst = tmp_path / "opt/pack" / private_pack.name
    assert json.loads((dst / "pack.manifest.json").read_text())["version"] == "v2"
    assert pack.find_pack() == dst


def test_command_home_is_the_bridges_own_outside_the_l3_lane(monkeypatch):
    monkeypatch.setattr(sandbox, "_command_uid", lambda: None)
    assert sandbox.command_home() == os.path.expanduser("~")
    monkeypatch.setattr(sandbox, "_command_uid", lambda: 999)
    assert sandbox.command_home() == l3lane.ACCOUNT_HOME


def test_a_pack_that_lands_after_the_lane_started_is_shared(tmp_path, monkeypatch):
    """Live order: lane up at connect, pack downloaded seconds later."""
    priv = tmp_path / "home"
    priv.mkdir(mode=0o700)
    monkeypatch.setenv(pack.PACK_DIR_ENV, str(priv / "cache"))
    monkeypatch.delenv(pack.PACK_PATH_ENV, raising=False)
    monkeypatch.setattr(pack, "SHARED_ROOT", tmp_path / "opt/pack")
    monkeypatch.setitem(pack._shared, "uid", None)
    monkeypatch.setitem(pack._shared, "pin", None)
    pack._reset_caches()
    uid = os.getuid() + 4242
    assert pack.share_with(uid) is None  # no pack yet
    src = _make_pack(priv / "cache", "v1")
    pack._reset_caches()
    pack.reshare()  # what ensure_pack / update_pack do once a pack lands
    assert pack.find_pack() == tmp_path / "opt/pack" / src.name
    pack._reset_caches()


def test_shared_pack_appends_the_accounts_user_site(private_pack, tmp_path):
    """User installs become importable without shadowing the pack's own."""
    sp = private_pack / "python/cpython-3.12/lib/python3.12/site-packages"
    sp.mkdir(parents=True)
    dst = pack.share_with(os.getuid() + 4242)
    pth = next(dst.glob("python/*/lib/python3*/site-packages/" + pack._USER_SITE_PTH))
    assert "addsitedir" in pth.read_text() and ".local" in pth.read_text()


def test_each_workspace_gets_its_own_home_on_a_shared_bridge(lane_home):
    import uuid

    (lane_home.home / ".ssh").mkdir()
    (lane_home.home / ".ssh/key").write_text("k")
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    workspace.workspace_pull([{"path": "docs/scope.md", "url": "https://A"}], workspace_id=a)
    workspace.workspace_pull([{"path": "docs/scope.md", "url": "https://B"}], workspace_id=b)
    home_a = lane_home.home / ".strobes/homes" / a
    assert (home_a / ".strobes/workspace/docs/scope.md").read_bytes() == b"body:https://A"
    assert [f["path"] for f in workspace.workspace_scan(workspace_id=b)["files"]] == ["docs/scope.md"]
    assert workspace.workspace_scan(workspace_id=b)["path"].endswith(b + "/.strobes/workspace")
    assert (home_a / ".ssh/key").read_text() == "k"  # real dotfiles linked in
    # No id: the shared directory, exactly as an older platform expects.
    assert workspace.workspace_root() == (lane_home.home / ".strobes/workspace").resolve()


def test_a_malformed_workspace_id_falls_back_to_the_shared_root(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "command_home", lambda: str(tmp_path))
    assert workspace.workspace_root("../../etc") == (tmp_path / ".strobes/workspace").resolve()
