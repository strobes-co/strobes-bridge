"""Tests for sandbox pack resolution + executor integration (no real pack needed)."""

import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from strobes_shell_agent import pack


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Isolate every test from ambient pack env + the lru_cache."""
    for var in (pack.PACK_PATH_ENV, pack.PACK_DIR_ENV, pack.PACK_URL_ENV, pack.PACK_DISABLE_ENV):
        monkeypatch.delenv(var, raising=False)
    pack.find_pack.cache_clear()
    pack._path_prefix.cache_clear()
    pack._extra_env.cache_clear()
    yield
    pack.find_pack.cache_clear()
    pack._path_prefix.cache_clear()
    pack._extra_env.cache_clear()


def _make_pack(root: Path, triple: str = None) -> Path:
    """Create a minimal but valid pack directory tree."""
    triple = triple or pack.triple()
    p = root / triple
    interp_dir = p / "python" / "cpython-3.12.13" / "bin"
    interp_dir.mkdir(parents=True)
    interp = interp_dir / "python3"
    interp.write_text("#!/bin/sh\necho fake\n")
    interp.chmod(0o755)
    (p / "bin").mkdir()
    (p / "bin" / "nuclei").write_text("x")
    (p / "pack.manifest.json").write_text(json.dumps({
        "schema": 1, "triple": triple, "python_version": "3.12",
        "interpreter": "python/cpython-3.12.13/bin/python3",
        "packages": ["boto3==1.0", "reportlab==4.0"],
        "tools": {"nuclei": {"version": "3.6.2", "sha256": "x", "binary": "nuclei"}},
    }))
    return p


def test_triple_format():
    t = pack.triple()
    assert "-" in t
    os_part, arch_part = t.split("-", 1)
    assert os_part in ("linux", "macos", "windows")
    assert arch_part in ("x86_64", "aarch64") or arch_part  # unknown arch passes through


def test_no_pack_is_graceful(monkeypatch):
    assert pack.find_pack() is None
    assert pack.python_interpreter() == "python3"
    assert pack.build_env()["PATH"] == os.environ["PATH"]
    assert pack.status() == {"present": False, "triple": pack.triple()}


def test_explicit_pack_path(tmp_path, monkeypatch):
    p = _make_pack(tmp_path)
    monkeypatch.setenv(pack.PACK_PATH_ENV, str(p))
    pack.find_pack.cache_clear()
    pack._path_prefix.cache_clear()

    assert pack.find_pack() == p.resolve()
    assert pack.python_interpreter() == str(p / "python/cpython-3.12.13/bin/python3")

    env_path = pack.build_env()["PATH"]
    assert env_path.startswith(str(p / "bin"))
    assert str(p / "python/cpython-3.12.13/bin") in env_path

    st = pack.status()
    assert st["present"] is True
    assert st["packages"] == 2
    assert st["tools"] == ["nuclei"]


def test_pack_dir_root(tmp_path, monkeypatch):
    _make_pack(tmp_path)
    monkeypatch.setenv(pack.PACK_DIR_ENV, str(tmp_path))
    pack.find_pack.cache_clear()
    assert pack.find_pack() is not None


def test_disable_overrides_everything(tmp_path, monkeypatch):
    p = _make_pack(tmp_path)
    monkeypatch.setenv(pack.PACK_PATH_ENV, str(p))
    monkeypatch.setenv(pack.PACK_DISABLE_ENV, "1")
    pack.find_pack.cache_clear()
    assert pack.find_pack() is None
    assert pack.python_interpreter() == "python3"


def test_invalid_pack_path_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv(pack.PACK_PATH_ENV, str(tmp_path / "nope"))
    pack.find_pack.cache_clear()
    assert pack.find_pack() is None


def test_safe_extract_rejects_traversal(tmp_path):
    """_safe_extract must refuse archives that escape the destination."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        with pytest.raises(RuntimeError, match="unsafe path"):
            pack._safe_extract(tar, tmp_path)
    assert not (tmp_path.parent / "escape.txt").exists()


def test_ensure_pack_noop_without_url(monkeypatch):
    """No pack + no URL -> returns None, never raises."""
    assert pack.ensure_pack(download=True) is None


def test_bundle_env_applied(tmp_path, monkeypatch):
    """Bundle tools declare runtime env (e.g. NMAPDIR); build_env resolves it absolute."""
    p = _make_pack(tmp_path)
    (p / "share" / "nmap" / "data").mkdir(parents=True)
    m = json.loads((p / "pack.manifest.json").read_text())
    m["env"] = {"NMAPDIR": "share/nmap/data"}
    (p / "pack.manifest.json").write_text(json.dumps(m))
    monkeypatch.setenv(pack.PACK_PATH_ENV, str(p))
    pack.find_pack.cache_clear()
    pack._extra_env.cache_clear()

    env = pack.build_env()
    assert env["NMAPDIR"] == str((p / "share" / "nmap" / "data").resolve())
