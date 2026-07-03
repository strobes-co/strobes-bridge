"""Sandbox pack integration for the shell bridge.

A "sandbox pack" is a self-contained, relocatable directory that reproduces the Strobes
cloud sandbox runtime on the bridge host: a standalone Python interpreter with all agent
packages (boto3, reportlab, curl_cffi, cryptography, …) baked in, plus CLI security tools
(nuclei, httpx, ffuf, …) in ``bin/``. It runs with NO Docker, NO root, NO system Python
and NO internet at runtime. Build tooling lives in ``sandbox_pack/`` (see its README).

This module lets the daemon *use* a pack: it locates one (env override, then the default
install dir), optionally downloads + verifies + extracts one, and produces the PATH /
interpreter overrides the executor injects into every command it runs. If no pack is
present, everything degrades gracefully to the host's own tools (the pre-pack behaviour).

Resolution order:
  1. ``STROBES_PACK_PATH``  — absolute path to an extracted pack (air-gapped / bundled).
  2. ``<root>/<triple>``    — default install dir; root is ``STROBES_PACK_DIR`` or
                              ``~/.strobes-shell-agent/pack``. ``<triple>`` is e.g.
                              ``linux-x86_64`` / ``macos-aarch64`` / ``windows-x86_64``.
  3. download from ``STROBES_PACK_URL`` (if set and ``ensure_pack`` is called).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

PACK_PATH_ENV = "STROBES_PACK_PATH"   # explicit extracted-pack dir
PACK_DIR_ENV = "STROBES_PACK_DIR"     # root that holds <triple>/ subdirs
PACK_URL_ENV = "STROBES_PACK_URL"     # base URL to fetch packs from
PACK_DISABLE_ENV = "STROBES_PACK_DISABLE"  # set truthy to ignore any pack

DEFAULT_ROOT = Path.home() / ".strobes-shell-agent" / "pack"


def _truthy(v: Optional[str]) -> bool:
    return bool(v) and v.lower() not in ("0", "false", "no", "off", "")


def triple() -> str:
    """Platform triple used for pack naming, e.g. ``linux-x86_64``."""
    s = platform.system().lower()
    os_name = ("macos" if s.startswith("darwin")
               else "linux" if s.startswith("linux")
               else "windows" if s.startswith("windows") else s)
    m = platform.machine().lower()
    arch = ("x86_64" if m in ("x86_64", "amd64")
            else "aarch64" if m in ("aarch64", "arm64") else m)
    return f"{os_name}-{arch}"


def _is_pack(path: Path) -> bool:
    return (path / "pack.manifest.json").is_file()


def _packs_in(root: Path, t: str):
    """Yield pack dirs under ``root`` for triple ``t``: the dir itself, the exact triple,
    and any profiled variant (e.g. ``internal-ad-linux-x86_64``)."""
    yield root                 # root itself is a pack (manifest directly inside)
    yield root / t             # base pack, e.g. linux-x86_64
    try:
        for d in sorted(root.glob(f"*-{t}")):   # profiled, e.g. internal-ad-linux-x86_64
            yield d
    except OSError:
        pass


def _candidate_dirs():
    """Yield candidate pack dirs in priority order (base or profiled)."""
    t = triple()
    explicit = os.environ.get(PACK_PATH_ENV)
    if explicit:
        yield Path(explicit).expanduser()
    roots = []
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        roots.append(Path(sys._MEIPASS) / "pack")          # PyInstaller-embedded
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent / "pack")  # next-to-exe
    roots.append(Path(os.environ.get(PACK_DIR_ENV, DEFAULT_ROOT)).expanduser())  # cache
    for root in roots:
        yield from _packs_in(root, t)


@lru_cache(maxsize=1)
def find_pack() -> Optional[Path]:
    """Return the pack dir if one is present, else None. Resolution: explicit env path →
    PyInstaller-embedded → next-to-executable → default install/cache dir. Cached."""
    if _truthy(os.environ.get(PACK_DISABLE_ENV)):
        return None
    for cand in _candidate_dirs():
        if _is_pack(cand):
            return cand.resolve()
    return None


def _manifest(pack: Path) -> dict:
    try:
        return json.loads((pack / "pack.manifest.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def pack_python(pack: Optional[Path] = None) -> Optional[Path]:
    """Absolute path to the pack's standalone interpreter, or None."""
    pack = pack or find_pack()
    if not pack:
        return None
    rel = _manifest(pack).get("interpreter")
    if not rel:
        return None
    py = pack / rel
    return py if py.exists() else None


def pack_bin(pack: Optional[Path] = None) -> Optional[Path]:
    """Absolute path to the pack's CLI tools dir (``bin/``), or None."""
    pack = pack or find_pack()
    if not pack:
        return None
    b = pack / "bin"
    return b if b.is_dir() else None


@lru_cache(maxsize=1)
def _path_prefix() -> str:
    """PATH entries the pack contributes, highest priority first: CLI tools, then the
    interpreter's bin dir (so ``python3``/``pip`` resolve to the pack)."""
    parts = []
    b = pack_bin()
    if b:
        parts.append(str(b))
    pack = find_pack()
    if pack:
        # extra dirs from 'path'-exposed bundles (e.g. Windows nmap dir with its DLLs)
        for rel in (_manifest(pack).get("bin_dirs") or []):
            parts.append(str((pack / rel).resolve()))
    py = pack_python()
    if py:
        parts.append(str(py.parent))          # POSIX: .../bin ; Windows: interpreter root
        scripts = py.parent / "Scripts"       # Windows: pip console scripts land here
        if scripts.is_dir():
            parts.append(str(scripts))
    return os.pathsep.join(parts)


@lru_cache(maxsize=1)
def _extra_env() -> dict:
    """Runtime env vars declared by bundle tools (e.g. NMAPDIR), resolved to absolute
    paths inside the pack. Empty if no pack."""
    pack = find_pack()
    if not pack:
        return {}
    out = {}
    for var, rel in (_manifest(pack).get("env") or {}).items():
        out[var] = str((pack / rel).resolve())
    return out


@lru_cache(maxsize=1)
def _nuclei_config() -> Optional[str]:
    """Materialize a writable nuclei config dir whose .templates-config.json points at
    the pack's bundled templates, so `nuclei` finds them by default and runs offline.
    Never writes into the (possibly read-only) pack — uses a per-user cache dir. Returns
    the config dir path, or None if the pack ships no templates."""
    pack = find_pack()
    if not pack:
        return None
    m = _manifest(pack).get("nuclei")
    if not m:
        return None
    tpl = (pack / m["templates"]).resolve()
    if not tpl.is_dir():
        return None
    base = Path(os.environ.get(PACK_DIR_ENV, DEFAULT_ROOT)).expanduser()
    cfg = base / "nuclei-config"
    try:
        cfg.mkdir(parents=True, exist_ok=True)
        src = pack / m["config"]
        if src.is_dir():
            for f in src.iterdir():
                dst = cfg / f.name
                if f.is_file() and f.name != ".templates-config.json" and not dst.exists():
                    shutil.copy2(f, dst)
        (cfg / ".templates-config.json").write_text(
            json.dumps({"nuclei-templates-directory": str(tpl)}))
        return str(cfg)
    except OSError as e:
        log.warning("could not set up nuclei config: %s", e)
        return None


def build_env(base: Optional[dict] = None) -> dict:
    """Return an environment dict with the pack prepended to PATH and any bundle-tool
    env vars (e.g. NMAPDIR, NUCLEI_CONFIG_DIR) applied. If no pack is present, returns a
    copy of ``base`` unchanged. Safe to call on every command."""
    env = dict(os.environ if base is None else base)
    prefix = _path_prefix()
    if prefix:
        env["PATH"] = prefix + os.pathsep + env.get("PATH", "")
    env.update(_extra_env())   # pack-shipped tools' data dirs win (agent expects them)
    nc = _nuclei_config()
    if nc:
        env["NUCLEI_CONFIG_DIR"] = nc   # bundled nuclei-templates, offline by default
    return env


def python_interpreter() -> str:
    """Interpreter to use for ``execute_code`` python: the pack's if present, else the
    host's ``python3`` (pre-pack behaviour)."""
    py = pack_python()
    return str(py) if py else "python3"


def status() -> dict:
    """Human/diagnostic summary for get_env_info and prechecks."""
    pack = find_pack()
    if not pack:
        return {"present": False, "triple": triple()}
    m = _manifest(pack)
    return {
        "present": True,
        "path": str(pack),
        "triple": m.get("triple", triple()),
        "profile": m.get("profile", "base"),
        "python_version": m.get("python_version"),
        "packages": len(m.get("packages", [])),
        "tools": sorted((m.get("tools") or {}).keys()),
    }


# --------------------------------------------------------------------------- #
# provisioning (optional; only used when STROBES_PACK_URL is configured)
# --------------------------------------------------------------------------- #
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _reset_caches() -> None:
    find_pack.cache_clear()
    _path_prefix.cache_clear()
    _extra_env.cache_clear()
    _nuclei_config.cache_clear()


def _bundled_tarball() -> Optional[Path]:
    """Path to a pack tarball shipped INSIDE the artifact (embedded in the PyInstaller
    binary, or next to the executable) for the current triple — base or profiled (e.g.
    strobes-sandbox-pack-internal-ad-<triple>.tar.gz). None if absent."""
    t = triple()
    roots = []
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        roots.append(Path(sys._MEIPASS))
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    for r in roots:
        try:
            hits = sorted(r.glob(f"strobes-sandbox-pack-*{t}.tar.gz"))
        except OSError:
            hits = []
        if hits:
            return hits[0]
    return None


def ensure_pack(download: bool = True, timeout: int = 300) -> Optional[Path]:
    """Make a pack available and return its path (or None). Order, DEFAULT IS OFFLINE:
      1. already present (baked/co-located/cached) → use it, no network;
      2. a pack tarball bundled inside the artifact → self-extract locally, no network;
      3. ONLY if ``STROBES_PACK_URL`` is explicitly set → download + verify + extract.
    Never raises — any failure just leaves the daemon on host tools.
    """
    existing = find_pack()
    if existing:
        return existing

    # 2. offline self-extract from a pack tarball embedded in the binary
    bundled = _bundled_tarball()
    if bundled:
        root = Path(os.environ.get(PACK_DIR_ENV, DEFAULT_ROOT)).expanduser()
        try:
            root.mkdir(parents=True, exist_ok=True)
            log.info("extracting bundled sandbox pack (offline): %s", bundled.name)
            with tarfile.open(bundled) as tar:
                _safe_extract(tar, root)
            _reset_caches()
            found = find_pack()
            if found:
                return found
        except Exception as e:  # noqa: BLE001
            log.error("bundled pack extraction failed: %s", e)

    # 3. explicit opt-in network download (never the default — requires STROBES_PACK_URL)
    if not download:
        return None
    base_url = os.environ.get(PACK_URL_ENV)
    if not base_url:
        return None

    t = triple()
    fname = f"strobes-sandbox-pack-{t}.tar.gz"
    url = base_url.rstrip("/") + "/" + fname
    root = Path(os.environ.get(PACK_DIR_ENV, DEFAULT_ROOT)).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    try:
        log.info("downloading sandbox pack: %s", url)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / fname
            urllib.request.urlretrieve(url, tmp)  # noqa: S310 (operator-configured URL)
            expected = _fetch_expected_sha(url)
            if expected:
                got = _sha256(tmp)
                if got != expected:
                    log.error("pack sha256 mismatch (want %s got %s) — refusing", expected, got)
                    return None
                log.info("pack sha256 verified")
            else:
                log.warning("no .sha256 alongside pack; skipping integrity check")
            with tarfile.open(tmp) as tar:
                _safe_extract(tar, root)
    except Exception as e:  # noqa: BLE001 — provisioning must never crash the daemon
        log.error("sandbox pack download failed: %s", e)
        return None

    _reset_caches()
    return find_pack()


def _fetch_expected_sha(url: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(url + ".sha256", timeout=30) as r:  # noqa: S310
            return r.read().decode().split()[0].strip()
    except Exception:  # noqa: BLE001
        return None


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract guarding against path traversal (CVE-2007-4559 style)."""
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest) + os.sep) and target != dest:
            raise RuntimeError(f"unsafe path in archive: {member.name}")
    # Python 3.12+ supports a data filter; fall back for older runtimes.
    if sys.version_info >= (3, 12):
        tar.extractall(dest, filter="data")
    else:
        tar.extractall(dest)  # noqa: S202 (validated above)
