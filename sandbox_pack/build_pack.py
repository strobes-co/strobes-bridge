#!/usr/bin/env python3
"""
build_pack.py — build a self-contained, relocatable Strobes "sandbox pack".

A pack reproduces the Strobes cloud sandbox's Python runtime (interpreter + all
packages) plus the CLI security tools, as a single directory that runs with NO Docker,
NO root, NO system Python and NO internet at runtime. It is the artifact the bridge
unpacks and points PATH / interpreter at (see strobes_shell_agent/pack.py).

Engine: uv + python-build-standalone. Packages install directly into the standalone
interpreter (the py-app-standalone approach), which is relocatable by construction —
the interpreter resolves its home relative to its own executable, so the whole tree
can be extracted anywhere.

Run natively on each target OS/arch (CI matrix). For broad Linux compatibility, run
the Linux build INSIDE a manylinux2014 container (glibc 2.17) so the interpreter and
wheels target the oldest baseline — see build_linux_manylinux.sh.

    python3 build_pack.py --out ./out --python-version 3.12 --tar

Outputs:
    <out>/<triple>/                                       the pack
    <out>/strobes-sandbox-pack-<triple>.tar.gz            (with --tar)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- #
# platform helpers
# --------------------------------------------------------------------------- #
def detect_os() -> str:
    s = platform.system().lower()
    if s.startswith("darwin"):
        return "macos"
    if s.startswith("linux"):
        return "linux"
    if s.startswith("windows"):
        return "windows"
    raise SystemExit(f"unsupported OS: {platform.system()}")


def detect_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    raise SystemExit(f"unsupported arch: {platform.machine()}")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(str(c) for c in cmd)}", flush=True)
    return subprocess.run(cmd, check=True, **kw)


# --------------------------------------------------------------------------- #
# steps
# --------------------------------------------------------------------------- #
def find_uv(explicit: str | None) -> str:
    if explicit:
        return explicit
    for cand in (shutil.which("uv"), str(Path.home() / ".local/bin/uv")):
        if cand and Path(cand).exists():
            return cand
    raise SystemExit("uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh")


def install_python(uv: str, pack: Path, version: str) -> Path:
    """Install a relocatable python-build-standalone interpreter into <pack>/python."""
    pydir = pack / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "UV_PYTHON_INSTALL_DIR": str(pydir)}
    run([uv, "python", "install", "--install-dir", str(pydir), version], env=env)
    # uv leaves bookkeeping + an ABSOLUTE alias symlink (cpython-3.12-... -> full path).
    # Both break relocatability, so strip them: the real versioned dir that remains is
    # self-locating (python-build-standalone resolves its prefix from the executable).
    for junk in (".lock", ".temp", ".gitignore"):
        p = pydir / junk
        shutil.rmtree(p) if p.is_dir() else (p.unlink() if p.exists() else None)
    for child in list(pydir.iterdir()):
        # absolute alias -> remove the link only, not its target. On Windows uv may
        # create a directory *junction* instead of a symlink; strip that too.
        is_link = child.is_symlink() or (hasattr(os.path, "isjunction")
                                         and os.path.isjunction(child))
        if is_link:
            try:
                child.unlink()
            except (OSError, PermissionError):
                try:
                    child.rmdir()  # junctions unlink as dirs on some Windows builds
                except OSError:
                    pass
    # locate the interpreter; prefer real (non-reparse) dirs. On POSIX bin/python3 may
    # be a RELATIVE symlink -> python3.12 (fine); on Windows it's <dir>/python.exe.
    for pat in ("*/bin/python3", "*/bin/python", "*/python.exe"):
        hits = [p for p in sorted(pydir.glob(pat)) if not _under_reparse(p, pydir)]
        if hits:
            return hits[0]
    raise SystemExit(f"could not locate interpreter under {pydir}")


def _under_reparse(path: Path, root: Path) -> bool:
    """True if any directory between root and path is a symlink/junction (i.e. the
    interpreter would resolve back to an absolute alias, breaking relocatability)."""
    cur = path.parent
    while cur != root and cur != cur.parent:
        if cur.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(cur)):
            return True
        cur = cur.parent
    return False


def install_packages(uv: str, pybin: Path, req_in: Path, pack: Path, triple: str) -> Path:
    """Compile a pinned+hashed lock, then install into the standalone interpreter."""
    lock = pack / f"sandbox-requirements.{triple}.lock"
    run([uv, "pip", "compile", "--python", str(pybin), "--generate-hashes",
         "-o", str(lock), str(req_in)])
    # Install straight into the standalone interpreter's own site-packages (the
    # py-app-standalone approach) so the tree stays relocatable — no venv indirection
    # whose pyvenv.cfg would hard-code an absolute base path. uv marks the managed
    # interpreter "externally managed"; --break-system-packages opts in.
    run([uv, "pip", "install", "--python", str(pybin),
         "--break-system-packages", "-r", str(lock)])
    return lock


def relocate_fixup(pack: Path, pybin: Path) -> None:
    """Rewrite absolute shebangs in installed console scripts to a relative re-exec so
    entry-point scripts survive the pack being moved. Interpreter imports do not depend
    on this (python-build-standalone is self-locating); this only helps console_scripts."""
    bindir = pybin.parent
    if not bindir.exists():
        return
    py_rel = os.path.relpath(pybin, bindir)  # e.g. "python3"
    fixed = 0
    for entry in bindir.iterdir():
        if not entry.is_file() or entry.suffix in (".so", ".dylib"):
            continue
        try:
            if entry.read_bytes()[:2] != b"#!":
                continue
            text = entry.read_text(errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        lines = text.splitlines()
        if not lines or not lines[0].startswith("#!") or "python" not in lines[0]:
            continue
        shim = ("#!/bin/sh\n"
                '"true" \'\'\'\'\n'
                'exec "$(dirname "$0")/%s" "$0" "$@"\n'
                "'''\n" % py_rel)
        entry.write_text(shim + "\n".join(lines[1:]) + "\n")
        fixed += 1
    print(f"  fixed {fixed} console-script shebang(s)")


def render(template: str, **tokens: str) -> str:
    for k, v in tokens.items():
        template = template.replace("{" + k + "}", v)
    return template


def _extract(arc: Path, kind: str, dest: Path) -> None:
    if kind == "zip":
        with zipfile.ZipFile(arc) as z:
            z.extractall(dest)
    else:
        with tarfile.open(arc) as t:
            t.extractall(dest)


def download_tools(manifest: Path, pack: Path, os_name: str, arch: str) -> tuple[dict, dict]:
    """Download + install CLI tools for (os,arch). Returns (lock, env) where lock maps
    tool -> {version, sha256, binary, …} and env maps runtime var -> pack-relative path
    (e.g. NMAPDIR). Single-binary tools land in bin/; 'bundle' tools extract to
    share/<dir>/ with their binaries linked into bin/."""
    spec = json.loads(manifest.read_text())
    bindir = pack / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    arch_default = spec.get("arch_map_default", {})
    lock: dict = {}
    env: dict = {}
    exe = ".exe" if os_name == "windows" else ""
    for tool in spec["tools"]:
        name = tool["name"]
        plats = tool.get("platforms")
        if plats and f"{os_name}/{arch}" not in plats:
            print(f"  - {name}: no build for {os_name}/{arch}, skipping")
            continue
        toks = {
            "version": tool["version"],
            "os": tool.get("os_map", spec.get("os_map_default", {})).get(os_name, os_name),
            "arch": tool.get("arch_map", arch_default).get(arch, arch),
            "arch2": {"x86_64": "x86_64", "aarch64": "arm64"}.get(arch, arch),
            "arch3": tool.get("arch3", {}).get(arch, arch),
        }
        url = render(tool["url"], **toks)
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                arc = tmp / f"{name}.{tool['archive']}"
                print(f"  - {name}: {url}")
                urllib.request.urlretrieve(url, arc)  # noqa: S310 (trusted release URLs)

                if tool.get("kind") == "bundle":
                    lock[name] = _install_bundle(tool, arc, pack, bindir, exe, url, env)
                else:
                    _extract(arc, tool["archive"], tmp)
                    binname = tool["binary"] + exe
                    found = next((p for p in tmp.rglob(binname) if p.is_file()), None)
                    if not found:
                        print(f"    ! binary '{binname}' not found in archive, skipping")
                        continue
                    dest = bindir / binname
                    shutil.copy2(found, dest)
                    dest.chmod(0o755)
                    digest = sha256_file(dest)
                    lock[name] = {"version": tool["version"], "sha256": digest,
                                  "url": url, "binary": binname}
                    print(f"    ok {binname} sha256={digest[:16]}…")
        except Exception as e:  # noqa: BLE001 — one tool failing must not fail the pack
            print(f"    ! {name} failed: {e}")
    return lock, env


def _install_bundle(tool: dict, arc: Path, pack: Path, bindir: Path, exe: str,
                    url: str, env: dict) -> dict:
    """Extract a bundle tool (binary + data dir) into share/<bundle_dir>/, link its
    binaries into bin/, and register its runtime env (e.g. NMAPDIR)."""
    share = pack / "share" / tool["bundle_dir"]
    if share.exists():
        shutil.rmtree(share)
    share.mkdir(parents=True)
    _extract(arc, tool["archive"], share)
    # some archives nest a single top dir; flatten it so paths match the manifest env
    entries = [p for p in share.iterdir() if p.name not in (".", "..")]
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for item in list(inner.iterdir()):
            shutil.move(str(item), str(share / item.name))
        inner.rmdir()

    linked = []
    for b in tool.get("binaries", [tool.get("primary", tool["name"])]):
        bname = b + exe
        target = share / bname
        if not target.exists():
            print(f"    ! bundle binary '{bname}' missing, skipping link")
            continue
        target.chmod(0o755)
        link = bindir / bname
        if link.exists() or link.is_symlink():
            link.unlink()
        # relative symlink so the pack stays relocatable
        link.symlink_to(os.path.relpath(target, bindir))
        linked.append(bname)

    for var, rel in (tool.get("env") or {}).items():
        env[var] = rel  # pack-relative; resolved to absolute at runtime by pack.build_env

    primary = tool.get("primary", tool["name"]) + exe
    digest = sha256_file(share / primary)
    print(f"    ok bundle {tool['name']} -> share/{tool['bundle_dir']} "
          f"(bin: {', '.join(linked)}) sha256={digest[:16]}…")
    return {"version": tool["version"], "sha256": digest, "url": url,
            "binary": primary, "kind": "bundle", "bundle_dir": tool["bundle_dir"],
            "binaries": linked, "env": tool.get("env") or {}}


def pip_freeze(uv: str, pybin: Path) -> list[str]:
    out = subprocess.run([uv, "pip", "freeze", "--python", str(pybin)],
                         capture_output=True, text=True, check=True)
    return [l for l in out.stdout.splitlines() if l and not l.startswith("#")]


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(HERE / "out"), help="output root dir")
    ap.add_argument("--python-version", default="3.12")
    ap.add_argument("--requirements", default=str(HERE / "sandbox-requirements.in"))
    ap.add_argument("--manifest", default=str(HERE / "tools.manifest.json"))
    ap.add_argument("--uv", default=None, help="path to uv binary")
    ap.add_argument("--no-tools", action="store_true", help="skip CLI tool download")
    ap.add_argument("--tar", action="store_true", help="also produce a .tar.gz")
    args = ap.parse_args()

    uv = find_uv(args.uv)
    os_name, arch = detect_os(), detect_arch()
    triple = f"{os_name}-{arch}"
    out = Path(args.out).resolve()
    pack = out / triple
    if pack.exists():
        shutil.rmtree(pack)
    pack.mkdir(parents=True)

    print(f"[1/5] uv={uv}  target={triple}  python={args.python_version}")
    print("[2/5] installing standalone python …")
    pybin = install_python(uv, pack, args.python_version)
    print(f"      interpreter: {pybin}")

    print("[3/5] installing packages into interpreter …")
    lockfile = install_packages(uv, pybin, Path(args.requirements), pack, triple)
    relocate_fixup(pack, pybin)

    tools_lock, tools_env = {}, {}
    if not args.no_tools:
        print("[4/5] downloading CLI tools …")
        tools_lock, tools_env = download_tools(Path(args.manifest), pack, os_name, arch)
        (pack / "tools.lock.json").write_text(json.dumps(tools_lock, indent=2))
    else:
        print("[4/5] skipping CLI tools (--no-tools)")

    print("[5/5] writing pack manifest …")
    manifest = {
        "schema": 1,
        "triple": triple,
        "os": os_name,
        "arch": arch,
        "python_version": args.python_version,
        # store with forward slashes so the path joins cleanly on any OS that reads it
        "interpreter": pybin.relative_to(pack).as_posix(),
        "python_lock": lockfile.name,
        "packages": pip_freeze(uv, pybin),
        "tools": tools_lock,
        "env": tools_env,   # runtime env vars (pack-relative), e.g. {"NMAPDIR": "share/nmap/data"}
    }
    (pack / "pack.manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"      packages: {len(manifest['packages'])}  tools: {len(tools_lock)}")

    if args.tar:
        tarpath = out / f"strobes-sandbox-pack-{triple}.tar.gz"
        print(f"[+] taring -> {tarpath}")
        with tarfile.open(tarpath, "w:gz") as t:
            t.add(pack, arcname=triple)
        print(f"    size: {tarpath.stat().st_size / 1e6:.1f} MB")

    print(f"\n✅ pack built: {pack}")
    print(f"   run: {pack / manifest['interpreter']} -c 'import boto3, reportlab; print(\"ok\")'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
