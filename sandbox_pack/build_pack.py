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

# Windows consoles default to a legacy code page (cp1252) that can't encode the ✓/✅/…
# used in progress output, which crashes the build. Force UTF-8 stdio where possible.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = Path(__file__).resolve().parent

# Pack profiles → requirements files (relative to HERE). "base" is the lean web/CLI pack
# (all wheels, no compiler). "internal-ad" adds impacket/nxc/certipy/... and needs a C +
# Rust toolchain at build time (netifaces, aardwolf) — build it on manylinux/CI runners.
PROFILE_REQS = {
    "base": ["sandbox-requirements.in"],
    "internal-ad": ["sandbox-requirements.in", "internal-ad-requirements.in"],
}


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


def install_packages(uv: str, pybin: Path, req_ins: list, pack: Path, lock_key: str) -> Path:
    """Compile a pinned+hashed lock from one or more requirements files, then install
    into the standalone interpreter."""
    lock = pack / f"sandbox-requirements.{lock_key}.lock"
    run([uv, "pip", "compile", "--python", str(pybin), "--generate-hashes",
         "-o", str(lock), *[str(r) for r in req_ins]])
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


def download_tools(manifest: Path, pack: Path, os_name: str,
                   arch: str) -> tuple[dict, dict, list]:
    """Download + install CLI tools for (os,arch). Returns (lock, env, bin_dirs):
    lock maps tool -> {version, sha256, binary, …}; env maps runtime var -> pack-relative
    path (e.g. NMAPDIR); bin_dirs are extra pack-relative dirs to prepend to PATH (used by
    'path'-exposed bundles like Windows nmap whose binary needs its adjacent DLLs).
    Single-binary tools land in bin/; 'bundle' tools extract to share/<dir>/."""
    spec = json.loads(manifest.read_text())
    bindir = pack / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    arch_default = spec.get("arch_map_default", {})
    lock: dict = {}
    env: dict = {}
    bin_dirs: list = []
    exe = ".exe" if os_name == "windows" else ""
    for tool in spec["tools"]:
        name = tool["name"]
        plats = tool.get("platforms")
        if plats and f"{os_name}/{arch}" not in plats:
            print(f"  - {name}: no build for {os_name}/{arch}, skipping")
            continue
        # some tools change container format per-OS (e.g. ffuf ships .zip on Windows)
        archive = tool.get("archive_map", {}).get(os_name, tool["archive"])
        toks = {
            "version": tool["version"],
            "os": tool.get("os_map", spec.get("os_map_default", {})).get(os_name, os_name),
            "arch": tool.get("arch_map", arch_default).get(arch, arch),
            "arch2": {"x86_64": "x86_64", "aarch64": "arm64"}.get(arch, arch),
            "arch3": tool.get("arch3", {}).get(arch, arch),
            "ext": archive,   # container extension (tar.gz / zip), per-OS
        }
        url = render(tool["url"], **toks)
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                arc = tmp / f"{name}.{archive}"
                print(f"  - {name}: {url}")
                urllib.request.urlretrieve(url, arc)  # noqa: S310 (trusted release URLs)

                kind = tool.get("kind")
                if kind == "bundle":
                    lock[name] = _install_bundle(tool, arc, pack, bindir, exe, url,
                                                 env, bin_dirs)
                elif kind == "dmg":
                    lock[name] = _install_dmg(tool, arc, pack, bindir, exe, url,
                                              env, bin_dirs)
                else:
                    _extract(arc, archive, tmp)
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
    return lock, env, bin_dirs


def _install_bundle(tool: dict, arc: Path, pack: Path, bindir: Path, exe: str,
                    url: str, env: dict, bin_dirs: list) -> dict:
    """Extract an archive bundle (binary + data) into share/<bundle_dir>/, then finalize."""
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
    return _finalize_bundle(tool, share, pack, bindir, exe, url, env, bin_dirs)


def _install_dmg(tool: dict, arc: Path, pack: Path, bindir: Path, exe: str,
                 url: str, env: dict, bin_dirs: list) -> dict:
    """macOS only: mount a .dmg installer, expand its .mpkg, extract the component
    payloads, and assemble share/<bundle_dir>/ = {binaries at root, data/ subdir}.
    Used for nmap, which upstream ships only as a .dmg on macOS. The extracted nmap is
    x86_64 (runs natively on Intel, via Rosetta 2 on Apple Silicon) and statically links
    everything but libSystem/libc++, so it's self-contained."""
    share = pack / "share" / tool["bundle_dir"]
    if share.exists():
        shutil.rmtree(share)
    share.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        mnt = tdp / "mnt"
        mnt.mkdir()
        run(["hdiutil", "attach", "-nobrowse", "-readonly",
             "-mountpoint", str(mnt), str(arc)], capture_output=True)
        try:
            mpkg = next(mnt.glob("*.mpkg"))
            exp = tdp / "exp"
            run(["pkgutil", "--expand", str(mpkg), str(exp)], capture_output=True)
            root = tdp / "root"
            root.mkdir()
            for comp in tool.get("components", [tool.get("primary", tool["name"])]):
                payload = exp / f"{comp}.pkg" / "Payload"
                if payload.exists():
                    subprocess.run(f'cat "{payload}" | gzip -dc | cpio -id',
                                   cwd=root, shell=True, capture_output=True)
            # data dir (nmap-services etc.) -> share/<dir>/data
            data_src = root / tool.get("data_from", f"share/{tool['bundle_dir']}")
            shutil.copytree(data_src, share / "data")
            # binaries -> share/<dir>/
            for b in tool.get("binaries", [tool.get("primary", tool["name"])]):
                src = root / "bin" / b
                if src.exists():
                    dst = share / b
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)
        finally:
            subprocess.run(["hdiutil", "detach", str(mnt)], capture_output=True)
    return _finalize_bundle(tool, share, pack, bindir, exe, url, env, bin_dirs)


def _finalize_bundle(tool: dict, share: Path, pack: Path, bindir: Path, exe: str,
                     url: str, env: dict, bin_dirs: list) -> dict:
    """Expose a prepared share/<bundle_dir>/ and register its runtime env:
      - expose 'link' (default): relative-symlink/copy each binary into bin/. Good for
        self-contained binaries (Linux musl / macOS static nmap) that find data via env.
      - expose 'path': add share/<bundle_dir> to PATH. Needed when the binary depends on
        adjacent files (Windows nmap.exe + its DLLs)."""
    binaries = tool.get("binaries", [tool.get("primary", tool["name"])])
    expose = tool.get("expose", "link")
    exposed = []
    if expose == "path":
        bin_dirs.append(os.path.relpath(share, pack).replace(os.sep, "/"))
        for b in binaries:
            t = share / (b + exe)
            if t.exists():
                t.chmod(0o755)
                exposed.append(b + exe)
    else:  # link
        for b in binaries:
            bname = b + exe
            target = share / bname
            if not target.exists():
                print(f"    ! bundle binary '{bname}' missing, skipping")
                continue
            target.chmod(0o755)
            link = bindir / bname
            if link.exists() or link.is_symlink():
                link.unlink()
            try:  # relative symlink keeps the pack relocatable
                link.symlink_to(os.path.relpath(target, bindir))
            except (OSError, NotImplementedError):  # e.g. Windows w/o privilege
                shutil.copy2(target, link)
            exposed.append(bname)

    for var, rel in (tool.get("env") or {}).items():
        env[var] = rel  # pack-relative; resolved to absolute at runtime by pack.build_env

    primary = tool.get("primary", tool["name"]) + exe
    digest = sha256_file(share / primary)
    print(f"    ok bundle {tool['name']} -> share/{tool['bundle_dir']} "
          f"(expose={expose}: {', '.join(exposed)}) sha256={digest[:16]}…")
    return {"version": tool["version"], "sha256": digest, "url": url,
            "binary": primary, "kind": "bundle", "bundle_dir": tool["bundle_dir"],
            "expose": expose, "binaries": exposed, "env": tool.get("env") or {}}


def install_nuclei_templates(pack: Path, tools_lock: dict) -> Optional[dict]:
    """Fetch the nuclei-templates into the pack so nuclei runs fully offline. Uses the
    pack's own nuclei binary (native to the build host) to install templates, and stores
    a config dir alongside. At runtime pack.py points NUCLEI_CONFIG_DIR at a writable copy
    whose .templates-config.json names the resolved templates path."""
    meta = tools_lock.get("nuclei")
    if not meta:
        print("  (nuclei not in pack; skipping templates)")
        return None
    nbin = pack / "bin" / meta["binary"]
    tpl = pack / "share" / "nuclei-templates"
    cfg = pack / "share" / "nuclei-config"
    cfg.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        # NOTE: do NOT pass -disable-update-check here — it disables the update mechanism
        # entirely, so -update-templates would download nothing. This step needs network.
        env = {**os.environ, "HOME": td, "NUCLEI_CONFIG_DIR": str(cfg)}
        try:
            run([str(nbin), "-update-templates", "-update-template-dir", str(tpl)],
                env=env, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"  ! nuclei templates fetch failed: {e}")
            return None
    count = sum(1 for _ in tpl.rglob("*.yaml")) if tpl.exists() else 0
    if not count:
        print("  ! nuclei templates: none installed")
        return None
    print(f"  ok nuclei-templates: {count} templates -> share/nuclei-templates")
    return {"templates": "share/nuclei-templates", "config": "share/nuclei-config"}


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
    ap.add_argument("--profile", default="base", choices=list(PROFILE_REQS),
                    help="which toolset to bundle (base = web/CLI; internal-ad adds AD tools)")
    ap.add_argument("--requirements", default=None,
                    help="override the requirements file(s) for the profile")
    ap.add_argument("--manifest", default=str(HERE / "tools.manifest.json"))
    ap.add_argument("--uv", default=None, help="path to uv binary")
    ap.add_argument("--no-tools", action="store_true", help="skip CLI tool download")
    ap.add_argument("--no-templates", action="store_true",
                    help="skip bundling nuclei-templates (faster builds/tests)")
    ap.add_argument("--tar", action="store_true", help="also produce a .tar.gz")
    args = ap.parse_args()

    uv = find_uv(args.uv)
    os_name, arch = detect_os(), detect_arch()
    triple = f"{os_name}-{arch}"
    # profiled packs get a distinct name/dir so base + internal-ad can coexist
    pack_name = triple if args.profile == "base" else f"{args.profile}-{triple}"
    req_ins = ([Path(args.requirements)] if args.requirements
               else [HERE / r for r in PROFILE_REQS[args.profile]])
    out = Path(args.out).resolve()
    pack = out / pack_name
    if pack.exists():
        shutil.rmtree(pack)
    pack.mkdir(parents=True)

    print(f"[1/5] uv={uv}  target={pack_name}  python={args.python_version}")
    print(f"      profile={args.profile}  requirements={[r.name for r in req_ins]}")
    print("[2/5] installing standalone python …")
    pybin = install_python(uv, pack, args.python_version)
    print(f"      interpreter: {pybin}")

    print("[3/5] installing packages into interpreter …")
    lockfile = install_packages(uv, pybin, req_ins, pack, pack_name)
    relocate_fixup(pack, pybin)

    tools_lock, tools_env, tools_bin_dirs = {}, {}, []
    if not args.no_tools:
        print("[4/5] downloading CLI tools …")
        tools_lock, tools_env, tools_bin_dirs = download_tools(
            Path(args.manifest), pack, os_name, arch)
        (pack / "tools.lock.json").write_text(json.dumps(tools_lock, indent=2))
    else:
        print("[4/5] skipping CLI tools (--no-tools)")

    nuclei_cfg = None
    if not args.no_tools and not args.no_templates:
        print("[4b] bundling nuclei-templates …")
        nuclei_cfg = install_nuclei_templates(pack, tools_lock)

    print("[5/5] writing pack manifest …")
    manifest = {
        "schema": 1,
        "triple": triple,
        "profile": args.profile,
        "os": os_name,
        "arch": arch,
        "python_version": args.python_version,
        # store with forward slashes so the path joins cleanly on any OS that reads it
        "interpreter": pybin.relative_to(pack).as_posix(),
        "python_lock": lockfile.name,
        "packages": pip_freeze(uv, pybin),
        "tools": tools_lock,
        "env": tools_env,        # runtime env vars (pack-relative), e.g. {"NMAPDIR": "..."}
        "bin_dirs": tools_bin_dirs,  # extra PATH dirs (pack-relative), e.g. Windows nmap dir
        "nuclei": nuclei_cfg,    # {templates, config} pack-relative, or null
    }
    (pack / "pack.manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"      packages: {len(manifest['packages'])}  tools: {len(tools_lock)}")

    if args.tar:
        tarpath = out / f"strobes-sandbox-pack-{pack_name}.tar.gz"
        print(f"[+] taring -> {tarpath}")
        with tarfile.open(tarpath, "w:gz") as t:
            t.add(pack, arcname=pack_name)
        print(f"    size: {tarpath.stat().st_size / 1e6:.1f} MB")

    print(f"\n✅ pack built: {pack}")
    print(f"   run: {pack / manifest['interpreter']} -c 'import boto3, reportlab; print(\"ok\")'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
