#!/usr/bin/env python3
"""
test_pack.py — validate a built sandbox pack the way the bridge will actually use it.

Runs under ANY Python; it drives the PACK's own interpreter as a subprocess (never the
host interpreter) so a green run proves the pack is self-contained. Checks:

  1. interpreter launches and reports the expected version
  2. every pinned package imports (baseline + native + report/doc)
  3. native C/Rust extensions actually load and *work*:
       curl_cffi, cryptography (Fernet round-trip), lxml, pillow, zstandard, reportlab PDF
  4. sys.prefix points inside the pack (no leak to a host interpreter)
  5. CLI tools present, executable, version-runnable; sha256 matches tools.lock.json
  6. RELOCATABILITY: copy the pack to a fresh path and re-run (2)+(3) from there

Usage:  python3 test_pack.py --pack out/macos-aarch64   [--skip-relocate]
Exit 0 = all pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Windows cp1252 consoles can't encode the ✓/✗ used below; force UTF-8 where possible.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

IMPORTS = {
    "baseline": ["boto3", "botocore", "requests", "paramiko", "urllib3", "certifi", "yaml"],
    "native": ["curl_cffi", "cryptography", "lxml.etree", "PIL", "zstandard"],
    "report": ["reportlab", "pypdf", "pdfplumber", "docx", "pptx", "defusedxml"],
}

FUNCTIONAL = r"""
import sys, json, io
res = {"prefix": sys.prefix, "version": "%d.%d.%d" % sys.version_info[:3]}

from cryptography.fernet import Fernet
k = Fernet(Fernet.generate_key())
res["fernet_ok"] = k.decrypt(k.encrypt(b"strobes")) == b"strobes"

from curl_cffi import requests as cr
res["curl_cffi_ok"] = hasattr(cr, "Session")

from lxml import etree
res["lxml_ok"] = etree.fromstring("<a><b x='1'/></a>").xpath("//b/@x") == ["1"]

from PIL import Image
buf = io.BytesIO(); Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, "PNG")
res["pillow_ok"] = buf.getbuffer().nbytes > 0

import zstandard as z
d = b"strobes" * 100
res["zstd_ok"] = z.ZstdDecompressor().decompress(z.ZstdCompressor().compress(d)) == d

from reportlab.pdfgen import canvas
buf = io.BytesIO(); c = canvas.Canvas(buf); c.drawString(72, 720, "strobes"); c.save()
res["pdf_ok"] = buf.getvalue().startswith(b"%PDF")

import boto3
from botocore.config import Config
boto3.client("s3", region_name="ap-south-1", aws_access_key_id="x",
             aws_secret_access_key="y", config=Config(retries={"max_attempts": 0}))
res["boto3_ok"] = True

print("RESULT:" + json.dumps(res))
"""

GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def ok(m):  print(f"  {GREEN}✓{RST} {m}")
def bad(m): print(f"  {RED}✗ {m}{RST}")


def interp(pack: Path) -> Path:
    m = json.loads((pack / "pack.manifest.json").read_text())
    p = pack / m["interpreter"]
    if not p.exists():
        raise SystemExit(f"interpreter missing: {p}")
    return p


def run_imports(pybin: Path) -> bool:
    passed = True
    for group, mods in IMPORTS.items():
        line = []
        for m in mods:
            r = subprocess.run([str(pybin), "-c", f"import {m}"],
                               capture_output=True, text=True)
            good = r.returncode == 0
            line.append(f"{GREEN if good else RED}{m}{RST}")
            if not good:
                passed = False
                print(f"    {RED}{m}: {(r.stderr.strip().splitlines() or ['?'])[-1]}{RST}")
        print(f"  {group:9s} " + "  ".join(line))
    return passed


def run_functional(pybin: Path, pack: Path) -> bool:
    r = subprocess.run([str(pybin), "-c", FUNCTIONAL], capture_output=True, text=True)
    if r.returncode != 0:
        bad("functional probe crashed"); print(DIM + r.stderr.strip()[-1500:] + RST)
        return False
    line = next((l for l in r.stdout.splitlines() if l.startswith("RESULT:")), None)
    if not line:
        bad("no RESULT from probe"); print(DIM + r.stdout[-800:] + RST); return False
    res = json.loads(line[len("RESULT:"):])
    passed = str(pack.resolve()) in str(Path(res["prefix"]).resolve())
    (ok if passed else bad)(f"sys.prefix inside pack ({res['prefix']})")
    ok(f"python {res['version']}")
    for key in ("fernet_ok", "curl_cffi_ok", "lxml_ok", "pillow_ok",
                "zstd_ok", "pdf_ok", "boto3_ok"):
        good = res.get(key) is True
        (ok if good else bad)(key)
        passed &= good
    return passed


def check_tools(pack: Path) -> bool:
    lock_path = pack / "tools.lock.json"
    if not lock_path.exists() or not (lock := json.loads(lock_path.read_text())):
        print(f"  {DIM}(no tools recorded; skipping){RST}")
        return True
    # Build the same env the bridge injects: pack bin on PATH + bundle env (NMAPDIR).
    manifest = json.loads((pack / "pack.manifest.json").read_text())
    tool_env = dict(os.environ)
    tool_env["PATH"] = str(pack / "bin") + os.pathsep + tool_env.get("PATH", "")
    for var, rel in (manifest.get("env") or {}).items():
        tool_env[var] = str((pack / rel).resolve())
    passed = True
    for name, meta in lock.items():
        binp = pack / "bin" / meta["binary"]
        if not binp.exists():
            bad(f"{name}: missing binary"); passed = False; continue
        if hashlib.sha256(binp.read_bytes()).hexdigest() != meta["sha256"]:
            bad(f"{name}: sha256 mismatch"); passed = False; continue
        r = subprocess.run([str(binp), "-version"], capture_output=True, text=True, env=tool_env)
        if r.returncode != 0:
            r = subprocess.run([str(binp), "--version"], capture_output=True, text=True, env=tool_env)
        runnable = r.returncode == 0 or bool((r.stdout + r.stderr).strip())
        (ok if runnable else bad)(f"{name} {meta['version']} (sha256 ✓, runs {runnable})")
        passed &= runnable
        # nmap: prove an actual unprivileged connect scan works with the pack's NMAPDIR.
        if name == "nmap":
            s = subprocess.run([str(binp), "-sT", "-Pn", "-p", "80", "127.0.0.1"],
                               capture_output=True, text=True, env=tool_env)
            out = s.stdout + s.stderr
            scanned = "Nmap done" in out and "Unable to find nmap-services" not in out
            (ok if scanned else bad)(f"nmap connect-scan + NMAPDIR ({'ok' if scanned else out[-160:]})")
            passed &= scanned
    return passed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--skip-relocate", action="store_true")
    args = ap.parse_args()
    pack = Path(args.pack).resolve()
    if not (pack / "pack.manifest.json").exists():
        raise SystemExit(f"not a pack (no pack.manifest.json): {pack}")

    all_ok = True
    print(f"\n== sandbox pack: {pack} ==")
    pybin = interp(pack)
    print("\n[imports @ build location]");     all_ok &= run_imports(pybin)
    print("\n[functional @ build location]");  all_ok &= run_functional(pybin, pack)
    print("\n[cli tools]");                    all_ok &= check_tools(pack)

    if not args.skip_relocate:
        print("\n[relocatability] copying pack to a fresh path and re-running …")
        with tempfile.TemporaryDirectory(prefix="strobes-reloc-") as td:
            moved = Path(td) / "moved" / pack.name
            moved.parent.mkdir(parents=True)
            shutil.copytree(pack, moved, symlinks=True)
            mpy = interp(moved)
            print(f"  moved -> {moved}")
            all_ok &= run_imports(mpy)
            all_ok &= run_functional(mpy, moved)

    print(f"\n{'='*50}")
    print(f"{GREEN}ALL PASS{RST}" if all_ok else f"{RED}FAILURES ABOVE{RST}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
