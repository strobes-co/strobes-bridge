# Strobes Sandbox Pack

A **sandbox pack** reproduces the Strobes cloud (Bedrock) sandbox runtime on a bridge host
as a single, self-contained, relocatable directory:

- a **standalone Python interpreter** (python-build-standalone) with every agent package
  baked in — `boto3`, `reportlab`, `curl_cffi`, `cryptography`, `lxml`, `pillow`, … ;
- **CLI security tools** in `bin/` — `nuclei`, `httpx`, `subfinder`, `dnsx`, `ffuf`, `gobuster`,
  and `nmap` (+`ncat`/`nping`) — on **all** platforms (Linux, macOS, Windows).

It runs with **no Docker, no root, no system Python, and no internet at runtime**. This is how
the bridge stops being blocked by "the user can't install nmap / boto3 / reportlab here."

## Why this exists

The platform installs everything lazily at runtime (`import X` → `pip install X`), which
silently assumes the sandbox's Python + internet + arch + system libs. A customer bridge host
usually has none of those. The pack pre-solves it, once, per platform.

## Layout of a built pack

```
<triple>/                         e.g. linux-x86_64, macos-aarch64
  python/cpython-3.12.*/          standalone interpreter + site-packages
  bin/                            nuclei, httpx, ffuf, …
  pack.manifest.json              triple, interpreter path, package list, tool hashes
  tools.lock.json                 per-tool sha256 for offline verification
  sandbox-requirements.<triple>.lock   pinned + hashed python lock
```

## Building

Requires [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`).

```bash
# native build for the current OS/arch (macOS, Windows, or Linux)
python3 build_pack.py --out ./out --python-version 3.12 --tar

# Linux, portable across distros (glibc >= 2.28) — build in a manylinux_2_28 container
./build_linux_manylinux.sh x86_64
./build_linux_manylinux.sh aarch64      # arm64 host or qemu binfmt
```

`--tar` also emits `out/strobes-sandbox-pack-<triple>.tar.gz`. CI (`.github/workflows/build_sandbox_pack.yml`)
builds all platforms and publishes tarballs + `.sha256` files.

### Profiles

`--profile` selects the toolset (see `PROFILE_REQS` in `build_pack.py`):

| Profile | Adds | Build needs | Artifact name |
|---|---|---|---|
| `base` (default) | web/CLI: nuclei(+templates), nmap, httpx, ffuf, gobuster, subfinder, dnsx + python (boto3, reportlab, curl_cffi, …) | all wheels, **no compiler** | `strobes-sandbox-pack-<triple>` |
| `internal-ad` | base **plus** impacket, **netexec (nxc)**, certipy, bloodhound-python, mitm6, coercer, smbmap, ldapdomaindump, adidnsdump, bloodyAD, pywerview, lsassy | **C + Rust toolchain** (netifaces=C, aardwolf=Rust via netexec) | `strobes-sandbox-pack-internal-ad-<triple>` |

```bash
python3 build_pack.py --profile internal-ad --out ./out --tar   # native (needs gcc + rust)
./build_linux_manylinux.sh x86_64 internal-ad                   # containerised (adds rust)
```

A profiled pack extracts to its own dir (`internal-ad-<triple>`), so a base and an AD pack
can coexist; `pack.find_pack()` picks whichever is present for the host arch, and
`pack.status()["profile"]` reports which. Keep the lean **base** for web engagements; embed
**internal-ad** for internal/AD work. Git-only tools (Responder, enum4linux-ng, windapsearch)
are not yet bundled — they need a git-checkout mechanism rather than a wheel.

### Platform coverage

| Platform | Baseline | Runs on |
|---|---|---|
| linux-x86_64 / linux-aarch64 | manylinux_2_28 (glibc 2.28) | RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 10+, Amazon Linux 2023, SUSE 15+ |
| macos-aarch64 / macos-x86_64 | python-build-standalone | macOS 11+ |
| windows-x86_64 | python-build-standalone | Windows 10+ |

> glibc **< 2.28** (Amazon Linux 2, CentOS 7, Ubuntu 18.04) is **not** covered by the
> **Python** runtime: current Pillow/cryptography no longer ship glibc-2.17 wheels. A
> musl-static variant would be needed for those and Alpine — see "Future" below.
> (Note: the bundled **nmap** is musl-static and *does* run on those hosts — see below.)

### nmap (all platforms, +`ncat`/`nping`)

nmap is bundled per-OS from upstream, extracted at build time, with its data files shipped and
**`NMAPDIR`** set automatically by `pack.build_env()` (so `nmap-services`, `-sV`, and NSE work
offline). **Connect scans** (`-sT`) work **unprivileged** everywhere; **SYN** (`-sS`) and OS
detection need root / `cap_net_raw` (and the Npcap driver on Windows).

| OS | Source | Notes |
|---|---|---|
| Linux x86_64 / aarch64 | [ernw/static-toolbox](https://github.com/ernw/static-toolbox) | **musl-static** → runs on *any* Linux incl. Alpine & glibc < 2.28 (validated on Alpine 3.19, Amazon Linux 2). No floor. |
| macOS x86_64 / aarch64 | official `.dmg` (extracted at build) | binary is **x86_64** (native on Intel, **Rosetta 2** on Apple Silicon); statically links all but libSystem/libc++. Built on macOS runners only. |
| Windows x86_64 | official `nmap-7.92-win32.zip` (last portable zip) | whole dir on PATH (nmap.exe + its DLLs). **SYN/OS-detect need the Npcap driver** — a privileged kernel install that cannot be shipped as a portable file; connect scans work. |

Because nmap diverges by OS (different upstream, layout, packaging), the manifest has three
`nmap` entries with disjoint `platforms`; exactly one matches per build. Bundle install modes:
`expose: link` (symlink the self-contained binary into `bin/`, Linux/macOS) vs `expose: path`
(add the bundle dir to PATH so Windows nmap.exe finds its adjacent DLLs).

## Testing

`test_pack.py` drives the pack's **own** interpreter (never the host's), so a green run proves
self-containment. It checks imports, that native C/Rust extensions actually work (Fernet
round-trip, PDF generation, image encode, zstd), `sys.prefix` locality, CLI-tool hashes, and
**relocatability** (copies the pack elsewhere and re-runs).

```bash
python3 test_pack.py --pack out/<triple>
```

Validated offline on Rocky 8 (2.28), Ubuntu 20.04 (2.31), Debian 12 (2.36), macOS-arm64, and
Linux arm64/x86_64 in pristine `debian:12-slim` containers with **no system Python and
`--network none`**.

## How the bridge uses a pack

`strobes_shell_agent/pack.py` locates and (optionally) provisions a pack; the executor then
prepends `bin/` + the interpreter to `PATH` for every command and uses the pack's Python for
`execute_code`. If no pack is present, everything falls back to host tools unchanged.

Config (env):

| Var | Meaning |
|---|---|
| `STROBES_PACK_PATH` | absolute path to an extracted pack (air-gapped / bundled) |
| `STROBES_PACK_DIR`  | root holding `<triple>/` packs (default `~/.strobes-shell-agent/pack`) |
| `STROBES_PACK_URL`  | base URL to download `strobes-sandbox-pack-<triple>.tar.gz` (+ `.sha256`) on connect |
| `STROBES_PACK_DISABLE` | set truthy to ignore any pack |

## Adding a tool or package

- **Python package** → add to `sandbox-requirements.in` (note native vs pure-python), rebuild.
- **CLI tool** → add an entry to `tools.manifest.json` (URL template + per-os/arch maps +
  `platforms`), rebuild. The build records its sha256 into `tools.lock.json`.

## Future

- **Tier 2 (browser):** playwright + Chromium + its `.so` closure (heavier, separate pack).
- **Tier 3 (specialist):** frida-tools, z3-solver, sliver-py/mythic, APK toolchain.
- **musl variant:** for Alpine and glibc < 2.28 hosts (needs musllinux wheel coverage check,
  notably `curl_cffi`).
