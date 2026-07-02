#!/usr/bin/env bash
# Build a Linux sandbox pack inside a manylinux_2_28 container (glibc 2.28 baseline).
#
# Building against manylinux_2_28 makes the standalone interpreter + all native wheels
# target glibc >= 2.28, so the pack runs on RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 10+,
# Amazon Linux 2023, SUSE 15+. (An older 2.17 baseline is NOT viable: current Pillow and
# cryptography no longer publish glibc-2.17 wheels.)
#
# Usage:
#   ./build_linux_manylinux.sh x86_64            # -> out/linux-x86_64 + tarball
#   ./build_linux_manylinux.sh aarch64           # needs an arm64 host or qemu binfmt
#
# Requires Docker. Output lands in sandbox_pack/out/.
set -euo pipefail

ARCH="${1:-x86_64}"
case "$ARCH" in
  x86_64)  IMAGE="quay.io/pypa/manylinux_2_28_x86_64";  PLATFORM="linux/amd64" ;;
  aarch64) IMAGE="quay.io/pypa/manylinux_2_28_aarch64"; PLATFORM="linux/arm64" ;;
  *) echo "usage: $0 [x86_64|aarch64]" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/out"

echo ">> building linux-$ARCH pack in $IMAGE"
docker run --rm --platform "$PLATFORM" \
  -v "$HERE":/src:ro -v "$HERE/out":/out \
  "$IMAGE" bash -lc '
    set -e
    echo "host glibc: $(ldd --version | head -1)"
    export HOME=/root PATH=/root/.local/bin:$PATH
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
    uv run --python 3.12 python /src/build_pack.py --out /out \
      --requirements /src/sandbox-requirements.in \
      --manifest /src/tools.manifest.json \
      --python-version 3.12 --tar
  '
echo ">> done: $HERE/out/strobes-sandbox-pack-linux-$ARCH.tar.gz"
