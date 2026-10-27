#!/usr/bin/env bash
# Strobes Shell Bridge Agent — one-line installer (Linux + macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/strobes-co/strobes-bridge/main/install.sh | bash
#
# Downloads the prebuilt binary (sandbox pack embedded — nmap/nuclei/... run offline),
# installs it, walks you through setup, and registers a system service that starts on
# boot. Non-interactive: pass STROBES_URL / STROBES_API_KEY / STROBES_ORG_ID in the env.
#
#   Uninstall:  curl -fsSL .../install.sh | bash -s -- --uninstall
#   No service: ... | bash -s -- --no-service      (just install the binary)
set -euo pipefail

REPO="strobes-co/strobes-bridge"
BIN_NAME="strobes-shell-agent"

# Where to fetch the binary from. When this installer is served by a Strobes
# tenant (AI → Shells → one-line install), the tenant's install-script proxy
# rewrites the token below to its own same-origin download endpoint, so the
# executable is pulled from the tenant too — no GitHub dependency, works behind
# proxies that block GitHub. Left untouched (still the token) when the script is
# fetched directly from GitHub raw, in which case we fall back to GitHub Releases.
DOWNLOAD_BASE="__STROBES_DOWNLOAD_BASE__"
case "$DOWNLOAD_BASE" in *__STROBES_DOWNLOAD_BASE__*) DOWNLOAD_BASE="" ;; esac

UNINSTALL=0
WITH_SERVICE=1
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
    --no-service) WITH_SERVICE=0 ;;
  esac
done

c_blue()  { printf "\033[34m%b\033[0m\n" "$1"; }
c_green() { printf "\033[32m%b\033[0m\n" "$1"; }
c_red()   { printf "\033[31m%b\033[0m\n" "$1" >&2; }
die()     { c_red "error: $1"; exit 1; }

# --- resolve platform → release asset ---------------------------------------
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64)  ASSET="${BIN_NAME}-linux-amd64" ;;
      aarch64|arm64) ASSET="${BIN_NAME}-linux-arm64" ;;
      *) die "unsupported Linux arch: $arch" ;;
    esac ;;
  Darwin)
    case "$arch" in
      arm64) ASSET="${BIN_NAME}-macos-arm64" ;;
      x86_64) die "Intel macOS has no prebuilt binary — run the Docker image, or use an arm64 Mac." ;;
      *) die "unsupported macOS arch: $arch" ;;
    esac ;;
  *) die "unsupported OS: $os (use install.ps1 on Windows)" ;;
esac

# --- pick an install dir on PATH --------------------------------------------
if [ -w /usr/local/bin ] 2>/dev/null; then
  BINDIR=/usr/local/bin; SUDO=""
elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
  BINDIR=/usr/local/bin; SUDO="sudo"
else
  BINDIR="$HOME/.local/bin"; SUDO=""; mkdir -p "$BINDIR"
fi
TARGET="$BINDIR/$BIN_NAME"

# --- uninstall ---------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  c_blue "Removing Strobes Shell Agent…"
  "$TARGET" uninstall-service 2>/dev/null || true
  $SUDO rm -f "$TARGET" 2>/dev/null || rm -f "$TARGET" 2>/dev/null || true
  c_green "Uninstalled."
  exit 0
fi

# --- download ----------------------------------------------------------------
if [ -n "$DOWNLOAD_BASE" ]; then
  # Tenant proxy: {tenant}/api/v1/organizations/{org}/ai/bridge/download/?asset=…
  case "$DOWNLOAD_BASE" in *\?*) URL="${DOWNLOAD_BASE}&asset=${ASSET}" ;; *) URL="${DOWNLOAD_BASE}?asset=${ASSET}" ;; esac
else
  # This repo publishes two interleaved release trains — agent binaries
  # (vX.Y.Z) and sandbox packs (pack-vX.Y.Z) — and GitHub's /releases/latest
  # just means "most recently published release", regardless of train. So it
  # can resolve to a pack-only release that has no agent binary at all. Walk
  # releases newest-first (both trains, pack releases included) and use the
  # first one that actually ships this platform's asset.
  c_blue "Resolving latest release that includes ${ASSET}…"
  TAG=""
  for page in 1 2 3 4 5; do
    RELEASES_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100&page=${page}")" || die "failed to query GitHub releases API"
    [ "$RELEASES_JSON" = "[]" ] && break
    # awk must NOT `exit` early here: with `pipefail` set, closing its stdin
    # before printf finishes writing the (multi-KB) JSON blob sends printf a
    # SIGPIPE, which pipefail turns into the pipeline's exit status and kills
    # the script under `set -e` before `die` ever runs. Read to EOF instead.
    TAG="$(printf '%s' "$RELEASES_JSON" | awk -v want="\"name\": \"${ASSET}\"" '
      /"tag_name":/ { tag=$0 }
      index($0, want) && !found { result=tag; found=1 }
      END { print result }
    ' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    [ -n "$TAG" ] && break
  done
  [ -n "$TAG" ] || die "no release found containing asset ${ASSET}"
  URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
fi
c_blue "Downloading ${ASSET}…"
TMP="$(mktemp)"
curl -fSL --progress-bar "$URL" -o "$TMP" || die "download failed: $URL"
chmod +x "$TMP"
if [ -n "$SUDO" ]; then $SUDO mv "$TMP" "$TARGET"; else mv "$TMP" "$TARGET"; fi
c_green "Installed: $TARGET"
case ":$PATH:" in *":$BINDIR:"*) : ;; *) c_blue "note: add $BINDIR to your PATH";; esac

# --- egress sandbox (Linux) ---------------------------------------------------
# AI-issued commands run only inside an egress sandbox; without one the bridge
# refuses them. macOS ships Seatbelt; on Linux it is a system package, so say
# exactly what to install rather than installing it behind the user's back.
if [ "$os" = "Linux" ] && ! command -v bwrap >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then PKG="sudo apt-get install -y bubblewrap"
  elif command -v dnf >/dev/null 2>&1; then PKG="sudo dnf install -y bubblewrap"
  elif command -v yum >/dev/null 2>&1; then PKG="sudo yum install -y bubblewrap"
  elif command -v apk >/dev/null 2>&1; then PKG="sudo apk add bubblewrap"
  else PKG="install bubblewrap with your package manager"; fi
  c_red "warning: no egress sandbox on this host — the bridge will refuse AI-issued commands."
  echo  "   Fix:     $PKG"
  echo  "            (or run as root with nftables installed, for the packet-filter lane)"
  echo  "   Verify:  $BIN_NAME sandbox-check"
fi

# --- interactive setup (reads the terminal even when piped via curl|bash) ----
ask() { # ask VAR "Prompt" [silent]
  local __v="$1" __p="$2" __s="${3:-}" __cur ans
  __cur="$(eval "printf '%s' \"\${$__v:-}\"")"
  if [ -n "$__cur" ]; then return; fi          # already provided via env
  if [ ! -r /dev/tty ]; then return; fi        # non-interactive, no tty
  if [ -n "$__s" ]; then
    printf "%s" "$__p" > /dev/tty; read -rs ans < /dev/tty; printf "\n" > /dev/tty
  else
    printf "%s" "$__p" > /dev/tty; read -r ans < /dev/tty
  fi
  eval "$__v=\$ans"
}

STROBES_URL="${STROBES_URL:-}"; STROBES_API_KEY="${STROBES_API_KEY:-}"
STROBES_ORG_ID="${STROBES_ORG_ID:-}"; STROBES_SHELL_NAME="${STROBES_SHELL_NAME:-}"

if [ "$WITH_SERVICE" = 1 ]; then
  c_blue "\nSetup (from Strobes: AI → Shells → Create Shell [Bridge], and Settings → API Keys):"
  ask STROBES_URL     "  Strobes URL [https://app.strobes.co]: "
  STROBES_URL="${STROBES_URL:-https://app.strobes.co}"
  ask STROBES_API_KEY "  API key: " silent
  ask STROBES_ORG_ID  "  Organization ID: "
  ask STROBES_SHELL_NAME "  Shell name [$(hostname)]: "
  STROBES_SHELL_NAME="${STROBES_SHELL_NAME:-$(hostname)}"
fi

# --- register + start the service -------------------------------------------
if [ "$WITH_SERVICE" = 1 ] && [ -n "$STROBES_URL" ] && [ -n "$STROBES_API_KEY" ] && [ -n "$STROBES_ORG_ID" ]; then
  c_blue "Registering system service…"
  "$TARGET" install-service \
    --url "$STROBES_URL" --api-key "$STROBES_API_KEY" --org-id "$STROBES_ORG_ID" \
    ${STROBES_SHELL_NAME:+--name "$STROBES_SHELL_NAME"} || die "service registration failed"
  c_green "\n✅ Installed and running as a service."
  echo    "   Verify tools:  $BIN_NAME selftest"
  if [ "$os" = "Darwin" ]; then
    echo  "   Start/stop:    launchctl load|unload -w ~/Library/LaunchAgents/co.strobes.shell-agent.plist"
  else
    echo  "   Start/stop:    systemctl --user start|stop|status co.strobes.shell-agent.service"
    echo  "                  (sudo systemctl … if installed as root)"
  fi
  echo    "   Uninstall:     $BIN_NAME uninstall-service   (or re-run installer with --uninstall)"
else
  c_green "\n✅ Binary installed."
  echo    "   Run:  $BIN_NAME connect --url <URL> --api-key <KEY> --org-id <ORG> --name <NAME>"
  echo    "   Or as a service:  $BIN_NAME install-service --url … --api-key … --org-id …"
  echo    "   Verify tools:     $BIN_NAME selftest"
fi
