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
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
c_blue "Downloading ${ASSET}…"
TMP="$(mktemp)"
curl -fSL --progress-bar "$URL" -o "$TMP" || die "download failed: $URL"
chmod +x "$TMP"
if [ -n "$SUDO" ]; then $SUDO mv "$TMP" "$TARGET"; else mv "$TMP" "$TARGET"; fi
c_green "Installed: $TARGET"
case ":$PATH:" in *":$BINDIR:"*) : ;; *) c_blue "note: add $BINDIR to your PATH";; esac

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
