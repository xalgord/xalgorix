#!/usr/bin/env bash
#
# Xalgorix installer — one-line install of the latest release binary.
#
#   curl -sSL https://raw.githubusercontent.com/xalgorix/xalgorix/main/install.sh | bash
#
# What it does:
#   1. Detects your OS and CPU architecture.
#   2. Downloads the matching prebuilt binary from the latest GitHub Release.
#   3. Installs it to /usr/local/bin (falls back to ~/.local/bin without sudo).
#
# Env overrides:
#   XALGORIX_INSTALL_DIR   target directory (default: /usr/local/bin)
#   XALGORIX_VERSION       specific version tag, e.g. v4.5.48 (default: latest)
#
set -euo pipefail

REPO="xalgorix/xalgorix"
BINARY="xalgorix"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}==>${NC} $*"; }
ok()   { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${YELLOW}==>${NC} $*"; }
die()  { echo -e "${RED}error:${NC} $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required but not installed."

# ── Detect platform ────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) die "Unsupported OS '$OS'. Xalgorix ships Linux and macOS binaries; build from source for other platforms (see README)." ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported architecture '$ARCH'. Build from source (see README)." ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"
info "Platform: ${OS}/${ARCH} → asset '${ASSET}'"

# ── Resolve version ─────────────────────────────────────────────────────────
VERSION="${XALGORIX_VERSION:-}"
if [[ -z "$VERSION" ]]; then
  info "Resolving latest release…"
  VERSION="$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [[ -n "$VERSION" ]] || die "Could not resolve the latest release tag from GitHub."
fi
ok "Installing ${BINARY} ${VERSION}"

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

# ── Download ────────────────────────────────────────────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
info "Downloading ${URL}"
if ! curl -fSL --progress-bar "$URL" -o "$TMP/$BINARY"; then
  die "Download failed. This release may not include a ${OS}/${ARCH} binary — check https://github.com/${REPO}/releases"
fi
chmod +x "$TMP/$BINARY"

# ── Install ─────────────────────────────────────────────────────────────────
DEST="${XALGORIX_INSTALL_DIR:-/usr/local/bin}"
install_to() { mkdir -p "$1" && mv "$TMP/$BINARY" "$1/$BINARY"; }

if [[ -w "$DEST" ]]; then
  install_to "$DEST"
elif command -v sudo >/dev/null 2>&1; then
  info "Installing to ${DEST} (needs sudo)…"
  sudo mkdir -p "$DEST"
  sudo mv "$TMP/$BINARY" "$DEST/$BINARY"
else
  DEST="$HOME/.local/bin"
  warn "No write access to system path and sudo unavailable — installing to ${DEST}"
  install_to "$DEST"
  case ":$PATH:" in
    *":$DEST:"*) : ;;
    *) warn "Add ${DEST} to your PATH:  export PATH=\"\$PATH:${DEST}\"" ;;
  esac
fi

ok "Installed ${BINARY} → ${DEST}/${BINARY}"
echo ""
echo "  Next step (interactive setup):"
echo "    ${DEST}/${BINARY} --setup"
echo ""
echo "  The wizard configures your provider, model, and API key, then can launch"
echo "  the dashboard. Settings are stored privately in ~/.xalgorix.env."
echo ""
echo "  Prefer zero setup? Try the hosted version: https://www.xalgorix.com"
