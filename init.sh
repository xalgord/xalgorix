#!/usr/bin/env bash
# init.sh — Xalgorix agent verification entrypoint.
#
# Run this from the repo root before claiming a feature is done.
# Exits 0 only if the entire stack is green.
#
# Usage:
#   ./init.sh                  # full check (webui build + go test + race + vet + binary)
#   ./init.sh --no-webui       # skip webui bundle (use when webui unchanged)
#   ./init.sh --no-race        # skip race detector (faster local loop)
#   ./init.sh --help
#
# Environment overrides:
#   SKIP_WEBUI=1   same as --no-webui
#   SKIP_RACE=1    same as --no-race

set -euo pipefail

BUILD_WEBUI=1
RUN_RACE=1

for arg in "$@"; do
  case "$arg" in
    --no-webui) BUILD_WEBUI=0 ;;
    --no-race)  RUN_RACE=0 ;;
    --help|-h)
      sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "init.sh: unknown flag '$arg' (use --help)" >&2; exit 2 ;;
  esac
done
[ "${SKIP_WEBUI:-0}" = "1" ] && BUILD_WEBUI=0
[ "${SKIP_RACE:-0}"  = "1" ] && RUN_RACE=0

cd "$(dirname "$0")"

# --- preflight --------------------------------------------------------------
echo "▶ init.sh: preflight"
if ! command -v go >/dev/null 2>&1; then
  echo "  ✗ go not found on PATH" >&2; exit 1
fi
GO_VERSION_RAW="$(go version | awk '{print $3}')"   # e.g. go1.24.2
GO_MAJOR_MINOR="$(echo "$GO_VERSION_RAW" | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')"
case "$GO_MAJOR_MINOR" in
  1.24|1.25|1.26) echo "  ✓ go $GO_VERSION_RAW" ;;
  *) echo "  ✗ go $GO_VERSION_RAW — xalgorix needs go1.24+ (see go.mod)" >&2; exit 1 ;;
esac

if [ "$BUILD_WEBUI" = "1" ]; then
  if ! command -v node >/dev/null 2>&1; then
    echo "  ✗ node not found on PATH (needed for webui bundle)" >&2; exit 1
  fi
  echo "  ✓ node $(node -v)"
fi

# --- webui bundle -----------------------------------------------------------
if [ "$BUILD_WEBUI" = "1" ]; then
  echo "▶ init.sh: webui bundle (npm install + vite build)"
  make webui
else
  echo "▶ init.sh: webui bundle SKIPPED (--no-webui)"
fi

# --- gofmt ------------------------------------------------------------------
echo "▶ init.sh: gofmt"
UNFORMATTED="$(gofmt -l . 2>/dev/null | grep -v '^vendor/' || true)"
if [ -n "$UNFORMATTED" ]; then
  echo "  ✗ the following files are not gofmt-clean:" >&2
  echo "$UNFORMATTED" >&2
  echo "  run: go fmt ./..." >&2
  exit 1
fi
echo "  ✓ gofmt clean"

# --- go vet -----------------------------------------------------------------
echo "▶ init.sh: go vet"
go vet ./...

# --- go test ----------------------------------------------------------------
echo "▶ init.sh: go test ./..."
go test ./...

# --- race detector ----------------------------------------------------------
if [ "$RUN_RACE" = "1" ]; then
  echo "▶ init.sh: go test -race ./..."
  go test -race ./...
else
  echo "▶ init.sh: race detector SKIPPED (--no-race)"
fi

# --- build ------------------------------------------------------------------
echo "▶ init.sh: build ./cmd/xalgorix"
mkdir -p build
go build -o build/xalgorix ./cmd/xalgorix

# --- summary ----------------------------------------------------------------
echo
echo "✓ init.sh: ALL CHECKS PASSED"
echo "  binary: $(pwd)/build/xalgorix"
