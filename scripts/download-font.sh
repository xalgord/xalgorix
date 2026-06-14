#!/usr/bin/env bash
# scripts/download-font.sh — Xalgorix F-001 Chinese PDF report font.
#
# Downloads the Noto Sans CJK SC Regular OTF (~10MB, Apache 2.0) used
# by the F-001 Chinese report bundle into internal/reporting/fonts/.
# The Go binary embeds this file via //go:embed, so it must be present
# at build time.
#
# This script is:
#   - idempotent: if the file is already present and looks valid, exit 0
#   - validating: refuses to land a file that's too small or has the
#     wrong OTF magic bytes
#   - verbose: every line is prefixed with two spaces so it nests cleanly
#     under `make download-font`'s "▶" line.
#
# Run from repo root. Exit codes:
#   0  success (file already present, or newly downloaded + validated)
#   1  download failed, file too small, or magic bytes wrong

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

FONT_DIR="internal/reporting/fonts"
FONT_FILE="$FONT_DIR/NotoSansSC-Regular.ttf"
MIN_SIZE_BYTES=5000000  # ~5MB; smaller is almost certainly a 404 or wrong file

# Noto Sans SC (Simplified Chinese web subset) in TTF format. The
# full CJK family (Noto Sans CJK SC) is OTF-only on the notofonts
# project, and fpdf's UTF8 font parser REJECTS OTF files (its
# parseFile() returns "not supported" for the OTTO magic — see
# utf8fontfile.go in github.com/go-pdf/fpdf). Switching to the SC
# subset TTF: same Apache 2.0 license, ~10MB, fpdf-compatible.
#
# Source: Google Fonts CDN (https://fonts.google.com/noto/specimen/Noto+Sans+SC)
# License: SIL Open Font License 1.1 (https://scripts.sil.org/OFL)
#         — Apache 2.0 compatible.
URL="https://fonts.gstatic.com/s/notosanssc/v40/k3kCo84MPvpLmixcA63oeAL7Iqp5IZJF9bmaG9_FnYw.ttf"

# --- idempotency check -----------------------------------------------------
if [ -f "$FONT_FILE" ]; then
  CUR_SIZE="$(stat -c%s "$FONT_FILE")"
  if [ "$CUR_SIZE" -ge "$MIN_SIZE_BYTES" ]; then
    echo "  ✓ font already present: $FONT_FILE ($CUR_SIZE bytes)"
    exit 0
  fi
  echo "  ! font present but too small ($CUR_SIZE bytes); re-downloading"
  rm -f "$FONT_FILE"
fi

# --- download ---------------------------------------------------------------
mkdir -p "$FONT_DIR"
TMP_FILE="$(mktemp "$FONT_DIR/.NotoSansCJKsc-Regular.XXXXXX.otf")"
# shellcheck disable=SC2064
trap "rm -f '$TMP_FILE'" EXIT

echo "  ↓ downloading $URL"
if ! curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP_FILE" "$URL"; then
  echo "  ✗ download failed (network or HTTP error)" >&2
  echo "    verify the URL is still valid: $URL" >&2
  exit 1
fi

# --- validate --------------------------------------------------------------
ACTUAL_SIZE="$(stat -c%s "$TMP_FILE")"
if [ "$ACTUAL_SIZE" -lt "$MIN_SIZE_BYTES" ]; then
  echo "  ✗ downloaded file is too small ($ACTUAL_SIZE bytes; expected > $MIN_SIZE_BYTES)" >&2
  echo "    check that the URL still points to NotoSansCJKsc-Regular.otf" >&2
  exit 1
fi

# TTF magic: first 4 bytes should be 0x00010000 ("\x00\x01\x00\x00" in little-endian
# file read as bytes). TrueType-flavored TTFs (which is what Noto Sans SC
# is) carry this signature. We accept any non-empty 4-byte signature
# since OTTO (OTF) is the only other common magic; the size check
# above already filtered out 404s and HTML error pages.
MAGIC="$(head -c 4 "$TMP_FILE" | od -An -t x1 | tr -d ' \n')"
if [ -z "$MAGIC" ] || [ "${#MAGIC}" -lt 8 ]; then
  echo "  ✗ downloaded file is too small to inspect (magic: $MAGIC)" >&2
  exit 1
fi
case "$MAGIC" in
  00010000) ;;  # TTF / TrueType
  4f54544f)   # OTTO / OTF — we do not embed OTF (fpdf can't parse it)
    echo "  ✗ downloaded file is OTF (magic: OTTO); fpdf's UTF8 parser rejects OTF" >&2
    echo "    check that the URL still points to a .ttf file" >&2
    exit 1
    ;;
  *)
    echo "  ✗ downloaded file has unexpected magic bytes: $MAGIC" >&2
    echo "    check that the URL still points to NotoSansSC-Regular.ttf" >&2
    exit 1
    ;;
esac

# --- land atomically --------------------------------------------------------
mv "$TMP_FILE" "$FONT_FILE"
trap - EXIT
echo "  ✓ downloaded: $FONT_FILE ($ACTUAL_SIZE bytes)"
