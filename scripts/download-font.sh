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
FONT_FILE="$FONT_DIR/NotoSansCJKsc-Regular.otf"
MIN_SIZE_BYTES=5000000  # ~5MB; smaller is almost certainly a 404 or wrong file

# Apache 2.0 licensed Noto Sans CJK SC — the Simplified Chinese subset of
# the full Noto Sans CJK family maintained by Google and the notofonts
# project. The full font family is also distributed under the same
# license by Adobe as "Source Han Sans".
#
# Source: https://github.com/notofonts/noto-cjk
# License: SIL Open Font License 1.1 (https://scripts.sil.org/OFL)
#         — Apache 2.0 compatible.
URL="https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf"

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

# OTF magic: first 4 bytes should be "OTTO". TrueType-flavored OTFs
# (which is what Noto CJK uses) carry this signature.
MAGIC="$(head -c 4 "$TMP_FILE")"
if [ "$MAGIC" != "OTTO" ]; then
  echo "  ✗ downloaded file is not an OTF (magic bytes: ${MAGIC:-<empty>})" >&2
  echo "    check that the URL still points to NotoSansCJKsc-Regular.otf" >&2
  exit 1
fi

# --- land atomically --------------------------------------------------------
mv "$TMP_FILE" "$FONT_FILE"
trap - EXIT
echo "  ✓ downloaded: $FONT_FILE ($ACTUAL_SIZE bytes)"
