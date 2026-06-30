#!/usr/bin/env bash
# wa-universal-patch — one-line bootstrap.
#
#   curl -fsSL https://raw.githubusercontent.com/Loading886/iOS-5GPN-WhatsApp-Patch/main/bootstrap.sh | sudo bash
#
# Recommended: dry-run first (detects your gateway, changes nothing), then install:
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- --detect
#   curl -fsSL .../bootstrap.sh | sudo bash
# Uninstall:
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- --uninstall
#
# It downloads the patch files to a temp dir and runs the real installer. Nothing is left behind
# except the patch itself; everything it changes is backed up and reversible (see README).
set -euo pipefail

REPO="${WA_PATCH_REPO:-Loading886/iOS-5GPN-WhatsApp-Patch}"   # overridable: WA_PATCH_REPO=you/repo
REF="${WA_PATCH_REF:-main}"
BASE="https://raw.githubusercontent.com/$REPO/$REF"

[ "$(id -u)" = 0 ] || { echo "please run with sudo/root (it edits :443 + systemd)." >&2; exit 1; }
command -v curl >/dev/null || { echo "need 'curl' installed." >&2; exit 1; }

UNINSTALL=0
for a in "$@"; do [ "$a" = "--uninstall" ] && UNINSTALL=1; done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fetch(){ curl -fsSL "$BASE/$1" -o "$tmp/$1" || { echo "download failed: $1 (from $BASE)" >&2; exit 1; }; }

if [ "$UNINSTALL" = 1 ]; then
  echo "[*] wa-universal-patch: fetching uninstaller ($REPO@$REF)…"
  fetch uninstall.sh
  exec bash "$tmp/uninstall.sh"
fi

echo "[*] wa-universal-patch: fetching ($REPO@$REF)…"
for f in wa-shim.py install.sh uninstall.sh; do fetch "$f"; done
chmod +x "$tmp/install.sh" "$tmp/uninstall.sh"
echo "[*] running installer…"
exec bash "$tmp/install.sh" "$@"
