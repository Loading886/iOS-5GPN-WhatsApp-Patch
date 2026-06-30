#!/usr/bin/env bash
# wa-universal-patch uninstaller — fully reverts install.sh from the recorded rollback log.
# Each recorded undo is atomic (config restore + service reload together), so replaying them in
# reverse restores the original :443 listener, the firewall, and the DNS rule file in one pass.
set -uo pipefail
STATE_DIR=/etc/wa-universal-patch
ROLLBACK_FILE="$STATE_DIR/rollback.sh"
STATE_FILE="$STATE_DIR/state.env"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$ROLLBACK_FILE" ] || { echo "nothing to uninstall (no $ROLLBACK_FILE)"; exit 0; }
[ -f "$STATE_FILE" ] && . "$STATE_FILE" 2>/dev/null || true

echo "[*] reverting wa-universal-patch…"
while IFS= read -r line; do
  [ -n "$line" ] && { eval "$line" || echo "  [warn] undo step failed: $line" >&2; }
done < <(tac "$ROLLBACK_FILE")

rm -f /usr/local/sbin/wa-patch-uninstall
up=0
for i in 1 2 3 4 5 6 7 8 9 10; do                # a Type=simple listener can take a moment to re-bind :443
  ss -ltnH 'sport = :443' 2>/dev/null | grep -q . && { up=1; break; }
  sleep 1
done
if [ "$up" = 1 ]; then
  rm -rf "$STATE_DIR"
  echo "[ok] wa-universal-patch removed; a listener is back on :443 (${LISTENER:-your SNI listener}). Gateway restored."
else
  echo "[FAIL] nothing is listening on :443 after revert — restart your SNI listener manually:" >&2
  echo "       systemctl restart ${LISTENER_SVC:-sniproxy|sing-box|haproxy}" >&2
  echo "       (backups kept in $STATE_DIR/backups, undo log in $ROLLBACK_FILE)" >&2
  exit 1
fi
