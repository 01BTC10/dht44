#!/usr/bin/env bash
#
# Refresh the reputation lists the daemon loads at boot:
#   * bt_level1.p2p — community-curated BitTorrent-monitor IP ranges,
#     formatted as "Description:start_ip-end_ip" per line. Sourced from
#     a public mirror of the bt_level1 list (the original iblocklist.com
#     copy is paywalled).
#   * tor-exits.txt — current Tor exit relays, one IP per line, from
#     check.torproject.org/torbulkexitlist.
#
# After both are refreshed, the daemon is restarted so reputation.c
# picks up the new ranges. (No SIGHUP path in v1.)
#
# Driven by deploy/systemd/dht44-reputation.timer (daily).
# Manual run:  sudo /home/r2d2/dht44-crawler/scripts/refresh-reputation.sh
set -euo pipefail

DEST="${DHT44_REPUTATION_DIR:-/var/lib/dht44/reputation}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '[refresh-reputation] %s\n' "$*"; }

mkdir -p "$DEST"

# bt_level1 — try the canonical community mirrors in order.
BT_URL_PRIMARY='https://github.com/Naunter/BT_BlockLists/raw/master/bt_blocklists.gz'
BT_URL_FALLBACK='https://www.iblocklist.com/list.php?list=bt_level1&fileformat=p2p&archiveformat=gz'

log "fetching bt_level1.p2p"
if curl -sSL --max-time 60 -o "$TMP/bt.gz" "$BT_URL_PRIMARY"; then
    :
else
    log "primary mirror failed, trying fallback"
    curl -sSL --max-time 60 -o "$TMP/bt.gz" "$BT_URL_FALLBACK"
fi
gunzip -t "$TMP/bt.gz" 2>/dev/null || {
    # Some mirrors return plain text already.
    mv "$TMP/bt.gz" "$TMP/bt_level1.p2p"
}
[ -f "$TMP/bt_level1.p2p" ] || gunzip -c "$TMP/bt.gz" > "$TMP/bt_level1.p2p"
LINES=$(wc -l < "$TMP/bt_level1.p2p")
[ "$LINES" -ge 100 ] || { log "ERROR: bt_level1.p2p has $LINES lines, refusing"; exit 1; }
install -m 0644 "$TMP/bt_level1.p2p" "$DEST/bt_level1.p2p"
log "bt_level1.p2p: $LINES lines installed"

# Tor exit list.
log "fetching tor-exits.txt"
curl -sSL --max-time 30 -o "$TMP/tor.txt" \
    'https://check.torproject.org/torbulkexitlist'
TOR_LINES=$(grep -cE '^[0-9a-fA-F:.]' "$TMP/tor.txt" || true)
[ "$TOR_LINES" -ge 100 ] || { log "ERROR: tor-exits has $TOR_LINES lines, refusing"; exit 1; }
install -m 0644 "$TMP/tor.txt" "$DEST/tor-exits.txt"
log "tor-exits.txt: $TOR_LINES lines installed"

# Restart the daemon so reputation.c reloads. systemctl is-active will
# fail with a non-zero exit if the daemon isn't installed (e.g. dev
# checkout); we tolerate that.
if systemctl is-active --quiet dht44; then
    log "restarting dht44 to reload lists"
    systemctl restart dht44
else
    log "dht44 not running; skipped restart"
fi

log "done"
