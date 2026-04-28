#!/usr/bin/env bash
#
# Install / refresh every systemd unit dht44 needs on the host.
# Run with: sudo /home/r2d2/dht44-crawler/scripts/install-systemd.sh
#
# Idempotent — safe to re-run after editing any unit in deploy/systemd/.
# It backs up the existing unit, installs the new one, daemon-reloads,
# and re-enables timers / the main service. Only restarts dht44.service
# on demand (RESTART_DAEMON=1) so unrelated unit edits don't bounce the
# crawler.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/systemd"
DST=/etc/systemd/system
RESTART_DAEMON="${RESTART_DAEMON:-0}"

log() { printf '[install-systemd] %s\n' "$*"; }

declare -A KIND=(
    [dht44.service]=daemon
    [dht44-og.service]=oneshot
    [dht44-og.timer]=timer
    [dht44-reputation.service]=oneshot
    [dht44-reputation.timer]=timer
    [dht44-greynoise.service]=oneshot
    [dht44-greynoise.timer]=timer
)

for unit in "${!KIND[@]}"; do
    [ -f "$SRC/$unit" ] || { log "missing source: $SRC/$unit"; exit 1; }
    if [ -f "$DST/$unit" ] && ! cmp -s "$SRC/$unit" "$DST/$unit"; then
        cp -a "$DST/$unit" "$DST/$unit.bak.$(date +%Y%m%d-%H%M%S)"
    fi
    install -m 0644 "$SRC/$unit" "$DST/$unit"
    log "installed $unit"
done

systemctl daemon-reload

# Enable + start timers (the main service is enabled but we don't auto-
# restart it unless explicitly asked).
for unit in "${!KIND[@]}"; do
    case "${KIND[$unit]}" in
        timer)   systemctl enable --now "$unit" ;;
        daemon)  systemctl enable        "$unit"
                 if [ "$RESTART_DAEMON" = "1" ]; then
                     systemctl restart "$unit"
                 fi
                 ;;
    esac
done

systemctl list-timers --no-pager | grep -E 'dht44(-og|-reputation|-greynoise)' || true
echo "---"
systemctl is-active dht44 && systemctl is-enabled dht44 || true

log "done"
log "next steps:"
log "  - first reputation refresh:  sudo systemctl start dht44-reputation.service"
log "  - GreyNoise key (optional):  sudo install -m 0600 -D /dev/null /etc/dht44/greynoise.token"
log "                               then echo YOUR_KEY | sudo tee /etc/dht44/greynoise.token >/dev/null"
log "  - bounce daemon when ready:  sudo systemctl restart dht44"
