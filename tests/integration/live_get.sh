#!/usr/bin/env bash
# Opt-in live mainline test (LIVE=1). Puts a small immutable value via a
# daemon connected to the public DHT, then reads it back from a fresh state
# dir 10 seconds later.
set -euo pipefail
cd "$(dirname "$0")"
source ./common.sh

if [[ "${LIVE:-0}" != "1" ]]; then
    echo "SKIP: set LIVE=1 to run this (touches the live mainline DHT)"
    exit 0
fi

PORT_A=39881
PORT_B=39882

# A allows public routers (no --no-routers).
DHT44_HOME="$TMPROOT/a" "$DHT44" daemon --port "$PORT_A" --no-upnp \
    >"$TMPROOT/a.log" 2>&1 &
DAEMON_PIDS+=($!); eval "DHT44_HOME_a=$TMPROOT/a"; mkdir -p "$TMPROOT/a"
wait_for_socket a

echo "==> waiting 8s for A to bootstrap to mainline"
sleep 8
client a status 2>&1 | head -1 || true

VAL="hello-mainline-$(date +%s)"
echo "==> A: put-immutable $VAL"
PUT="$(client a put-immutable "$VAL")"
echo "$PUT"
TARGET="$(echo "$PUT" | head -1 | awk '{print $1}')"

echo "==> sleep 10"
sleep 10

# Fresh daemon B on a clean state dir, also bootstrapped to mainline.
DHT44_HOME="$TMPROOT/b" "$DHT44" daemon --port "$PORT_B" --no-upnp \
    >"$TMPROOT/b.log" 2>&1 &
DAEMON_PIDS+=($!); eval "DHT44_HOME_b=$TMPROOT/b"; mkdir -p "$TMPROOT/b"
wait_for_socket b

echo "==> waiting 6s for B to bootstrap"
sleep 6

echo "==> B: get --target $TARGET"
GET="$(client b get --target "$TARGET" 2>&1 || true)"
echo "$GET"

if [[ "$GET" == *"$VAL"* ]]; then
    echo "==> PASS: live retrieval"
    exit 0
fi
echo "FAIL: B did not retrieve A's mainline value" >&2
dump_logs_on_fail
exit 1
