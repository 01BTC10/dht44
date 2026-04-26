#!/usr/bin/env bash
#
# Localhost round-trip: two embedded libbep44 nodes cross-bootstrap,
# one publishes a mutable item, the other retrieves and verifies it.
# No public DHT, no real bootstrap routers — pure local test.
#
# Topology:
#                                       127.0.0.1
#   +-------------------+              +-------------------+
#   | Producer (port A) | ---put---->  | Storer  (port B)  |
#   +-------------------+              +-------------------+
#                                              ^
#   +-------------------+                      |
#   | Consumer (port C) | --------get----------+
#   +-------------------+
#
# Producer's put resolves through the storer — the only peer either of
# them know. Consumer cross-bootstraps from the storer, runs get,
# verifies the value matches.

set -euo pipefail

# Loopback (127.x) is treated as 'martian' by jech/dht by default — so on a
# stock build two embedded nodes on the same host silently drop each other's
# packets. The vendored copy of jech/dht honors this env var to opt out for
# tests; see vendor/jech-dht/PROVENANCE.md.
export DHT_ALLOW_LOOPBACK=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER="$REPO_ROOT/tests/lib_driver"

if [[ ! -x "$DRIVER" ]]; then
    echo "FAIL: $DRIVER not built. Run 'make tests/lib_driver' first." >&2
    exit 2
fi

TMP="$(mktemp -d -t libbep44_int_XXXXXX)"
PIDS=()
cleanup() {
    set +e
    for p in "${PIDS[@]}"; do kill -KILL "$p" 2>/dev/null; done
    if [[ "${KEEP_TMP:-0}" != 1 ]]; then rm -rf "$TMP"
    else echo "(keeping $TMP)"; fi
}
trap cleanup EXIT

PORT_STORER=18831
PORT_PRODUCER=18832
PORT_CONSUMER=18833
VALUE='hello-from-libbep44'

mkdir -p "$TMP/storer" "$TMP/producer" "$TMP/consumer"

echo "==> generating key"
"$DRIVER" keygen --out "$TMP/key.json" >"$TMP/pk.hex"

echo "==> starting storer on :$PORT_STORER"
DHT_DEBUG=${DHT_DEBUG:-} "$DRIVER" serve \
    --port "$PORT_STORER" --state "$TMP/storer" \
    --seconds 60 \
    >"$TMP/storer.log" 2>&1 &
PIDS+=($!)
sleep 1

echo "==> producer puts (peer=storer)"
"$DRIVER" put \
    --port "$PORT_PRODUCER" --state "$TMP/producer" \
    --key "$TMP/key.json" \
    --seq 1 --value "$VALUE" \
    --peer "127.0.0.1:$PORT_STORER" \
    --seconds 8 \
    >"$TMP/put.out" 2>"$TMP/put.err" || {
        echo "FAIL: producer put exited non-zero"
        cat "$TMP/put.err"
        exit 1
    }
cat "$TMP/put.out"
grep -q '^acks=[1-9]' "$TMP/put.out" || {
    echo "FAIL: producer reported no acks"
    cat "$TMP/put.err"
    exit 1
}

echo "==> consumer gets (peer=storer)"
"$DRIVER" get \
    --port "$PORT_CONSUMER" --state "$TMP/consumer" \
    --pk-from "$TMP/key.json" \
    --peer "127.0.0.1:$PORT_STORER" \
    --seconds 8 \
    >"$TMP/get.out" 2>"$TMP/get.err" || {
        echo "FAIL: consumer get exited non-zero"
        cat "$TMP/get.err"
        cat "$TMP/get.out"
        exit 1
    }

# Driver echoes the bencoded value (e.g. "19:hello-from-libbep44").
EXPECTED_BENCODED="${#VALUE}:$VALUE"
GOT="$(head -1 "$TMP/get.out")"
if [[ "$GOT" != "$EXPECTED_BENCODED" ]]; then
    echo "FAIL: value mismatch"
    echo "  expected: $EXPECTED_BENCODED"
    echo "  got:      $GOT"
    cat "$TMP/get.err"
    exit 1
fi

echo "==> ok: lib_roundtrip"
