#!/usr/bin/env bash
# Two daemons on localhost cross-bootstrap; immutable put on A, get on B.
set -euo pipefail
cd "$(dirname "$0")"
source ./common.sh

PORT_A=37881
PORT_B=37882

echo "==> starting daemon A on port $PORT_A"
start_daemon a "$PORT_A"
wait_for_socket a

echo "==> starting daemon B on port $PORT_B (bootstrap to A)"
start_daemon b "$PORT_B" --bootstrap "127.0.0.1:$PORT_A"
wait_for_socket b

# Wait for routing tables to populate. The daemon's bootstrap-retry loop
# re-pings every 2 s while the table is empty; node_good takes effect once
# a peer has replied to one of OUR pings (not just sent us one). 12 s
# upper bound — typically converges in 4–6 s.
echo "==> waiting for routing tables (good+dubious > 0 on both)"
for i in {1..24}; do
    sleep 0.5
    A_STATUS=$(client a status 2>/dev/null || true)
    B_STATUS=$(client b status 2>/dev/null || true)
    A_GOOD=$(echo "$A_STATUS" | grep -oE 'good_nodesi[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
    B_GOOD=$(echo "$B_STATUS" | grep -oE 'good_nodesi[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
    A_DUB=$(echo "$A_STATUS" | grep -oE 'dubious_nodesi[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
    B_DUB=$(echo "$B_STATUS" | grep -oE 'dubious_nodesi[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
    A_TOTAL=$((A_GOOD + A_DUB))
    B_TOTAL=$((B_GOOD + B_DUB))
    echo "    A: good=$A_GOOD dub=$A_DUB   B: good=$B_GOOD dub=$B_DUB"
    if [[ "$A_TOTAL" -gt 0 && "$B_TOTAL" -gt 0 ]]; then break; fi
done

echo "==> A: put-immutable hello-from-A"
PUT_OUT=$(client a put-immutable "hello-from-A" 2>&1)
echo "$PUT_OUT"
TARGET="$(echo "$PUT_OUT" | head -n1 | awk '{print $1}')"
ACKS="$(echo "$PUT_OUT" | head -n1 | sed -nE 's/.*acks=([0-9]+).*/\1/p')"
if [[ -z "$TARGET" ]]; then
    echo "FAIL: no target hex in put output" >&2
    dump_logs_on_fail
    exit 1
fi
echo "    target=$TARGET acks=${ACKS:-?}"

echo "==> B: get --target $TARGET"
sleep 0.5
GET_OUT="$(client b get --target "$TARGET" 2>&1)"
echo "$GET_OUT"

if [[ "$GET_OUT" == *"hello-from-A"* ]]; then
    echo "==> PASS: round-trip succeeded"
    exit 0
fi

echo "FAIL: B did not retrieve A's value" >&2
dump_logs_on_fail
exit 1
