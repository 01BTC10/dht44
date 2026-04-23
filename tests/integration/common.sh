# shellcheck shell=bash
# Helpers shared by integration tests.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DHT44="$REPO_ROOT/dht44"

if [[ ! -x "$DHT44" ]]; then
    echo "FAIL: $DHT44 not built. Run 'make' first." >&2
    exit 2
fi

TMPROOT="$(mktemp -d -t dht44_int_XXXXXX)"
DAEMON_PIDS=()

cleanup() {
    local pid
    for pid in "${DAEMON_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.3
    for pid in "${DAEMON_PIDS[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPROOT"
}
trap cleanup EXIT INT TERM

# start_daemon NAME PORT [--bootstrap host:port]...
# Daemon's logs land in $TMPROOT/<name>.log; state in $TMPROOT/<name>.
# Sets DAEMON_PID_<name> to the pid.
start_daemon() {
    local name="$1" port="$2"; shift 2
    local home="$TMPROOT/$name"
    mkdir -p "$home"
    DHT44_HOME="$home" "$DHT44" daemon \
        --port "$port" --no-upnp --no-routers \
        "$@" \
        >"$TMPROOT/$name.log" 2>&1 &
    local pid=$!
    DAEMON_PIDS+=("$pid")
    eval "DAEMON_PID_${name}=$pid"
    eval "DHT44_HOME_${name}=$home"
}

# wait_for_socket NAME
wait_for_socket() {
    local name="$1"
    local home_var="DHT44_HOME_${name}"
    local home="${!home_var}"
    local i
    for i in {1..50}; do
        [[ -S "$home/sock" ]] && return 0
        sleep 0.1
    done
    echo "FAIL: $name daemon socket never appeared" >&2
    cat "$TMPROOT/$name.log" >&2
    exit 1
}

# Run dht44 client commands against a named daemon's home dir.
client() {
    local name="$1"; shift
    local home_var="DHT44_HOME_${name}"
    DHT44_HOME="${!home_var}" "$DHT44" "$@"
}

dump_logs_on_fail() {
    echo "==== logs ====" >&2
    for f in "$TMPROOT"/*.log; do
        echo "--- $(basename "$f") ---" >&2
        cat "$f" >&2
    done
}
