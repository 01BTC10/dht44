# dht44

CLI for storing and retrieving [BEP 44](https://www.bittorrent.org/beps/bep_0044.html)
items (mutable + immutable) on the BitTorrent Mainline DHT, in C.

Built on [`jech/dht`](https://github.com/jech/dht) (Kademlia substrate, vendored at
`vendor/jech-dht/`). Ed25519 via libsodium, SHA-1 via OpenSSL EVP, NAT traversal
via miniupnpc.

## Architecture

Client/daemon split. The daemon owns the UDP socket, routing table, and lookup
engine, and runs continuously. The CLI is a thin client over a UNIX socket
(`~/.dht44/sock`, mode 0700, bencode-framed). Secret keys never leave the CLI —
puts are signed locally and the signed bytes are handed to the daemon to relay.

```
$ dht44 daemon &                       # long-running, owns the DHT node
$ dht44 keygen -o ~/.dht44/key.bin     # local, no network
$ dht44 put -k ~/.dht44/key.bin --seq 1 --string "hello"
$ dht44 get -k ~/.dht44/key.bin
hello
```

## Build (Arch Linux)

```sh
sudo pacman -S libsodium openssl miniupnpc jansson sqlite libwebsockets libmaxminddb
git clone --recurse-submodules ssh://git@ds1621.tail7aed4e.ts.net:4022/r2d2/bep44_dht.git
cd bep44_dht
make
```

If you cloned without `--recurse-submodules`:
```sh
git submodule update --init --recursive
```

The web dashboard ships as a React app under `frontend/`. To rebuild the
bundle (`frontend/dist/`):
```sh
cd frontend && npm install && npm run build
```
The repo includes a pre-built `frontend/dist/`, so this is only needed if you
edit the UI sources.

## Commands

| Command | Description | Needs daemon |
|---|---|---|
| `keygen -o KEYFILE [-k EXISTING ...] [--salt S ...]` | Generate keypair, write JSON to KEYFILE and stdout. Repeat `--salt` to precompute multiple targets; repeat `-k` to also include existing keys in the output. | no |
| `pubkey -k KEYFILE` | Print pubkey hex from a JSON keyfile | no |
| `target -k KEYFILE [--salt S]` | Print BEP 44 target hex from a JSON keyfile | no |
| `put -k KEYFILE [--salt S] --seq N [--cas M] [--bencode\|--string] VALUE` | Store mutable item | yes |
| `put-immutable [--bencode\|--string] VALUE` | Store immutable item | yes |
| `get --target HEX` | Retrieve immutable item by target | yes |
| `get -k KEYFILE [--salt S]` | Retrieve mutable item (own key) | yes |
| `get --pubkey HEX [--salt S]` | Retrieve mutable item (third-party) | yes |
| `daemon [--port N] [--republish MIN] [--no-upnp] [--upnp-lifetime SEC] [--bootstrap HOST:PORT]... [--no-routers] [--no-ipv6] [--crawl] [--crawl-workers N] [--crawl-pps N] [--web PORT] [--web-static DIR] [--geoip-city PATH] [--geoip-asn PATH]` | Run long-lived node | — |

Exit codes: `0` success, `1` usage, `2` network/timeout, `3` crypto verify failure,
`4` DHT reject (with err code printed), `5` no daemon running.

## State directory

`~/.dht44/` (mode 0700; override with `DHT44_HOME=/path`):
- Keyfiles are JSON. `dht44 keygen -o PATH` writes `PATH` (mode 0600) AND prints the same JSON to stdout. Schema:
  `{ "keys": [ { "sk": "<128 hex>", "pk": "<64 hex>", "targets": { "": "<40 hex>", "<salt>": "<40 hex>", ... } }, ... ] }`
- `node_id.bin` — 20 B persistent DHT node ID.
- `nodes.bin` / `nodes6.bin` — compact node lists (v4/v6) for warm start.
- `items/<hex-target>.json` — daemon's republish + serve queue (human-readable).
- `sock` — IPC UNIX socket (daemon-owned).
- `lock` — `flock`-based daemon mutex.
- `observe.db` — SQLite of crawler observations (only when `--crawl` or `--web` is on).
- `geoip/{city,asn}-lite.mmdb` — optional MaxMind GeoLite2 dbs (paths supplied via `--geoip-city`/`--geoip-asn`; not auto-discovered).
- `daemon.log` — recommended target for stderr when running detached.

## Crawler + web dashboard

The daemon doubles as a passive observer when `--web PORT` is passed, and as
an active crawler when `--crawl` is added. Both modes write to
`$DHT44_HOME/observe.db`.

```sh
DHT44_HOME=~/.dht44_crawler DHT44_WEB_BIND_ALL=1 \
  dht44 daemon --port 6890 --crawl --web 8877 \
    --web-static /path/to/bep44_dht/frontend/dist \
    --geoip-city ~/.dht44_crawler/geoip/city-lite.mmdb \
    --geoip-asn  ~/.dht44_crawler/geoip/asn-lite.mmdb
```

Daemon flags:
- `--crawl` — run active find_node + BEP 51 sample_infohashes workers.
- `--crawl-workers N` (default 8), `--crawl-pps N` (default 100, outbound cap).
- `--liveness` / `--no-liveness` — re-ping every observed peer on a
  rolling cadence so `/api/stats` can report alive vs stale buckets.
  **Default-on** when observation is enabled (`--web` or `--crawl`); off
  otherwise. `--no-liveness` opts out explicitly.
- `--liveness-window-hours H` (default 6) — target re-ping cadence per
  peer. The sweeper picks the oldest-pinged peer not yet re-checked
  inside this window. With 28 k peers and a 6 h window the steady-state
  rate is ~1.3 pings/sec; the cap below bounds the catch-up burst.
- `--liveness-pps N` (default 50) — outbound cap for the sweeper.
  Independent of `--crawl-pps`. Bumping the table from 28 k → 200 k
  peers takes the steady-state rate from ~1.3 to ~10 pps; the cap is
  there for the catch-up phase right after startup, not the steady state.
- `--prune-days D` (default 7, 0 = never) — delete peers whose
  `last_seen` is older than D days. The pruner runs once per hour while
  the sweeper is on.
- `--web PORT` — HTTP + WebSocket server. Without `--web-static`, serves a
  minimal built-in HTML stub (4 tabs, no charts). With `--web-static DIR`,
  serves the full React dashboard (peers / queries / infohashes / bep44 / graph,
  with top-clients and top-countries panels inside Peers).
- `--geoip-city`, `--geoip-asn` — paths to MaxMind `.mmdb` files. Without
  these, `/api/country-stats` returns `note: no geoip city db loaded` and
  the country panel is empty.
- `--bootstrap HOST:PORT` — extra bootstrap peer (repeatable).
- `--no-routers` — skip the public bootstrap routers.
- `--no-ipv6` — disable IPv6 (otherwise dual-stack).

Environment variables:
- `DHT44_HOME` — override `~/.dht44/` (use a separate dir for the crawler so
  it doesn't share state with your CLI daemon).
- `DHT44_WEB_BIND_ALL=1` — bind the web server to all interfaces; default is
  loopback only.
- `DHT_DEBUG=1` — verbose jech/dht trace.
- `DHT44_LOOKUP_DEBUG=1` — verbose iterative-lookup trace.

API endpoints (when `--web` is on):
`/api/{stats,peers,queries,infohashes,bep44,client-stats,country-stats,infohash-sources,graph}`
plus `WS /stream` for live pushes (`peers`, `queries`, `infohashes`, `bep44`,
`stats`).

`/api/stats` extras worth knowing: `peers` is cumulative (every `(ip,port)`
ever observed since the db was opened); `peers_alive_6h` and `peers_alive_24h`
count rows whose `last_seen` is within those windows — meaningful only when
the liveness sweeper is running. `peers_stale = peers - peers_alive_24h`.

`/api/peers` rows include classifier output (`crawler_score`, `crawler_class`
∈ {ok, crawler, monitor, honeypot}, `crawler_signals[]`, `crawler_reason`).
The legacy single bit `likely_crawler` (= score ≥ 1) is also still present
for the graph view.

## Layout

See [`CLAUDE.md`](CLAUDE.md) for the full design and protocol notes.

```
bep44_dht/
├── README.md
├── CLAUDE.md           ← design + protocol notes
├── Makefile
├── src/                ← project code (one CLAUDE.md inside)
├── tests/              ← unit + integration tests
└── vendor/jech-dht/    ← submodule, vendored as-is
```

## License

Project: see top-level `LICENSE` (TBD).
`vendor/jech-dht/` retains its upstream MIT license.
