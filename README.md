# dht44

CLI for storing and retrieving [BEP 44](https://www.bittorrent.org/beps/bep_0044.html)
items (mutable + immutable) on the BitTorrent Mainline DHT, in C.

Built on [`jech/dht`](https://github.com/jech/dht) (Kademlia substrate, vendored at
`vendor/jech-dht/`). Ed25519 via libsodium, SHA-1 via OpenSSL EVP, NAT traversal
via miniupnpc.

## Branches

This repo has two long-lived branches with deliberately different scope:

- **`main`** (this branch) — the lean BEP 44 implementation. A single C
  binary that runs as a daemon and a thin CLI to put/get mutable +
  immutable items. No SQLite, no web server, no observation pipeline.
  Dependencies stay small: libsodium, OpenSSL, miniupnpc, libjansson.
  Intended for embedding, scripts, and other tools that just need a
  reliable BEP 44 client. **Read on for usage.**

- **`crawler`** — active development branch. Adds, on top of the main
  daemon: an active DHT crawler (find_node + BEP 51 sample_infohashes),
  a SQLite observation store at `$DHT44_HOME/observe.db`, a
  libwebsockets HTTP+WS API, a React dashboard with peers / queries /
  infohashes / bep44 / 3D peer-graph tabs, GeoIP enrichment via MaxMind
  GeoLite2, a multi-signal crawler / monitor / honeypot classifier on
  the peers JSON, and a paced liveness sweeper + 7-day pruner that
  keeps "alive in last 6h / 24h / stale" stats meaningful. Pulls in
  extra deps (sqlite3, libwebsockets, libmaxminddb) and an `npm`-built
  frontend. See `README.md` on that branch for the full set of flags
  and the dashboard runtime invocation.

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
sudo pacman -S libsodium openssl miniupnpc jansson
git clone --recurse-submodules ssh://git@ds1621.tail7aed4e.ts.net:4022/r2d2/bep44_dht.git
cd bep44_dht
make
```

If you cloned without `--recurse-submodules`:
```sh
git submodule update --init --recursive
```

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
| `daemon [--port N] [--republish MIN] [--no-upnp] [--upnp-lifetime SEC]` | Run long-lived node | — |

Exit codes: `0` success, `1` usage, `2` network/timeout, `3` crypto verify failure,
`4` DHT reject (with err code printed), `5` no daemon running.

## State directory

`~/.dht44/` (mode 0700):
- Keyfiles are JSON. `dht44 keygen -o PATH` writes `PATH` (mode 0600) AND prints the same JSON to stdout. Schema:
  `{ "keys": [ { "sk": "<128 hex>", "pk": "<64 hex>", "targets": { "": "<40 hex>", "<salt>": "<40 hex>", ... } }, ... ] }`
- `node_id.bin` — 20 B persistent DHT node ID.
- `nodes.bin` — compact node list for warm start.
- `items/<hex-target>.json` — daemon's republish + serve queue (human-readable).
- `sock` — IPC UNIX socket (daemon-owned).
- `lock` — `flock`-based daemon mutex.

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
