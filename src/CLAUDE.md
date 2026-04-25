# src/

All `dht44` source code. See the project root [`CLAUDE.md`](../CLAUDE.md) for the
overall design, BEP 44 protocol notes, and coding conventions.

## Files

| File | Layer | Responsibility |
|---|---|---|
| `main.c` | — | argv dispatch to `cmd_*` |
| `commands.h` | — | `cmd_*` prototypes |
| `bencode.{c,h}` | 1 | bencode encoder + decoder; strict dict-key ordering |
| `bep44.{c,h}` | 2 | target hashing, signable bytes, sign/verify, KRPC builders |
| `state.{c,h}` | 3 | `~/.dht44/` persistence (key, node_id, nodes, items, lock) |
| `cmd_key.c` | 4 | `keygen`, `pubkey`, `target` (no network, no daemon) |
| `dht_wrap.{c,h}` | 5 | jech/dht glue, bind, bootstrap, packet peek dispatch |
| `lookup.{c,h}` | 6 | iterative closest-node lookup (α=3, top-k=8) |
| `ipc.{c,h}` | 7 | UNIX socket framing for client↔daemon |
| `upnp.{c,h}` | 8 | miniupnpc IGD port mapping (best-effort, non-fatal) |
| `cmd_daemon.c` | 9 | daemon event loop, republish timer, inbound serve, optional crawl + observe + web |
| `cmd_get.c` | 10 | thin CLI: derive target, ask daemon, verify locally |
| `cmd_put.c` | 10 | thin CLI: sign locally, hand signed bytes to daemon |
| `crawl.{c,h}` | 11 | active crawl workers (find_node + BEP 51) with per-worker shortlists |
| `liveness.{c,h}` | 11 | paced sweeper that re-pings every observed peer + 7-day pruner |
| `observe.{c,h}` | 11 | sink that mines every packet into peers/queries/infohashes/bep44 |
| `db.{c,h}` | 11 | sqlite3 store at `$DHT44_HOME/observe.db`; JSON readouts via jansson |
| `http_ws.{c,h}` | 11 | libwebsockets HTTP + WS server; serves the React bundle from `--web-static` |

`cmd_*` files exist as stubs from commit 1 so `main.c` links; each is filled in at
its layer's commit.

## Conventions reminder

- Log to `stderr` with `[dht44:<module>]` tag.
- `static` anything not exported in a header.
- Fixed-size arrays for crypto material (`uint8_t pk[32]`, `sig[64]`, `target[20]`).
- `sodium_memzero` on secret key material before free/exit.
- Error returns: `int`, `0` OK, negative = failure. CLI maps to exit codes 0/1/2/3/4/5
  per the root `CLAUDE.md`.
- Hot-path parsing (e.g. `bencode_peek`) avoids heap; full decoders use a single
  arena freed in one call.

## Adding a new subcommand

1. Add prototype to `commands.h`.
2. Implement in a `cmd_*.c` file (or extend an existing one).
3. Register the dispatch line in `main.c`.
4. Update the usage string in `main.c` and the table in the root README.
