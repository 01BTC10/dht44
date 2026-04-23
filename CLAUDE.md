# CLAUDE.md — `dht44`

CLI tool for storing and retrieving [BEP 44](https://www.bittorrent.org/beps/bep_0044.html)
items (mutable + immutable) on the BitTorrent Mainline DHT. C, built on
[`jech/dht`](https://github.com/jech/dht) as the Kademlia substrate. Ed25519 via
libsodium, SHA-1 via OpenSSL EVP, NAT traversal via miniupnpc.

## Goals

- Single binary `dht44` driving a long-running daemon over a local UNIX socket.
- Commands: `keygen`, `pubkey`, `target`, `put`, `put-immutable`, `get`, `daemon`.
- Persist routing table, node ID, and Ed25519 key across invocations.
- No external runtime state beyond `~/.dht44/`.

## Non-goals

- Full BitTorrent client (no torrent/metadata handling).
- Payload encryption — wrap externally if needed.
- IPv6 in v1 (codepaths kept ready).
- Multiple concurrent daemons on one state dir.

## Dependencies

- `libsodium` (Ed25519, CSPRNG)
- `libssl` / `libcrypto` (SHA-1 via EVP, HMAC for token issuance)
- `libminiupnpc` (UPnP IGD port mapping for the daemon)
- `libjansson` (human-readable JSON for items on disk)
- `jech/dht` — vendored at `vendor/jech-dht/` (git submodule)

Install (Arch): `sudo pacman -S libsodium openssl miniupnpc jansson`.

## Architecture: client/daemon split

```
   ┌─────────────────────┐                       ┌────────────────────────────┐
   │  dht44 (CLI client) │ ──UNIX socket──────▶  │  dht44 daemon              │
   │                     │  ~/.dht44/sock        │                            │
   │ keygen/pubkey/target│  bencode-framed       │ owns UDP socket            │
   │   → local, no IPC   │  length-prefixed      │ owns jech routing table    │
   │ put/put-immutable   │                       │ owns lookup engine + tokens│
   │   → sign locally,   │                       │ owns republish timer       │
   │     send signed     │                       │ serves inbound get/put     │
   │     payload         │                       │ persists nodes.bin every   │
   │ get → ask + verify  │                       │   5 min + on SIGINT        │
   └─────────────────────┘                       └────────────────────────────┘
```

The daemon never touches secret keys. The CLI signs locally with `-k KEYFILE`,
hands the signed bytes to the daemon, and the daemon relays + republishes them.

The CLI exits with `error: no daemon running` (exit 5) if `~/.dht44/sock` is
absent. No auto-spawn in v1.

### Daemon boot sequence

1. `state_init` — ensure `~/.dht44/` (0700), `flock` the lock file.
2. Load `node_id.bin` (or generate via libsodium CSPRNG and persist).
3. `dht_wrap_init(port)` — bind UDP non-blocking, `dht_init(s, -1, node_id, "DH44")`.
4. `dht_insert_node` for every entry in `nodes.bin` (jech's "softer bootstrapping" —
   no traffic until the node is touched).
5. `upnp_init(port, lifetime)` (skip if `--no-upnp`); errors are non-fatal.
6. `ipc_listen(~/.dht44/sock)` — mode 0700.
7. After 3 s, if `dht_nodes(AF_INET, &good, ...)` reports `good < 4`, also call
   `dht_wrap_bootstrap` to ping the public routers.

### jech/dht packet interception

jech/dht implements BEP 5 but not BEP 44. We intercept inbound packets *before*
`dht_periodic()` sees them:

```
   recvfrom(sock)
       │
       ▼
   bencode_peek(msg) → (y, q or r, t)
       │
   ┌───┴─────────────────────────────────────┐
   │                                         │
  y="q" && q∈{"get","put"}         everything else
   │                                         │
  handle_bep44_query()              dht_periodic(buf, len, ...)
   │
  y="r" && tid ∈ pending_bep44_tx   →  handle_bep44_response()
   │
  else: fall through to dht_periodic()
```

Outbound BEP 44 traffic is entirely ours: build packet → `sendto` → register
pending tx in a `(tid, peer_addr) → callback` table with timeout.

Don't pass intercepted BEP 44 packets to `dht_periodic()` — return after handling.
*Do* pass unrelated KRPC traffic (pings, find_node, get_peers responses) so the
routing table stays fresh.

### Iterative lookup

jech/dht's internal search is oriented around info_hashes + `get_peers`, not
generic closest-node for arbitrary targets. We do our own lookup:

1. Seed with up to 8 closest nodes from jech's routing table
   (`dht_get_nodes(sin, &num4, NULL, NULL)`, then sort by XOR distance).
2. Send parallel `get` queries (α=3 in flight).
3. Parse responses: `nodes` field → insert into shortlist; `v`/`k`/`seq`/`sig` →
   collect; `token` → store per-node for subsequent `put`.
4. Repeat until top-k=8 by XOR distance have all responded or timed out.
5. For `put`: send to those top-k using each node's token.

Timeout: 15 s hard ceiling; typical convergence in 2–5 s.

## CLI

```
dht44 keygen -o KEYFILE
dht44 pubkey -k KEYFILE
dht44 target -k KEYFILE [--salt S]
dht44 put -k KEYFILE [--salt S] --seq N [--cas M] [--bencode|--string] VALUE
dht44 put-immutable [--bencode|--string] VALUE
dht44 get --target HEX              # immutable
dht44 get -k KEYFILE [--salt S]     # mutable, derives target locally
dht44 get --pubkey HEX [--salt S]   # mutable, someone else's key
dht44 daemon [--port PORT] [--republish MINUTES] [--no-upnp] [--upnp-lifetime SECONDS]
```

Exit codes: `0` success, `1` usage, `2` network/timeout, `3` crypto verify failure,
`4` DHT reject (with err code printed), `5` no daemon running.

`--string` wraps VALUE as a bencode string. `--bencode` treats VALUE as already
bencoded bytes from stdin or file. Default: `--string`.

## State directory

`~/.dht44/` (mode 0700):
- Keyfiles are JSON written by `keygen` (see CLI section). Schema:
  `{ "keys": [ { "sk": "<128 hex>", "pk": "<64 hex>", "targets": { "": "<40 hex>", "<salt>": "<40 hex>", ... } }, ... ] }`.
  `keygen` always prints the same JSON to stdout. `pubkey`/`target`/`put`/`get`
  read these files via `state_load_key`, which extracts `keys[0].sk` (or just
  `keys[0].pk` for derivation-only commands).
- `node_id.bin` — 20 B DHT node ID. **Persist across runs** — rotating it destroys
  routing table presence.
- `nodes.bin` — compact node info list (a few hundred entries) for warm start.
  Saved every 5 min and on SIGINT.
- `items/<hex-target>.json` — items the daemon stores for republish + inbound
  serve. Human-readable JSON; binary fields are hex-encoded. Mutable items
  carry `mutable:true, pk, seq, salt?, sig, v`; immutable items carry
  `mutable:false, v`. Storing `pk` lets the daemon return a fully-verifiable
  mutable response on inbound `get` (without `pk`, third-party requesters
  can't validate the signature).
- `sock` — UNIX socket the daemon listens on. Removed on clean shutdown.
- `lock` — `flock`-based mutex so a daemon and a CLI command don't collide.

## Bootstrap routers

Resolved via `getaddrinfo`, fed to `dht_ping_node()` if `dht_nodes()` is sparse:
- `router.bittorrent.com:6881`
- `dht.transmissionbt.com:6881`
- `router.utorrent.com:6881`
- `router.bitcomet.com:6881`

Wait until routing table reports ≥ 10 good nodes before declaring readiness.
Give up after 30 s.

## BEP 44 gotchas

Easy to miss, will bite:

1. **Target**: `SHA1(pubkey ‖ salt)` — raw byte concat, no length prefix, no
   separator.
2. **Signable bytes**: `[4:salt<L>:<salt>]3:seqi<seq>e1:v<v_bencoded>` —
   concatenated bencode key-value pairs, **no wrapping dict**. Sign the wire
   encoding of `v` (`5:hello`), not the raw payload (`hello`).
3. **Bencode dict key order**: strict alphabetical. `a` sub-dict:
   `id, k, salt, seq, sig, token, v`. Outer: `a, q, t, y`. Any other order =
   rejected.
4. **Value limit**: 1000 bytes for `v` (bencoded), not the whole message.
5. **Salt limit**: ≤ 64 bytes.
6. **Seq**: strictly monotonic. Replacing requires `new_seq > stored_seq`.
   `seq == stored_seq` is rejected.
7. **CAS**: optional `cas` in put = expected current seq. Mismatch → err 301.
8. **Error codes to handle**: 201 generic, 203 protocol, 205 msg too big, 206
   invalid sig, 301 CAS mismatch, 302 seq < current, 303 missing k/sig,
   304/305 salt issues, 426 immutable too big.
9. **Republish**: items expire after ~2 h. Republish every 60 min from daemon.
10. **Token scope**: each responding node issues its own token, tied to requester
    IP + target. Use the token from node X when putting to node X.

## jech/dht integration

- `dht_init(s, s6, node_id, version)` — pass IPv4 socket + `-1` for v6 (v1).
- `dht_periodic(buf, len, from, fromlen, &tosleep_ms, callback, closure)` — call
  with received data, or `NULL`/`0` for a timeout tick.
- Main loop: `select` with timeout `tosleep_ms`; on readable `recvfrom` + peek +
  dispatch.
- Callback fires on `DHT_EVENT_SEARCH_DONE` and `DHT_EVENT_VALUES` — not used by
  BEP 44 but must be non-NULL.
- We provide these symbols jech/dht calls (declared in `vendor/jech-dht/dht.h`):
  - `dht_random_bytes(void *buf, size_t n)` → `randombytes_buf`
  - `dht_hash(dst, dstlen, s1, s1len, s2, s2len, s3, s3len)` → EVP SHA-1 of
    `s1|s2|s3`, truncate/pad to `dstlen`
  - `dht_blacklisted(sa, salen)` → return 0
  - `dht_sendto(sockfd, buf, len, flags, to, tolen)` → wrap `sendto`
- jech/dht already defines `dht_gettimeofday` as a macro on non-Windows
  (`vendor/jech-dht/dht.c:76`); we don't provide it.
- IPv6 is disabled at runtime by passing `-1` for the v6 socket. There is no
  `-DHAVE_IPV6=0` build flag; the conditionals in `dht.c` are runtime.

## Makefile

```make
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += -Isrc -Ivendor/jech-dht
LDFLAGS ?= -lsodium -lcrypto -lminiupnpc

SRC := $(wildcard src/*.c) vendor/jech-dht/dht.c
OBJ := $(SRC:.c=.o)

dht44: $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

TESTS := $(patsubst %.c,%,$(wildcard tests/test_*.c))
test: $(TESTS)
	@for t in $(TESTS); do echo "==> $$t"; ./$$t || exit 1; done

tests/test_%: tests/test_%.c $(filter-out src/main.o,$(OBJ))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) dht44 $(TESTS)

.PHONY: clean test
```

## Testing strategy

Build incrementally and test each layer before moving up:

1. **Bencode**: encode/decode round-trip; reject malformed (unsorted dict keys,
   trailing data, bad lengths).
2. **BEP 44 crypto**: vectors against libtorrent's `test_dht.cpp` expected outputs.
   Target hash, signable bytes, signature must match byte-for-byte.
3. **KRPC assembly**: compare our `put` message bytes against
   [`bittorrent-dht`](https://github.com/webtorrent/bittorrent-dht) output for the
   same inputs.
4. **Local round-trip**: two `dht44 daemon` on `127.0.0.1:6881` and `127.0.0.1:6882`,
   cross-bootstrap, `put` on one, `get` on the other.
5. **Live network**: `put` small value, `sleep 10`, `get` from a different process.
   Expect ≥ 4 of 8 stores to succeed.
6. **CAS**: two racing `put`s with same seq, one with correct CAS, one without —
   second must fail with err 301.
7. **Seq regression**: `put` seq=5, then `put` seq=3 — must fail with err 302.

## Implementation order

Tackle in this sequence — each layer depends only on those above:

1. `bencode.{c,h}` + tests
2. `bep44.{c,h}` + tests
3. `state.{c,h}` (key/node_id/nodes persistence)
4. `cmd_key.c` (no network — easiest to verify)
5. `dht_wrap.{c,h}` — jech/dht init, bootstrap, packet peek dispatch
6. `lookup.{c,h}` — iterative closest-node with `get` queries
7. `ipc.{c,h}` — UNIX socket framing for client↔daemon
8. `upnp.{c,h}` — miniupnpc IGD port mapping
9. `cmd_daemon.c` — event loop + republish + serve inbound
10. `cmd_get.c` / `cmd_put.c` — thin CLI clients over IPC
11. Integration tests (local + live)

## Coding conventions

- C11, `-Wall -Wextra` clean.
- No heap allocations in hot paths where stack suffices.
- All pubkey/sig/hash buffers as fixed-size arrays, not pointers-to-malloc.
- `static` everything not exported in a header.
- Error return: `int` with 0 = OK, negative = failure; log via
  `fprintf(stderr, ...)` with a tag `[dht44:module]`.
- `sodium_memzero` on all secret key material before free/exit.
- No `strcpy`, `sprintf`, or unbounded `scanf`. Use `snprintf` with explicit cap
  checks.
- Transaction IDs: 2 bytes, random per query, tracked in a small open-addressed
  hash table keyed by `(tid, sockaddr)`.

## References

- BEP 44 spec: https://www.bittorrent.org/beps/bep_0044.html
- BEP 5 (base DHT): https://www.bittorrent.org/beps/bep_0005.html
- jech/dht: https://github.com/jech/dht
- libtorrent BEP 44 tests (oracle vectors):
  https://github.com/arvidn/libtorrent/blob/master/test/test_dht.cpp
- bittorrent-dht BEP 44 implementation:
  https://github.com/webtorrent/bittorrent-dht/blob/master/client.js
- miniupnpc: https://miniupnp.tuxfamily.org/
