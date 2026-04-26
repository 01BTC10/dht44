# vendor/jech-dht

This directory is a vendored copy of [`jech/dht`](https://github.com/jech/dht),
the Kademlia BitTorrent DHT implementation by Juliusz Chroboczek. License is
MIT (see `LICENCE` in this directory) and is preserved unchanged.

## Provenance

Forked at upstream commit predating this snapshot, with **two local patches**
on top:

- `Add dht_closest_nodes for target-sorted XOR-distance lookup` —
  introduces `dht_closest_nodes(target, af, sin/sin6, ids, max)`. Walks all
  buckets, sorts good nodes by XOR distance to `target`, and returns up to
  `max` paired (id, addr) entries. Used by `src/dht_wrap.c` for BEP 44 /
  generic Kademlia closest-node searches; without it two daemons querying
  the same target converge to disjoint top-K sets and cross-node retrieval
  breaks. Patch is purely additive — no upstream symbol or behaviour was
  modified.

- `is_martian honors DHT_ALLOW_LOOPBACK env var` — when the env var is
  set, 127.0.0.0/8 is no longer treated as a martian source so two
  libbep44 instances on the same host can round-trip during
  integration tests. Default behaviour is unchanged. The check is
  cached after the first call so getenv runs once per process. Used
  by `tests/integration/lib_roundtrip.sh`.

This was previously a git submodule pointing at a private fork. It was
inlined as plain tracked files so cloning the project no longer requires
`--recurse-submodules` and doesn't pull from the private fork host.

## Re-syncing with upstream

Upstream `jech/dht` is mature and slow-moving. To pull a newer upstream
revision: clone `github.com/jech/dht` to a scratch dir, copy `dht.c` and
`dht.h` over the files here, then re-apply the `dht_closest_nodes` addition
(diff visible in this project's git history under `vendor/jech-dht/`).
