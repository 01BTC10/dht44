# vendor/

Third-party code, vendored.

## `jech-dht/`

Git submodule of [`jech/dht`](https://github.com/jech/dht), a Kademlia DHT
implementation in C.

Tracked from this fork: `http://ds1621.tail7aed4e.ts.net:3000/r2d2/dht`.

**Do not edit files inside `jech-dht/`.** It is an external dependency; local
patches would conflict with upstream and aren't tracked by this repo's history
(only the submodule pointer is). If a fix is needed, push it to the fork and
bump the submodule pointer.

### What we use from it

- Public API in `vendor/jech-dht/dht.h`: `dht_init`, `dht_periodic`, `dht_nodes`,
  `dht_get_nodes`, `dht_ping_node`, `dht_insert_node`, `dht_search`, `dht_uninit`.
- `vendor/jech-dht/dht.c` is compiled as part of `dht44` (see root `Makefile`).

### What we provide back to it

jech/dht expects the host program to define four symbols (declared in `dht.h`).
These live in `src/dht_wrap.c`:

- `dht_sendto` — alias for `sendto(2)`.
- `dht_blacklisted` — return 0.
- `dht_hash` — EVP SHA-1 of three concatenated buffers.
- `dht_random_bytes` — `randombytes_buf` from libsodium.

`dht_gettimeofday` is **not** in this list — jech/dht defines it as a macro on
non-Windows (`dht.c:76`).

### Updating

```sh
cd vendor/jech-dht
git fetch origin
git checkout <new-commit>
cd ../..
git add vendor/jech-dht
git commit -m "vendor: bump jech/dht to <short-sha>"
```
