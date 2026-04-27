# libbep44

Embeddable C library for storing and retrieving
[BEP 44](https://www.bittorrent.org/beps/bep_0044.html) items
(mutable + immutable, signed with Ed25519) on the BitTorrent Mainline DHT.

The full peer-to-peer DHT — UDP socket, routing table, iterative
Kademlia lookup, KRPC packet handling, BEP 5 + BEP 44 wire formats —
is wrapped behind a small async API. You bring an event loop and
write four lines to publish a value:

```c
bep44_opts_t opts = { .port = 6881, .state_dir = "./state",
                      .bootstrap_routers = 1 };
bep44_ctx_t *ctx = bep44_open(&opts);
bep44_keypair_t kp; bep44_keygen(&kp);
bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                  (uint8_t *)"5:hello", 7, on_put, NULL);
while (running) bep44_step(ctx, 250);
bep44_close(ctx);
```

Built on the [`jech/dht`](https://github.com/jech/dht) Kademlia
implementation (vendored at `vendor/jech-dht/`), with two small
local patches documented in `vendor/jech-dht/PROVENANCE.md`.

This branch is the **library distribution**. The `main` branch is
the upstream `dht44` CLI/daemon — same DHT internals, different
shape. `git switch main` for the daemon flavor.

## Contents

- [Build](#build)
- [Linking](#linking)
- [Quick start](#quick-start)
- [API reference](#api-reference)
  - [Constants and types](#constants-and-types)
  - [Lifecycle](#lifecycle)
    - [`bep44_open`](#bep44_open) ·
      [`bep44_close`](#bep44_close) ·
      [`bep44_fd`](#bep44_fd) ·
      [`bep44_step`](#bep44_step) ·
      [`bep44_good_nodes`](#bep44_good_nodes) ·
      [`bep44_add_peer`](#bep44_add_peer)
  - [Keys](#keys)
    - [`bep44_keygen`](#bep44_keygen) ·
      [`bep44_keypair_from_sk`](#bep44_keypair_from_sk) ·
      [`bep44_save_key`](#bep44_save_key) ·
      [`bep44_load_key`](#bep44_load_key)
  - [Targets](#targets)
    - [`bep44_target_mutable`](#bep44_target_mutable) ·
      [`bep44_target_immutable`](#bep44_target_immutable)
  - [Operations](#operations)
    - [`bep44_put_mutable`](#bep44_put_mutable) ·
      [`bep44_put_immutable`](#bep44_put_immutable) ·
      [`bep44_get_mutable`](#bep44_get_mutable) ·
      [`bep44_get_immutable`](#bep44_get_immutable)
- [State directory](#state-directory)
- [Persistence and republish](#persistence-and-republish)
- [NAT traversal (UPnP)](#nat-traversal-upnp)
- [Threading model](#threading-model)
- [Tests](#tests)
- [License](#license)

## Build

System packages (Arch Linux):

```sh
sudo pacman -S libsodium openssl jansson miniupnpc
```

Or on Debian/Ubuntu:

```sh
sudo apt install libsodium-dev libssl-dev libjansson-dev libminiupnpc-dev
```

Build:

```sh
git clone -b libbep44 ssh://git@ds1621.tail7aed4e.ts.net:4022/r2d2/bep44_dht.git
cd bep44_dht
make           # produces libbep44.a
```

## Linking

Static archive at `libbep44.a`, public header at `include/libbep44.h`.

```sh
gcc your_app.c \
    -I/path/to/bep44_dht/include \
    /path/to/bep44_dht/libbep44.a \
    -lsodium -lcrypto -ljansson -lminiupnpc \
    -o your_app
```

The library has no runtime files of its own; everything it needs lives
in the `state_dir` you pass to `bep44_open`.

## Quick start

Save this as `quickstart.c`:

```c
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "libbep44.h"

typedef struct { int done; } put_state;
typedef struct { int done; int found; } get_state;

static void on_put(const bep44_put_result_t *r, void *u) {
    put_state *p = u; p->done = 1;
    printf("put: stored on %d node(s)\n", r->stored_count);
}
static void on_get(const bep44_get_result_t *r, void *u) {
    get_state *g = u; g->done = 1; g->found = r->found;
    if (r->found) printf("got %zu bytes (seq=%lld)\n",
                         r->value_len, (long long)r->seq);
    else          puts("not found");
}

int main(void) {
    bep44_opts_t opts = {
        .port = 6881,
        .state_dir = "./quickstart_state",
        .bootstrap_routers = 1,
    };
    bep44_ctx_t *ctx = bep44_open(&opts);
    if (!ctx) return 1;

    bep44_keypair_t kp;
    if (bep44_load_key("./quickstart_state/key.json", &kp) != 0) {
        bep44_keygen(&kp);
        bep44_save_key("./quickstart_state/key.json", &kp);
    }

    /* Block until we have enough peers to do real work. Cold-boot
     * against the public DHT takes 30s+ — don't add a time cap here
     * unless you also handle the "no peers yet" path. */
    while (bep44_good_nodes(ctx) < 4) bep44_step(ctx, 250);

    put_state put_s = { 0 };
    bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                      (uint8_t *)"5:hello", 7, on_put, &put_s);
    while (!put_s.done) bep44_step(ctx, 250);

    /* Get-after-put on a freshly-bootstrapped node is sometimes flaky:
     * our lookup may converge on different peers than the put just hit,
     * because the routing table is still warming up. The lookup itself
     * grows the routing table as a side effect, so retrying a couple
     * times reliably resolves it. (If you're testing against the live
     * mainline DHT for the first time, this is normal.) */
    for (int attempt = 0; attempt < 5; attempt++) {
        get_state get_s = { 0 };
        bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get, &get_s);
        while (!get_s.done) bep44_step(ctx, 250);
        if (get_s.found) break;
    }

    bep44_close(ctx);
    return 0;
}
```

```sh
gcc quickstart.c libbep44.a -Iinclude -lsodium -lcrypto -ljansson -lminiupnpc -o quickstart
mkdir -p quickstart_state
./quickstart
```

## API reference

### Constants and types

| Name | Value | Meaning |
|---|---|---|
| `BEP44_PK_LEN` | 32 | Ed25519 public key bytes |
| `BEP44_SK_LEN` | 64 | Ed25519 secret key bytes (libsodium combined form) |
| `BEP44_SIG_LEN` | 64 | Ed25519 signature bytes |
| `BEP44_TARGET_LEN` | 20 | SHA-1 target bytes |
| `BEP44_VALUE_MAX` | 1000 | Max bencoded value length (BEP 44 spec cap) |
| `BEP44_SALT_MAX` | 64 | Max salt length (BEP 44 spec cap) |

`bep44_ctx_t` — opaque DHT context. Created by `bep44_open`, freed by
`bep44_close`. **One per process.**

`bep44_keypair_t` — `{ uint8_t pk[32]; uint8_t sk[64]; }`. The secret
key is the libsodium 64-byte combined form (seed + pk).

`bep44_opts_t` — passed to `bep44_open`:

| Field | Type | Meaning |
|---|---|---|
| `port` | `int` | UDP port (use `0` to let the OS pick) |
| `state_dir` | `const char *` | **Required.** Where node id, warm-start nodes, and stored items are persisted |
| `bootstrap_routers` | `int` | Non-zero = ping the four public routers on open |
| `use_upnp` | `int` | Non-zero = ask the gateway to forward `port` via UPnP IGD (best-effort; failure is logged and the library continues) |
| `upnp_lifetime_sec` | `int` | UPnP lease duration; `0` defaults to 3600 |
| `republish_minutes` | `int` | Re-push every stored item on this cadence so it doesn't expire from peer caches. `0` defaults to 60. Negative disables. See [Persistence and republish](#persistence-and-republish). |

`bep44_put_result_t` — passed to put callback:

| Field | Type | Meaning |
|---|---|---|
| `success` | `int` | 1 if at least one peer stored the value |
| `stored_count` | `int` | How many peers ack'd |
| `err_code` | `int` | Non-zero if any peer returned a BEP 44 error (see codes in [BEP 44](https://www.bittorrent.org/beps/bep_0044.html)) |

`bep44_get_result_t` — passed to get callback. Pointers are valid only
inside the callback; copy if you need them to survive:

| Field | Type | Meaning |
|---|---|---|
| `found` | `int` | 1 if a value was retrieved |
| `is_mutable` | `int` | 1 if mutable, 0 if immutable |
| `pk` | `uint8_t[32]` | Public key (mutable only; verified before delivery) |
| `seq` | `int64_t` | Sequence number (mutable only) |
| `sig` | `uint8_t[64]` | Signature (mutable only) |
| `value` | `const uint8_t *` | Bencoded `v` (e.g. `"5:hello"`, not `"hello"`) |
| `value_len` | `size_t` | Length of `value` |

`bep44_put_cb` / `bep44_get_cb` — callback typedefs:

```c
typedef void (*bep44_put_cb)(const bep44_put_result_t *result, void *user);
typedef void (*bep44_get_cb)(const bep44_get_result_t *result, void *user);
```

Callbacks fire from inside `bep44_step` — never from inside the
`bep44_put_*` / `bep44_get_*` call itself.

---

### Lifecycle

#### `bep44_open`

```c
bep44_ctx_t *bep44_open(const bep44_opts_t *opts);
```

Bind the UDP socket, load (or create) the persistent node id, install
the inbound BEP 44 server, and optionally ping the public bootstrap
routers. **One context per process** — a second open in the same
process returns `NULL`.

- `opts->state_dir` is required. The directory is created (mode 0700)
  if it doesn't exist.
- `opts->port = 0` lets the OS pick an ephemeral port (useful for
  tests and short-lived clients).
- `opts->bootstrap_routers = 1` triggers `getaddrinfo` lookups of
  `router.bittorrent.com:6881` and friends, then `dht_ping_node` on
  each. Set to 0 if you're going to inject your own peers via
  [`bep44_add_peer`](#bep44_add_peer).

Returns the context handle on success, `NULL` on error.

```c
bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./libbep44_state",
    .bootstrap_routers = 1,
};
bep44_ctx_t *ctx = bep44_open(&opts);
if (!ctx) {
    fprintf(stderr, "bep44_open failed\n");
    return 1;
}
```

**Errors:**
- Returns `NULL` if `opts` or `opts->state_dir` is `NULL`.
- Returns `NULL` if the state directory can't be created.
- Returns `NULL` if a context is already open in this process.
- Returns `NULL` if the UDP port is already bound or libsodium fails
  to initialize.

---

#### `bep44_close`

```c
void bep44_close(bep44_ctx_t *ctx);
```

Persist warm-start nodes, fire any pending callbacks with
`success=0` / `found=0` so user closures can be freed, release the
UDP socket. Safe to call on `NULL` or on an already-closed context.

```c
bep44_close(ctx);
```

**Errors:** none — this call cannot fail.

---

#### `bep44_fd`

```c
int bep44_fd(const bep44_ctx_t *ctx);
```

The underlying UDP file descriptor, for integrating libbep44 into your
own `select` / `poll` / `epoll` event loop. Returns `-1` if the
context is not open.

```c
int fd = bep44_fd(ctx);
fd_set rfds;
FD_ZERO(&rfds); FD_SET(fd, &rfds);
struct timeval tv = { 0, 250 * 1000 };
if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0)
    bep44_step(ctx, 0);          /* fd is readable, drain it */
else
    bep44_step(ctx, 0);          /* timeout, just tick */
```

**Errors:** returns `-1` if `ctx` is `NULL` or closed.

---

#### `bep44_step`

```c
int bep44_step(bep44_ctx_t *ctx, int timeout_ms);
```

Drive one iteration of the event loop:

1. Run periodic DHT housekeeping (jech bucket maintenance,
   pending-tx timeouts, lookup deadlines).
2. Sleep up to `timeout_ms` waiting for an inbound UDP packet (the
   internal sleep is clamped down to whatever the next deadline
   needs, so this never oversleeps a callback).
3. Drain everything that arrived, dispatching to lookup/put/get
   transaction callbacks and the inbound BEP 44 server.

Callbacks for any pending put/get fire from inside this call. Returns
`0` on success, `-1` on a fatal socket error (the caller should
`bep44_close`).

```c
while (running) {
    if (bep44_step(ctx, 250) < 0) break;   /* fatal — close */
}
```

**Errors:**
- `-1` if `ctx` is `NULL` / closed, or if `select`/`recvfrom` returned
  a non-recoverable error.
- `0` is also returned when `select` was interrupted by a signal —
  this is benign.

---

#### `bep44_good_nodes`

```c
int bep44_good_nodes(const bep44_ctx_t *ctx);
```

Approximate number of "good" peers in the routing table — peers that
have responded to a query in the last 15 minutes. Useful as a
readiness probe before issuing your first put/get on a fresh node.

```c
/* wait until bootstrap settles, but not forever */
time_t deadline = time(NULL) + 30;
while (time(NULL) < deadline && bep44_good_nodes(ctx) < 8)
    bep44_step(ctx, 250);
```

**Errors:** returns `0` if `ctx` is `NULL` or closed (no error
distinct from "no peers yet").

---

#### `bep44_add_peer`

```c
int bep44_add_peer(bep44_ctx_t *ctx, const char *ipv4, uint16_t port);
```

Inject a known IPv4 peer into the routing table. The library sends a
ping; the peer is promoted to "good" once its pong arrives via a
subsequent `bep44_step`. Use this to bootstrap against your own DHT
node, a peer from a different discovery channel, or when running
without `bootstrap_routers`.

```c
bep44_add_peer(ctx, "203.0.113.10", 6881);
/* let the ping/pong round-trip before relying on this peer */
for (int i = 0; i < 20; i++) bep44_step(ctx, 100);
```

**Errors:**
- `-1` if `ctx` is `NULL` / closed, or if `ipv4` is `NULL`.
- `-1` if `inet_pton` rejects `ipv4` (not a dotted-quad).
- `-1` if the underlying ping send fails.

---

### Keys

#### `bep44_keygen`

```c
int bep44_keygen(bep44_keypair_t *out);
```

Generate a fresh Ed25519 keypair from the OS CSPRNG (libsodium
`randombytes_buf`). Returns `0` on success.

```c
bep44_keypair_t kp;
if (bep44_keygen(&kp) != 0) {
    fprintf(stderr, "keygen failed\n");
    return 1;
}
/* kp.pk is 32 bytes, kp.sk is 64 bytes */
```

**Errors:**
- `-1` if `out` is `NULL`.
- `-1` if libsodium fails to initialize (extremely unlikely).

---

#### `bep44_keypair_from_sk`

```c
int bep44_keypair_from_sk(bep44_keypair_t *out,
                          const uint8_t sk[BEP44_SK_LEN]);
```

Recover a full keypair from a 64-byte libsodium secret key (which
already embeds the seed and pk — this just extracts the pk and copies
the sk). Useful when your application stores secret keys in its own
format and feeds them to libbep44 at runtime.

```c
uint8_t my_sk[BEP44_SK_LEN] = { /* loaded from your vault */ };
bep44_keypair_t kp;
if (bep44_keypair_from_sk(&kp, my_sk) != 0) return 1;
/* kp.pk now matches the pk embedded in my_sk */
```

**Errors:**
- `-1` if `out` or `sk` is `NULL`.
- `-1` if libsodium can't derive a pk (corrupt sk).

---

#### `bep44_save_key`

```c
int bep44_save_key(const char *path, const bep44_keypair_t *kp);
```

Atomically write the keypair as JSON at `path`, mode 0600. The file
format is the same as the `dht44 keygen` CLI — keys live under a
`"keys": [...]` array so the file can hold multiple identities. The
value of `path` is taken verbatim; no directory creation.

```c
bep44_keypair_t kp;
bep44_keygen(&kp);
if (bep44_save_key("./state/identity.json", &kp) != 0) {
    fprintf(stderr, "save failed\n");
    return 1;
}
```

On disk:

```json
{
  "keys": [
    { "sk": "<128-hex>", "pk": "<64-hex>" }
  ]
}
```

**Errors:**
- `-1` if `path` or `kp` is `NULL`.
- `-1` if the directory containing `path` doesn't exist or isn't
  writable.
- `-1` if the atomic rename fails.

---

#### `bep44_load_key`

```c
int bep44_load_key(const char *path, bep44_keypair_t *out);
```

Read the JSON keyfile at `path`, decode the first entry's `sk`, and
recover `pk` from it. The file may contain multiple keys; only
`keys[0]` is loaded. If the file came from
[`bep44_save_key`](#bep44_save_key) or `dht44 keygen` it'll Just Work.

```c
bep44_keypair_t kp;
if (bep44_load_key("./state/identity.json", &kp) != 0) {
    /* file missing — generate a fresh one */
    bep44_keygen(&kp);
    bep44_save_key("./state/identity.json", &kp);
}
```

**Errors:**
- `-1` if `path` or `out` is `NULL`.
- `-1` if the file doesn't exist or can't be opened.
- `-1` if the file isn't valid JSON or the schema is wrong.
- `-1` if the `sk` field isn't 128 hex chars.

---

### Targets

#### `bep44_target_mutable`

```c
int bep44_target_mutable(const uint8_t pk[BEP44_PK_LEN],
                         const char *salt, size_t salt_len,
                         uint8_t target[BEP44_TARGET_LEN]);
```

Compute the BEP 44 target for a mutable item: `SHA1(pk || salt)`. Pass
`salt = NULL, salt_len = 0` for an unsalted target. Useful when you
want to publish the target out-of-band (e.g. share a link before
publishing) or when retrieving someone else's item by `(pk, salt)`.

```c
bep44_keypair_t kp;
bep44_keygen(&kp);

uint8_t target[BEP44_TARGET_LEN];
const char *salt = "messages/inbox";
bep44_target_mutable(kp.pk, salt, strlen(salt), target);

for (int i = 0; i < 20; i++) printf("%02x", target[i]);
putchar('\n');
```

**Errors:**
- `-1` if `pk` or `target` is `NULL`.
- `-1` if `salt_len > BEP44_SALT_MAX`.

---

#### `bep44_target_immutable`

```c
int bep44_target_immutable(const uint8_t *v_bencoded, size_t v_len,
                           uint8_t target[BEP44_TARGET_LEN]);
```

Compute the BEP 44 target for an immutable item: `SHA1(v_bencoded)`.
The input must already be bencoded (e.g. `"5:hello"` for the string
`hello`).

```c
const uint8_t v[] = "5:hello";
uint8_t target[BEP44_TARGET_LEN];
bep44_target_immutable(v, sizeof(v) - 1, target);
/* target now identifies "hello" in the immutable namespace */
```

**Errors:**
- `-1` if `v_bencoded` or `target` is `NULL`.
- `-1` if `v_len > BEP44_VALUE_MAX`.

---

### Operations

All four operations are **non-blocking**: they queue work and return
immediately. Completion arrives via the user-supplied callback,
fired from inside `bep44_step`. The library never calls back from
inside the queueing function itself.

#### `bep44_put_mutable`

```c
int bep44_put_mutable(bep44_ctx_t *ctx,
                      const bep44_keypair_t *kp,
                      const char *salt, size_t salt_len,
                      int64_t seq, int64_t cas,
                      const uint8_t *v_bencoded, size_t v_len,
                      bep44_put_cb cb, void *user);
```

Sign a mutable item locally with `kp.sk`, run an iterative lookup to
find the eight closest peers to `SHA1(pk || salt)`, and store the
signed item on each one. The lookup hard timeout is 15 s; the
callback fires once all per-peer puts have settled (ack, error, or
timeout) or the lookup itself timed out.

- `seq` must be **strictly greater** than any previously-stored seq
  for this `(pk, salt)` target. Peers with a higher current seq will
  reject the put with err 302.
- `cas = -1` skips compare-and-swap. Otherwise it must equal the
  currently-stored seq, or peers reject with err 301.
- `v_bencoded` must already be bencoded — `"5:hello"` for the string
  `"hello"`. Hard cap at `BEP44_VALUE_MAX = 1000` bytes.
- `salt_len <= BEP44_SALT_MAX = 64`. Pass `salt = NULL, salt_len = 0`
  for unsalted.

```c
typedef struct { int done; int acks; } put_state;
static void on_put(const bep44_put_result_t *r, void *u) {
    put_state *ps = u;
    ps->done = 1;
    ps->acks = r->stored_count;
}

bep44_keypair_t kp;
bep44_keygen(&kp);

const uint8_t v[] = "5:hello";
put_state ps = { 0 };
bep44_put_mutable(ctx, &kp,
                  /*salt=*/ NULL, 0,
                  /*seq=*/ 1,
                  /*cas=*/ -1,
                  v, sizeof(v) - 1,
                  on_put, &ps);
while (!ps.done) bep44_step(ctx, 250);
printf("stored on %d peers\n", ps.acks);
```

**Errors:**
- `-1` if any pointer arg is `NULL`, `ctx` is closed, `seq < 0`,
  `v_len == 0`, `v_len > BEP44_VALUE_MAX`, or
  `salt_len > BEP44_SALT_MAX`.
- `-1` if all 16 in-flight put slots are in use (reschedule and try
  again later).
- `-1` if signing fails (sk corrupt or signable buffer overflow).
- `-1` if `lookup_start` returns `NULL` (all 8 lookup slots in use).

The callback's `result.success` is `0` if no peer ack'd; check
`result.err_code` for the most recent BEP 44 error code (e.g. 301
CAS mismatch, 302 seq regression).

---

#### `bep44_put_immutable`

```c
int bep44_put_immutable(bep44_ctx_t *ctx,
                        const uint8_t *v_bencoded, size_t v_len,
                        bep44_put_cb cb, void *user);
```

Like `bep44_put_mutable` but for immutable items. Target is
`SHA1(v_bencoded)` — implicit, you don't pass it. No key, no
signature, no seq/cas. The same content always lands at the same
target.

```c
typedef struct { int done; } put_state;
static void on_put(const bep44_put_result_t *r, void *u) {
    put_state *ps = u; ps->done = 1;
    printf("immutable: %d peers stored\n", r->stored_count);
}

const uint8_t v[] = "12:hello, world";
put_state ps = { 0 };
bep44_put_immutable(ctx, v, sizeof(v) - 1, on_put, &ps);
while (!ps.done) bep44_step(ctx, 250);
```

**Errors:**
- `-1` if `ctx`, `v_bencoded` is `NULL`, or `ctx` is closed.
- `-1` if `v_len == 0` or `v_len > BEP44_VALUE_MAX`.
- `-1` if all in-flight put slots are in use.
- `-1` if `lookup_start` fails.

---

#### `bep44_get_mutable`

```c
int bep44_get_mutable(bep44_ctx_t *ctx,
                      const uint8_t pk[BEP44_PK_LEN],
                      const char *salt, size_t salt_len,
                      bep44_get_cb cb, void *user);
```

Fetch the latest mutable item under `SHA1(pk || salt)`. The library
runs an iterative lookup, collects up to 4 candidate values from the
closest peers, and picks the one with the highest `seq` whose
signature verifies under `pk`. Items signed by a different key, or
unsigned/forged values, are silently discarded.

`result.found = 0` if nothing was retrieved or if every retrieved
candidate failed signature verification.

```c
typedef struct {
    int done;
    char value[1024]; size_t vlen;
    int64_t seq;
} get_state;

static void on_get(const bep44_get_result_t *r, void *u) {
    get_state *gs = u; gs->done = 1;
    if (r->found && r->value_len < sizeof(gs->value)) {
        memcpy(gs->value, r->value, r->value_len);
        gs->vlen = r->value_len;
        gs->seq = r->seq;
    }
}

uint8_t pk[BEP44_PK_LEN] = { /* the publisher's public key */ };
get_state gs = { 0 };
bep44_get_mutable(ctx, pk, /*salt=*/ NULL, 0, on_get, &gs);
while (!gs.done) bep44_step(ctx, 250);

if (gs.vlen) printf("got seq=%lld, %zu bencoded bytes\n",
                    (long long)gs.seq, gs.vlen);
else         puts("not found");
```

**Errors:**
- `-1` if `ctx`, `pk` is `NULL`, or `ctx` is closed.
- `-1` if `salt_len > BEP44_SALT_MAX`.
- `-1` if all in-flight get slots are in use.
- `-1` if `lookup_start` fails.

The callback receives `result.found = 0` if the lookup found values
under the target but none were signed by `pk` — defends against
unrelated peers serving the same target hash.

---

#### `bep44_get_immutable`

```c
int bep44_get_immutable(bep44_ctx_t *ctx,
                        const uint8_t target[BEP44_TARGET_LEN],
                        bep44_get_cb cb, void *user);
```

Fetch an immutable item by precomputed target. No signature
verification (immutable items aren't signed); the integrity property
is just `SHA1(v_bencoded) == target`, which is a property of the
content itself, not of the network. The library does NOT verify the
hash currently — if you need that guarantee, recompute
`bep44_target_immutable(result.value, result.value_len)` and compare.

```c
typedef struct { int done; size_t vlen; uint8_t buf[1024]; } get_state;
static void on_get(const bep44_get_result_t *r, void *u) {
    get_state *gs = u; gs->done = 1;
    if (r->found && r->value_len < sizeof(gs->buf)) {
        memcpy(gs->buf, r->value, r->value_len);
        gs->vlen = r->value_len;
    }
}

uint8_t target[BEP44_TARGET_LEN] = { /* SHA1(v_bencoded) */ };
get_state gs = { 0 };
bep44_get_immutable(ctx, target, on_get, &gs);
while (!gs.done) bep44_step(ctx, 250);
```

**Errors:**
- `-1` if `ctx`, `target` is `NULL`, or `ctx` is closed.
- `-1` if all in-flight get slots are in use.
- `-1` if `lookup_start` fails.

---

## State directory

The `state_dir` you pass to `bep44_open` accumulates:

- `node_id.bin` — 20-byte persistent DHT node ID. Generated on first
  open and never rotated. Deleting it makes you a different node to
  the rest of the network and discards all your routing-table
  presence.
- `nodes.bin` — compact IPv4 node list saved on close. On the next
  `bep44_open` these are inserted as warm-bootstrap peers, so a
  restart converges faster.
- `items/<40-hex-target>.json` — items that other peers asked you to
  store, plus any items you've put yourself. The library serves these
  to inbound `get` queries from other peers and uses them to honor
  CAS / seq invariants on inbound `put`.

You can keep a keyfile alongside (e.g. `state_dir/key.json`), but
that's just convention — `bep44_save_key` / `bep44_load_key` accept
arbitrary paths.

## Persistence and republish

BEP 44 items are not permanent on the network. Storers expire them
after **about 2 hours** unless somebody re-pushes them. If you publish
once and then sleep for 3 hours, your value is gone — even though
your node is still up.

Two consequences in practice:

1. **`put` then immediate `get` from a fresh process** is unreliable.
   The 8 closest peers your put hit may not be in the get's routing
   table yet, so the lookup converges elsewhere. (You'll see
   "stored on 15 nodes" then `not found` from a separate process.)
2. **Long-lived publication needs a long-lived process.** Whoever
   wants their value to stay reachable has to keep re-pushing it.

The library does this for you when `bep44_step` is called regularly
in a long-running process:

- Every put — yours via `bep44_put_*` and any peer-origin put your
  inbound server accepts — is persisted to `state_dir/items/<target>.json`.
- Every `republish_minutes` (default 60) the library walks that
  directory and re-issues each item's put. For peer-origin items it
  re-emits the stored signed bytes verbatim, so no key is needed.
  For self-origin items it does the same — the signature you made at
  put time is still valid because the seq, value, and salt didn't
  change.

Tuning notes:

- The default of 60 minutes is intentionally well below the ~2h peer
  expiry. Going lower than ~15 min is wasteful; going above 90 min
  flirts with the expiry window.
- Set `opts.republish_minutes = -1` if you really want to opt out
  (e.g. you're the publisher *and* you're going to call `bep44_put_*`
  yourself on a custom schedule with bumped seq).
- **You must keep your process running and calling `bep44_step`** for
  republish to fire. A short-lived `--put` that exits immediately
  publishes once and then leaves no agent behind. If that's your
  pattern, plan to invoke the publisher again before 2h pass — or
  run a long-lived agent (the next section).

### Long-lived publisher snippet

```c
bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./state",
    .bootstrap_routers = 1,
    .use_upnp = 1,
    .republish_minutes = 60,        /* default; shown for clarity */
};
bep44_ctx_t *ctx = bep44_open(&opts);

/* Publish once. */
bep44_keypair_t kp; /* loaded or generated */
bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                  (uint8_t *)"5:hello", 7, on_put, NULL);

/* Drive the loop forever. The library republishes every 60 min on
 * its own; you don't have to call put again. */
while (running) bep44_step(ctx, 250);
```

The republish sweep runs at most 4 lookups concurrently per cycle, so
holding many items doesn't hammer the network in bursts — large
collections are spread across a few seconds.

## NAT traversal (UPnP)

If you're behind a NAT — typical for a home or office machine — your
node can reach the public DHT outbound but other peers can't reach
you inbound. That means:

- **Your puts still work** (outbound).
- **Peers can't ask you for what you've stored** (inbound). You won't
  show up in others' routing tables long-term, you can't serve as a
  storer for arbitrary peer items, and your own value lives only on
  the original 8 closest peers (with the usual ~2h expiry).

Set `opts.use_upnp = 1` and the library asks your gateway to forward
your UDP port via UPnP IGD on open, refreshes the lease every
`upnp_lifetime_sec / 2`, and tears the mapping down on `bep44_close`.
Failures (no IGD, IGD refused) are logged and non-fatal — the library
just continues without the mapping.

UPnP only works when:

- Your gateway has UPnP enabled (most home routers do; many corp
  networks don't).
- You passed a fixed `opts.port` (UPnP needs a known external port).
  `port = 0` skips UPnP since the OS-picked port would change between
  runs anyway.
- The library was linked against `libminiupnpc` (it is by default).

If UPnP fails or isn't available, options are: configure a manual
port forward on your router, run on a public IP, or accept that you
work as an outbound-only client.

## Threading model

**Single-threaded.** All public functions on `bep44_ctx_t` must be
called from the same thread, and `bep44_step` is the only place
callbacks fire.

If you need to interface with multi-threaded code, marshal calls into
the libbep44 thread (e.g. via a pipe whose read fd you `select` on
alongside `bep44_fd`). The library will not synchronize for you.

The DHT engine internals (jech) hold global state, so **only one
context per process**. A second `bep44_open` returns `NULL`.

## Tests

```sh
make test          # unit + public-API smoke tests
make integration   # localhost round-trip between two embedded nodes
```

The integration test starts three short-lived libbep44 instances on
`127.0.0.1`, has one publish a mutable item, has another retrieve it,
and asserts the value matches. The vendored copy of `jech/dht` carries
a small patch that opts out of its loopback-as-martian rejection when
`DHT_ALLOW_LOOPBACK` is set — see
[`vendor/jech-dht/PROVENANCE.md`](vendor/jech-dht/PROVENANCE.md).

## License

MIT — see [`LICENSE`](LICENSE). Copyright © 2026 Tayaout
Labelle-Kuberek <tayaoutlk@gmail.com>. The vendored copy of
`jech/dht` retains its upstream MIT license; see
[`vendor/jech-dht/LICENCE`](vendor/jech-dht/LICENCE).
