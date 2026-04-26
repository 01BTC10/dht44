/*
 * libbep44 — embed BEP 44 (mutable + immutable) on the BitTorrent
 * Mainline DHT into a C program.
 *
 * Single-threaded. The caller drives the event loop by calling
 * bep44_step() periodically (or selecting on bep44_fd()). All put/get
 * calls are non-blocking; completion arrives via the user-supplied
 * callback, fired from inside bep44_step().
 *
 *   bep44_opts_t opts = { .port = 6881, .state_dir = "./state",
 *                         .bootstrap_routers = 1 };
 *   bep44_ctx_t *ctx = bep44_open(&opts);
 *   bep44_keypair_t kp; bep44_keygen(&kp);
 *   bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
 *                     (uint8_t*)"5:hello", 7, on_put, NULL);
 *   while (running) bep44_step(ctx, 250);
 *   bep44_close(ctx);
 */

#ifndef LIBBEP44_H
#define LIBBEP44_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- constants ---------------- */

#ifndef BEP44_PK_LEN
#define BEP44_PK_LEN      32   /* Ed25519 public key */
#endif
#ifndef BEP44_SK_LEN
#define BEP44_SK_LEN      64   /* Ed25519 secret key (libsodium form) */
#endif
#ifndef BEP44_SIG_LEN
#define BEP44_SIG_LEN     64
#endif
#ifndef BEP44_TARGET_LEN
#define BEP44_TARGET_LEN  20   /* SHA-1 */
#endif
#ifndef BEP44_VALUE_MAX
#define BEP44_VALUE_MAX  1000  /* BEP 44 hard cap on bencoded v */
#endif
#ifndef BEP44_SALT_MAX
#define BEP44_SALT_MAX     64
#endif

/* ---------------- types ---------------- */

typedef struct bep44_ctx bep44_ctx_t;

typedef struct {
    uint8_t pk[BEP44_PK_LEN];
    uint8_t sk[BEP44_SK_LEN];
} bep44_keypair_t;

/*
 * Options for bep44_open. Zero-initialise then set the fields you care
 * about. `state_dir` is REQUIRED — node id and warm-start nodes are
 * persisted there. Pass an empty unique directory if you want a fresh
 * identity.
 */
typedef struct {
    int          port;              /* UDP port; 0 = let OS pick */
    const char  *state_dir;         /* required, must already be writable */
    int          bootstrap_routers; /* 1 = ping public routers on open */
} bep44_opts_t;

typedef struct {
    int success;       /* 1 if at least one peer ack'd the put */
    int stored_count;  /* number of peers that ack'd */
    int err_code;      /* non-zero if any peer returned a BEP 44 err */
} bep44_put_result_t;

/*
 * Get result. value/value_len point at memory owned by the library and
 * are only valid for the duration of the callback — copy if you need
 * to keep them. `is_mutable` selects which fields are populated:
 *   mutable:  pk, seq, sig, value
 *   immutable: value
 */
typedef struct {
    int            found;          /* 1 if a value was retrieved */
    int            is_mutable;
    uint8_t        pk[BEP44_PK_LEN];
    int64_t        seq;
    uint8_t        sig[BEP44_SIG_LEN];
    const uint8_t *value;          /* bencoded `v` */
    size_t         value_len;
} bep44_get_result_t;

typedef void (*bep44_put_cb)(const bep44_put_result_t *result, void *user);
typedef void (*bep44_get_cb)(const bep44_get_result_t *result, void *user);

/* ---------------- lifecycle ---------------- */

/*
 * Open a context. Returns NULL on error (state_dir missing, port
 * already bound, sodium_init failed, second concurrent open in this
 * process). At most one context may be open at a time per process.
 */
bep44_ctx_t *bep44_open (const bep44_opts_t *opts);

/* Close. Safe to call on NULL. Drains pending callbacks (they fire
 * with success=0 / found=0 to let the user free their closures). */
void         bep44_close(bep44_ctx_t *ctx);

/* Underlying UDP fd, for select/poll integration. -1 if not open. */
int          bep44_fd   (const bep44_ctx_t *ctx);

/*
 * Drive one iteration of the event loop. Sleeps up to timeout_ms
 * waiting for a packet or internal deadline. Pumps the routing table,
 * fires lookup/put/get callbacks. Returns 0 on success, -1 on fatal
 * error (caller should bep44_close).
 */
int          bep44_step (bep44_ctx_t *ctx, int timeout_ms);

/* Approximate count of "good" peers in the routing table. Useful as a
 * readiness probe before issuing your first put/get. */
int          bep44_good_nodes(const bep44_ctx_t *ctx);

/* ---------------- keys ---------------- */

/* Generate a fresh Ed25519 keypair. Returns 0 on success. */
int          bep44_keygen          (bep44_keypair_t *out);

/* Recover a keypair from a 64-byte libsodium secret key. */
int          bep44_keypair_from_sk (bep44_keypair_t *out,
                                    const uint8_t sk[BEP44_SK_LEN]);

/* Persist / load keypair as JSON file (mode 0600). The file format is
 * compatible with the dht44 CLI keygen output. */
int          bep44_save_key        (const char *path,
                                    const bep44_keypair_t *kp);
int          bep44_load_key        (const char *path,
                                    bep44_keypair_t *out);

/* ---------------- targets ---------------- */

/* SHA1(pk || salt). salt may be NULL/0 for empty salt. */
int          bep44_target_mutable  (const uint8_t pk[BEP44_PK_LEN],
                                    const char *salt, size_t salt_len,
                                    uint8_t target[BEP44_TARGET_LEN]);

/* SHA1(v_bencoded). */
int          bep44_target_immutable(const uint8_t *v_bencoded, size_t v_len,
                                    uint8_t target[BEP44_TARGET_LEN]);

/* ---------------- operations ---------------- */

/*
 * Publish a mutable item under SHA1(pk || salt). `seq` must be
 * strictly greater than any previously-stored seq for this target.
 * Pass cas=-1 to skip compare-and-swap; otherwise the put fails if
 * the stored seq != cas. `v_bencoded` must already be bencoded
 * (e.g. "5:hello", not "hello") and ≤ BEP44_VALUE_MAX bytes.
 *
 * Async: callback fires once stores have settled (or the lookup
 * times out). Returns 0 if the put was queued, -1 on input error.
 */
int          bep44_put_mutable  (bep44_ctx_t *ctx,
                                 const bep44_keypair_t *kp,
                                 const char *salt, size_t salt_len,
                                 int64_t seq, int64_t cas,
                                 const uint8_t *v_bencoded, size_t v_len,
                                 bep44_put_cb cb, void *user);

/*
 * Publish an immutable item. Target is implicit (SHA1 of v_bencoded).
 */
int          bep44_put_immutable(bep44_ctx_t *ctx,
                                 const uint8_t *v_bencoded, size_t v_len,
                                 bep44_put_cb cb, void *user);

/*
 * Fetch the latest mutable item under SHA1(pk || salt). Library
 * verifies the Ed25519 signature; result.found is 0 if nothing was
 * found OR if all candidates failed verification.
 */
int          bep44_get_mutable  (bep44_ctx_t *ctx,
                                 const uint8_t pk[BEP44_PK_LEN],
                                 const char *salt, size_t salt_len,
                                 bep44_get_cb cb, void *user);

/*
 * Fetch an immutable item by its precomputed target.
 */
int          bep44_get_immutable(bep44_ctx_t *ctx,
                                 const uint8_t target[BEP44_TARGET_LEN],
                                 bep44_get_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* LIBBEP44_H */
