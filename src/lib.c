/*
 * libbep44 — public API implementation. Composes bencode/bep44/state/
 * dht_wrap/lookup into a small embeddable client.
 *
 * Single-threaded. One ctx per process (dht_wrap holds global state).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "libbep44.h"

#include "bencode.h"
#include "bep44.h"
#include "dht_wrap.h"
#include "lookup.h"
#include "state.h"

/* ============================================================
 * One-context-per-process. dht_wrap_* are global; we enforce.
 * ============================================================ */

struct bep44_ctx {
    int  open;
    int  port;
    char state_dir[1024];
};

static struct bep44_ctx g_ctx;

/* ============================================================
 * Pending op tracking
 * ============================================================ */

#define MAX_INFLIGHT 16

typedef struct put_op {
    int                 in_use;
    uint8_t             target[BEP44_TARGET_LEN];
    int                 mutable_;
    uint8_t             pk[BEP44_PK_LEN];
    uint8_t             sig[BEP44_SIG_LEN];
    int                 has_cas;
    int64_t             cas;
    int64_t             seq;
    uint8_t             salt[BEP44_SALT_MAX];
    size_t              salt_len;
    uint8_t             v[BEP44_VALUE_MAX];
    size_t              v_len;
    int                 pending;       /* outstanding per-peer tx */
    int                 acks;
    int                 last_err;
    bep44_put_cb        cb;
    void               *user;
    int                 lookup_started;
    int                 done;
} put_op;

typedef struct get_op {
    int                 in_use;
    int                 mutable_;
    uint8_t             target[BEP44_TARGET_LEN];
    uint8_t             pk[BEP44_PK_LEN];   /* mutable: copy of expected pk for verify */
    uint8_t             salt[BEP44_SALT_MAX];
    size_t              salt_len;
    bep44_get_cb        cb;
    void               *user;
    int                 done;
} get_op;

static put_op g_puts[MAX_INFLIGHT];
static get_op g_gets[MAX_INFLIGHT];

static put_op *put_alloc(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++)
        if (!g_puts[i].in_use) {
            memset(&g_puts[i], 0, sizeof(g_puts[i]));
            g_puts[i].in_use = 1;
            return &g_puts[i];
        }
    return NULL;
}

static void put_release(put_op *p) {
    sodium_memzero(p, sizeof(*p));
}

static get_op *get_alloc(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++)
        if (!g_gets[i].in_use) {
            memset(&g_gets[i], 0, sizeof(g_gets[i]));
            g_gets[i].in_use = 1;
            return &g_gets[i];
        }
    return NULL;
}

static void get_release(get_op *g) {
    memset(g, 0, sizeof(*g));
}

/* ============================================================
 * Lifecycle
 * ============================================================ */

static int
mkdir_p_writable(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(path, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    fprintf(stderr, "[libbep44] mkdir %s: %s\n", path, strerror(errno));
    return -1;
}

bep44_ctx_t *
bep44_open(const bep44_opts_t *opts)
{
    if (!opts || !opts->state_dir || !*opts->state_dir) {
        fprintf(stderr, "[libbep44] state_dir is required\n");
        return NULL;
    }
    if (g_ctx.open) {
        fprintf(stderr, "[libbep44] a context is already open in this process\n");
        return NULL;
    }
    if (mkdir_p_writable(opts->state_dir) < 0) return NULL;

    /* state_* read DHT44_HOME from the environment */
    if (setenv("DHT44_HOME", opts->state_dir, 1) < 0) {
        fprintf(stderr, "[libbep44] setenv: %s\n", strerror(errno));
        return NULL;
    }

    if (dht_wrap_init_opt((uint16_t)opts->port, /*want_ipv6=*/0) < 0) {
        fprintf(stderr, "[libbep44] dht_wrap_init failed\n");
        return NULL;
    }

    /* Warm-start from any persisted nodes. */
    struct sockaddr_in warm[256];
    int warm_n = 0;
    if (state_load_nodes(warm, 256, &warm_n) == 0 && warm_n > 0) {
        for (int i = 0; i < warm_n; i++) dht_wrap_insert_warm(&warm[i]);
    }

    if (opts->bootstrap_routers) {
        (void)dht_wrap_ping_routers();
    }

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.open = 1;
    g_ctx.port = opts->port;
    snprintf(g_ctx.state_dir, sizeof(g_ctx.state_dir), "%s", opts->state_dir);
    memset(g_puts, 0, sizeof(g_puts));
    memset(g_gets, 0, sizeof(g_gets));
    return &g_ctx;
}

void
bep44_close(bep44_ctx_t *ctx)
{
    if (!ctx || !ctx->open) return;

    /* Persist warm nodes for next time. */
    struct sockaddr_in nodes[256];
    int n = dht_wrap_get_nodes(nodes, 256);
    if (n > 0) (void)state_save_nodes(nodes, n);

    /* Notify any pending callbacks they're cancelled. */
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (g_puts[i].in_use && !g_puts[i].done && g_puts[i].cb) {
            bep44_put_result_t r = { 0 };
            g_puts[i].cb(&r, g_puts[i].user);
            put_release(&g_puts[i]);
        }
        if (g_gets[i].in_use && !g_gets[i].done && g_gets[i].cb) {
            bep44_get_result_t r = { 0 };
            g_gets[i].cb(&r, g_gets[i].user);
            get_release(&g_gets[i]);
        }
    }
    dht_wrap_uninit();
    ctx->open = 0;
}

int
bep44_fd(const bep44_ctx_t *ctx)
{
    if (!ctx || !ctx->open) return -1;
    return dht_wrap_socket();
}

int
bep44_step(bep44_ctx_t *ctx, int timeout_ms)
{
    if (!ctx || !ctx->open) return -1;
    int wrap_wake = timeout_ms;
    int look_wake = timeout_ms;
    dht_wrap_step(NULL, 0, NULL, 0, &wrap_wake);
    lookup_tick(&look_wake);
    int wake = wrap_wake < look_wake ? wrap_wake : look_wake;
    if (wake < 0) wake = 0;
    if (wake > timeout_ms) wake = timeout_ms;

    int fd = dht_wrap_socket();
    if (fd < 0) return -1;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = { wake / 1000, (wake % 1000) * 1000 };
    int sr = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (sr < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    if (sr > 0 && FD_ISSET(fd, &rfds)) {
        for (;;) {
            uint8_t pkt[2048];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(fd, pkt, sizeof(pkt) - 1, 0,
                                 (struct sockaddr *)&from, &fromlen);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                return -1;
            }
            pkt[n] = '\0';
            int ww = 0;
            dht_wrap_step(pkt, (size_t)n,
                          (struct sockaddr *)&from, (int)fromlen, &ww);
        }
    }
    return 0;
}

int
bep44_good_nodes(const bep44_ctx_t *ctx)
{
    if (!ctx || !ctx->open) return 0;
    int good = 0, dub = 0;
    dht_wrap_status(&good, &dub);
    return good;
}

/* ============================================================
 * Keys
 * ============================================================ */

int
bep44_keygen(bep44_keypair_t *out)
{
    if (!out) return -1;
    if (sodium_init() < 0) return -1;
    if (crypto_sign_keypair(out->pk, out->sk) != 0) return -1;
    return 0;
}

int
bep44_keypair_from_sk(bep44_keypair_t *out, const uint8_t sk[BEP44_SK_LEN])
{
    if (!out || !sk) return -1;
    if (sodium_init() < 0) return -1;
    memcpy(out->sk, sk, BEP44_SK_LEN);
    if (crypto_sign_ed25519_sk_to_pk(out->pk, out->sk) != 0) return -1;
    return 0;
}

int
bep44_save_key(const char *path, const bep44_keypair_t *kp)
{
    if (!path || !kp) return -1;
    return state_save_key(path, kp->sk);
}

int
bep44_load_key(const char *path, bep44_keypair_t *out)
{
    if (!path || !out) return -1;
    if (sodium_init() < 0) return -1;
    if (state_load_key(path, out->sk) < 0) return -1;
    if (crypto_sign_ed25519_sk_to_pk(out->pk, out->sk) != 0) {
        sodium_memzero(out, sizeof(*out));
        return -1;
    }
    return 0;
}

/* ============================================================
 * Targets
 * ============================================================ */

int
bep44_target_mutable(const uint8_t pk[BEP44_PK_LEN],
                     const char *salt, size_t salt_len,
                     uint8_t target[BEP44_TARGET_LEN])
{
    if (!pk || !target) return -1;
    if (salt_len > BEP44_SALT_MAX) return -1;
    bep44_target(target, pk, (const uint8_t *)salt, salt_len);
    return 0;
}

int
bep44_target_immutable(const uint8_t *v_bencoded, size_t v_len,
                       uint8_t target[BEP44_TARGET_LEN])
{
    if (!v_bencoded || !target) return -1;
    if (v_len > BEP44_VALUE_MAX) return -1;
    bep44_immutable_target(target, v_bencoded, v_len);
    return 0;
}

/* ============================================================
 * Put — common helpers
 * ============================================================ */

static void
put_complete(put_op *p)
{
    if (p->done) return;
    p->done = 1;
    bep44_put_result_t r = {
        .success      = p->acks > 0 ? 1 : 0,
        .stored_count = p->acks,
        .err_code     = p->last_err,
    };
    if (p->cb) p->cb(&r, p->user);
    put_release(p);
}

static void
on_put_response(bep44_tx_event ev,
                const struct sockaddr *peer, int peerlen,
                const bencode_value *r, const bencode_value *e,
                void *closure)
{
    (void)peer; (void)peerlen;
    put_op *p = closure;
    if (!p->in_use || p->done) return;
    if (ev == BEP44_TX_RESPONSE && r) {
        p->acks++;
    } else if (ev == BEP44_TX_ERROR && e
               && e->type == BENCODE_LIST && e->list.len >= 1
               && e->list.items[0]->type == BENCODE_INT) {
        p->last_err = (int)e->list.items[0]->i;
    }
    if (--p->pending <= 0) put_complete(p);
}

static void
on_put_lookup_done(int rc,
                   const lookup_value *values, size_t value_count,
                   const lookup_token *tokens, size_t token_count,
                   void *closure)
{
    (void)rc; (void)values; (void)value_count;
    put_op *p = closure;
    if (!p->in_use || p->done) return;

    if (token_count == 0) { put_complete(p); return; }

    p->pending = 0;
    for (size_t i = 0; i < token_count; i++) {
        const lookup_token *t = &tokens[i];
        uint8_t pkt[1500];
        ssize_t plen;
        uint8_t tid[2];
        dht_wrap_random_tid(tid);

        if (p->mutable_) {
            const int64_t *cas_ptr = p->has_cas ? &p->cas : NULL;
            plen = bep44_build_put_query_mutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(), p->pk,
                p->salt_len ? p->salt : NULL, p->salt_len,
                p->seq, cas_ptr, p->sig,
                t->token, t->token_len,
                p->v, p->v_len);
        } else {
            plen = bep44_build_put_query_immutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(),
                t->token, t->token_len,
                p->v, p->v_len);
        }
        if (plen < 0) continue;

        if (dht_wrap_send_query((const struct sockaddr *)&t->peer,
                                (int)t->peerlen, pkt, (size_t)plen,
                                tid, sizeof(tid),
                                5000, on_put_response, p) == 0) {
            p->pending++;
        }
    }
    if (p->pending == 0) put_complete(p);
}

/* ============================================================
 * Put (mutable + immutable)
 * ============================================================ */

int
bep44_put_mutable(bep44_ctx_t *ctx,
                  const bep44_keypair_t *kp,
                  const char *salt, size_t salt_len,
                  int64_t seq, int64_t cas,
                  const uint8_t *v_bencoded, size_t v_len,
                  bep44_put_cb cb, void *user)
{
    if (!ctx || !ctx->open || !kp || !v_bencoded) return -1;
    if (v_len == 0 || v_len > BEP44_VALUE_MAX) return -1;
    if (salt_len > BEP44_SALT_MAX) return -1;
    if (seq < 0) return -1;

    put_op *p = put_alloc();
    if (!p) return -1;

    p->mutable_ = 1;
    p->cb = cb;
    p->user = user;
    memcpy(p->pk, kp->pk, BEP44_PK_LEN);
    if (salt && salt_len) memcpy(p->salt, salt, salt_len);
    p->salt_len = salt_len;
    p->seq = seq;
    if (cas >= 0) { p->has_cas = 1; p->cas = cas; }
    memcpy(p->v, v_bencoded, v_len);
    p->v_len = v_len;
    bep44_target(p->target, kp->pk, (const uint8_t *)salt, salt_len);

    /* Sign locally. */
    uint8_t signable[BEP44_VALUE_MAX + 128];
    ssize_t slen = bep44_signable(signable, sizeof(signable),
                                  (const uint8_t *)salt, salt_len,
                                  seq, v_bencoded, v_len);
    if (slen < 0) { put_release(p); return -1; }
    if (bep44_sign(p->sig, kp->sk, signable, (size_t)slen) < 0) {
        put_release(p); return -1;
    }

    if (lookup_start(p->target, 15000, on_put_lookup_done, p) == NULL) {
        put_release(p); return -1;
    }
    p->lookup_started = 1;
    return 0;
}

int
bep44_put_immutable(bep44_ctx_t *ctx,
                    const uint8_t *v_bencoded, size_t v_len,
                    bep44_put_cb cb, void *user)
{
    if (!ctx || !ctx->open || !v_bencoded) return -1;
    if (v_len == 0 || v_len > BEP44_VALUE_MAX) return -1;

    put_op *p = put_alloc();
    if (!p) return -1;

    p->mutable_ = 0;
    p->cb = cb;
    p->user = user;
    memcpy(p->v, v_bencoded, v_len);
    p->v_len = v_len;
    bep44_immutable_target(p->target, v_bencoded, v_len);

    if (lookup_start(p->target, 15000, on_put_lookup_done, p) == NULL) {
        put_release(p); return -1;
    }
    p->lookup_started = 1;
    return 0;
}

/* ============================================================
 * Get (mutable + immutable)
 * ============================================================ */

static void
on_get_lookup_done(int rc,
                   const lookup_value *values, size_t value_count,
                   const lookup_token *tokens, size_t token_count,
                   void *closure)
{
    (void)rc; (void)tokens; (void)token_count;
    get_op *g = closure;
    if (!g->in_use || g->done) return;
    g->done = 1;

    bep44_get_result_t r = { 0 };

    /* For mutable: pick highest-seq value whose signature verifies under
     * our expected pk. For immutable: any matching value. */
    const lookup_value *best = NULL;
    for (size_t i = 0; i < value_count; i++) {
        const lookup_value *v = &values[i];
        if (g->mutable_ != v->mutable_) continue;
        if (g->mutable_) {
            /* Some peers may report a different pk under the same target;
             * skip those. Verify signature. */
            if (memcmp(v->k, g->pk, BEP44_PK_LEN) != 0) continue;
            uint8_t signable[BEP44_VALUE_MAX + 128];
            ssize_t slen = bep44_signable(signable, sizeof(signable),
                                          g->salt_len ? g->salt : NULL, g->salt_len,
                                          v->seq, v->v, v->v_len);
            if (slen < 0) continue;
            if (bep44_verify(v->sig, v->k, signable, (size_t)slen) != 0) continue;
        }
        if (!best) { best = v; continue; }
        if (g->mutable_ && v->seq > best->seq) best = v;
    }

    if (best) {
        r.found      = 1;
        r.is_mutable = best->mutable_;
        if (best->mutable_) {
            memcpy(r.pk,  best->k,   BEP44_PK_LEN);
            memcpy(r.sig, best->sig, BEP44_SIG_LEN);
            r.seq = best->seq;
        }
        r.value     = best->v;
        r.value_len = best->v_len;
    }
    if (g->cb) g->cb(&r, g->user);
    get_release(g);
}

int
bep44_get_mutable(bep44_ctx_t *ctx,
                  const uint8_t pk[BEP44_PK_LEN],
                  const char *salt, size_t salt_len,
                  bep44_get_cb cb, void *user)
{
    if (!ctx || !ctx->open || !pk) return -1;
    if (salt_len > BEP44_SALT_MAX) return -1;

    get_op *g = get_alloc();
    if (!g) return -1;
    g->mutable_ = 1;
    g->cb = cb;
    g->user = user;
    memcpy(g->pk, pk, BEP44_PK_LEN);
    if (salt && salt_len) memcpy(g->salt, salt, salt_len);
    g->salt_len = salt_len;
    bep44_target(g->target, pk, (const uint8_t *)salt, salt_len);

    if (lookup_start(g->target, 15000, on_get_lookup_done, g) == NULL) {
        get_release(g); return -1;
    }
    return 0;
}

int
bep44_get_immutable(bep44_ctx_t *ctx,
                    const uint8_t target[BEP44_TARGET_LEN],
                    bep44_get_cb cb, void *user)
{
    if (!ctx || !ctx->open || !target) return -1;

    get_op *g = get_alloc();
    if (!g) return -1;
    g->mutable_ = 0;
    g->cb = cb;
    g->user = user;
    memcpy(g->target, target, BEP44_TARGET_LEN);

    if (lookup_start(g->target, 15000, on_get_lookup_done, g) == NULL) {
        get_release(g); return -1;
    }
    return 0;
}
