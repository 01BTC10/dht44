/*
 * libbep44 — public API implementation. Composes bencode/bep44/state/
 * dht_wrap/lookup into a small embeddable client.
 *
 * Single-threaded. One ctx per process (dht_wrap holds global state).
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium.h>

#include "libbep44.h"

#include "bencode.h"
#include "bep44.h"
#include "dht_wrap.h"
#include "lookup.h"
#include "state.h"
#include "upnp.h"

#include <time.h>

/* ============================================================
 * Inbound BEP 44 server. The library doubles as a BEP 44 server:
 * any peer that finds us in the routing table can issue get/put
 * against us, and we'll answer from items/<target>.json on disk.
 * Required for two libbep44 nodes to round-trip in isolation.
 * ============================================================ */

#define LIB_TOKEN_LEN 8
static uint8_t g_token_secret[32];

static void
issue_token(uint8_t out[LIB_TOKEN_LEN], const struct sockaddr_in *peer,
            const uint8_t target[BEP44_TARGET_LEN])
{
    uint8_t buf[4 + 2 + BEP44_TARGET_LEN];
    memcpy(buf, &peer->sin_addr, 4);
    memcpy(buf + 4, &peer->sin_port, 2);
    memcpy(buf + 6, target, BEP44_TARGET_LEN);
    unsigned char digest[20];
    unsigned int  dlen = sizeof(digest);
    HMAC(EVP_sha1(), g_token_secret, sizeof(g_token_secret),
         buf, sizeof(buf), digest, &dlen);
    memcpy(out, digest, LIB_TOKEN_LEN);
}

static int
token_matches(const uint8_t *got, size_t got_len,
              const struct sockaddr_in *peer,
              const uint8_t target[BEP44_TARGET_LEN])
{
    if (got_len != LIB_TOKEN_LEN) return 0;
    uint8_t want[LIB_TOKEN_LEN];
    issue_token(want, peer, target);
    return sodium_memcmp(got, want, LIB_TOKEN_LEN) == 0;
}

static void
on_inbound_query(const struct sockaddr *peer, int peerlen,
                 const uint8_t *tid, size_t tid_len,
                 int is_put,
                 const bencode_value *a,
                 void *closure)
{
    (void)closure; (void)peerlen;
    if (peer->sa_family != AF_INET) return;       /* v4-only for now */
    const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;

    if (!is_put) {
        const bencode_value *t = bencode_dict_get(a, "target");
        if (!t || t->type != BENCODE_STR || t->str.len != BEP44_TARGET_LEN) return;
        uint8_t target[BEP44_TARGET_LEN];
        memcpy(target, t->str.bytes, BEP44_TARGET_LEN);

        stored_item si = { 0 };
        int have = state_load_item(target, &si) == 0;
        uint8_t token[LIB_TOKEN_LEN];
        issue_token(token, p4, target);

        uint8_t out[2048];
        ssize_t n;
        if (have && si.mutable_) {
            n = bep44_build_get_response_mutable(
                out, sizeof(out), tid, tid_len,
                dht_wrap_node_id(), si.pk, NULL, 0, si.seq, si.sig,
                token, sizeof(token), si.v, si.v_len);
        } else if (have) {
            n = bep44_build_get_response_immutable(
                out, sizeof(out), tid, tid_len,
                dht_wrap_node_id(), NULL, 0,
                token, sizeof(token), si.v, si.v_len);
        } else {
            /* No item — still return a token so the requester can put. */
            bencode_writer w;
            bencode_writer_init(&w, out, sizeof(out));
            bencode_dict_open(&w);
                bencode_cstr(&w, "r");
                bencode_dict_open(&w);
                    bencode_cstr(&w, "id");
                    bencode_str(&w, dht_wrap_node_id(), BEP44_NODE_ID_LEN);
                    bencode_cstr(&w, "token");
                    bencode_str(&w, token, sizeof(token));
                bencode_dict_close(&w);
                bencode_cstr(&w, "t"); bencode_str(&w, tid, tid_len);
                bencode_cstr(&w, "y"); bencode_cstr(&w, "r");
            bencode_dict_close(&w);
            n = bencode_writer_finish(&w);
        }
        if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        return;
    }

    /* PUT */
    const bencode_value *target = bencode_dict_get(a, "target");
    const bencode_value *tok    = bencode_dict_get(a, "token");
    const bencode_value *v      = bencode_dict_get(a, "v");
    const bencode_value *k      = bencode_dict_get(a, "k");
    const bencode_value *salt   = bencode_dict_get(a, "salt");
    const bencode_value *seqv   = bencode_dict_get(a, "seq");
    const bencode_value *sig    = bencode_dict_get(a, "sig");
    const bencode_value *casv   = bencode_dict_get(a, "cas");

    if (!tok || tok->type != BENCODE_STR || !v || v->type != BENCODE_STR) return;

    int is_mutable = (k && k->type == BENCODE_STR && k->str.len == BEP44_PK_LEN
                      && sig && sig->type == BENCODE_STR && sig->str.len == BEP44_SIG_LEN
                      && seqv && seqv->type == BENCODE_INT);

    /* Re-bencode v as a string for sig + target. */
    uint8_t vb[BEP44_MAX_V + 16];
    bencode_writer vw;
    bencode_writer_init(&vw, vb, sizeof(vb));
    bencode_str(&vw, v->str.bytes, v->str.len);
    ssize_t vb_len = bencode_writer_finish(&vw);
    if (vb_len < 0) return;

    uint8_t target_buf[BEP44_TARGET_LEN];
    size_t  salt_len = (salt && salt->type == BENCODE_STR) ? salt->str.len : 0;
    const uint8_t *salt_bytes = salt_len > 0 ? salt->str.bytes : NULL;

    if (is_mutable) {
        if (salt_len > BEP44_MAX_SALT) {
            uint8_t out[128];
            ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                          207, "salt too long");
            if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
            return;
        }
        bep44_target(target_buf, k->str.bytes, salt_bytes, salt_len);
    } else {
        bep44_immutable_target(target_buf, vb, (size_t)vb_len);
    }

    if (!token_matches(tok->str.bytes, tok->str.len, p4, target_buf)) {
        uint8_t out[256];
        ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                      203, "bad token");
        if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        return;
    }
    if (target && target->type == BENCODE_STR
        && target->str.len == BEP44_TARGET_LEN
        && memcmp(target->str.bytes, target_buf, BEP44_TARGET_LEN) != 0) {
        uint8_t out[256];
        ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                      203, "target mismatch");
        if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        return;
    }

    if (is_mutable) {
        uint8_t signable[BEP44_MAX_V + 128];
        ssize_t slen = bep44_signable(signable, sizeof(signable),
                                      salt_bytes, salt_len,
                                      seqv->i, vb, (size_t)vb_len);
        if (slen < 0
            || bep44_verify(sig->str.bytes, k->str.bytes,
                            signable, (size_t)slen) < 0) {
            uint8_t out[256];
            ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                          206, "invalid signature");
            if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
            return;
        }

        stored_item existing = { 0 };
        int have_existing = (state_load_item(target_buf, &existing) == 0);
        if (have_existing && existing.mutable_) {
            if (casv && casv->type == BENCODE_INT && casv->i != existing.seq) {
                uint8_t out[256];
                ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                              301, "CAS mismatch");
                if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
                return;
            }
            if (seqv->i <= existing.seq) {
                uint8_t out[256];
                ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                              302, "seq must be > current");
                if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
                return;
            }
        }

        stored_item si = { 0 };
        si.mutable_ = 1;
        si.origin   = ITEM_ORIGIN_PEER;
        memcpy(si.pk, k->str.bytes, BEP44_PK_LEN);
        si.seq = seqv->i;
        if (salt_len) { memcpy(si.salt, salt_bytes, salt_len); si.salt_len = salt_len; }
        memcpy(si.sig, sig->str.bytes, BEP44_SIG_LEN);
        /* Store the bencoded form so future get responses re-emit it
         * verbatim via bencode_raw — get_response_mutable expects
         * v_bencoded, not raw value bytes. */
        if ((size_t)vb_len > sizeof(si.v)) return;
        memcpy(si.v, vb, (size_t)vb_len);
        si.v_len = (size_t)vb_len;
        if (state_save_item(target_buf, &si) < 0) return;
    } else {
        if ((size_t)vb_len > BEP44_MAX_V) return;
        stored_item si = { 0 };
        si.mutable_ = 0;
        si.origin = ITEM_ORIGIN_PEER;
        memcpy(si.v, vb, (size_t)vb_len);
        si.v_len = (size_t)vb_len;
        if (state_save_item(target_buf, &si) < 0) return;
    }

    uint8_t out[256];
    ssize_t n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                         dht_wrap_node_id());
    if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
}

/* ============================================================
 * One-context-per-process. dht_wrap_* are global; we enforce.
 * ============================================================ */

struct bep44_ctx {
    int     open;
    int     port;
    char    state_dir[1024];
    /* UPnP */
    int     upnp_active;
    time_t  upnp_next_refresh;
    int     upnp_lifetime;
    /* Republish */
    int     republish_secs;        /* 0 disables */
    time_t  next_republish_at;
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

    /* Fresh per-process token secret + inbound query server. */
    randombytes_buf(g_token_secret, sizeof(g_token_secret));
    dht_wrap_set_query_handler(on_inbound_query, NULL);

    /* Optional UPnP IGD port mapping. Best-effort. */
    int upnp_lifetime = opts->upnp_lifetime_sec > 0
                        ? opts->upnp_lifetime_sec : 3600;
    int upnp_active = 0;
    if (opts->use_upnp && opts->port > 0) {
        if (upnp_init((uint16_t)opts->port, (uint32_t)upnp_lifetime) == 0) {
            upnp_active = 1;
        }
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

    int rep_min = opts->republish_minutes;
    if (rep_min == 0) rep_min = 60;
    int rep_secs = rep_min < 0 ? 0 : rep_min * 60;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.open = 1;
    g_ctx.port = opts->port;
    snprintf(g_ctx.state_dir, sizeof(g_ctx.state_dir), "%s", opts->state_dir);
    g_ctx.upnp_active        = upnp_active;
    g_ctx.upnp_lifetime      = upnp_lifetime;
    g_ctx.upnp_next_refresh  = time(NULL) + (upnp_lifetime > 60
                                            ? upnp_lifetime / 2 : 30);
    g_ctx.republish_secs     = rep_secs;
    /* Don't republish on the very first step — let the routing table
     * settle first. Schedule the first sweep one cycle out. */
    g_ctx.next_republish_at  = rep_secs > 0 ? time(NULL) + rep_secs : 0;
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
    if (ctx->upnp_active) {
        upnp_shutdown();
        ctx->upnp_active = 0;
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

/* ============================================================
 * Republish — re-push every stored item every republish_secs so peer
 * caches don't expire it (BEP 44 items live ~2h on storers).
 *
 * For peer-origin items we re-emit the original signed bytes verbatim
 * (no key needed). For self-origin items, same thing — the signature
 * is already valid for that (seq, v, salt) and remains so as long as
 * we don't bump seq.
 *
 * Implementation: walk items/<target>.json, for each item run a fresh
 * lookup, then on lookup completion fan out put queries with the
 * stored sig + token from each responder.
 * ============================================================ */

typedef struct rep_op {
    int          in_use;
    uint8_t      target[BEP44_TARGET_LEN];
    stored_item  item;
    int          pending;
} rep_op;

#define REP_MAX_INFLIGHT 4
static rep_op g_reps[REP_MAX_INFLIGHT];

static rep_op *
rep_alloc(void)
{
    for (int i = 0; i < REP_MAX_INFLIGHT; i++)
        if (!g_reps[i].in_use) {
            memset(&g_reps[i], 0, sizeof(g_reps[i]));
            g_reps[i].in_use = 1;
            return &g_reps[i];
        }
    return NULL;
}

static void
on_rep_response(bep44_tx_event ev,
                const struct sockaddr *peer, int peerlen,
                const bencode_value *r, const bencode_value *e,
                void *closure)
{
    (void)ev; (void)peer; (void)peerlen; (void)r; (void)e;
    rep_op *p = closure;
    if (!p->in_use) return;
    if (--p->pending <= 0) memset(p, 0, sizeof(*p));
}

static void
on_rep_lookup_done(int rc,
                   const lookup_value *values, size_t value_count,
                   const lookup_token *tokens, size_t token_count,
                   void *closure)
{
    (void)rc; (void)values; (void)value_count;
    rep_op *p = closure;
    if (!p->in_use) return;
    if (token_count == 0) { memset(p, 0, sizeof(*p)); return; }

    p->pending = 0;
    for (size_t i = 0; i < token_count; i++) {
        const lookup_token *t = &tokens[i];
        uint8_t pkt[1500];
        ssize_t plen;
        uint8_t tid[2];
        dht_wrap_random_tid(tid);

        if (p->item.mutable_) {
            plen = bep44_build_put_query_mutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(), p->item.pk,
                p->item.salt_len ? p->item.salt : NULL, p->item.salt_len,
                p->item.seq, NULL, p->item.sig,
                t->token, t->token_len,
                p->item.v, p->item.v_len);
        } else {
            plen = bep44_build_put_query_immutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(),
                t->token, t->token_len,
                p->item.v, p->item.v_len);
        }
        if (plen < 0) continue;
        if (dht_wrap_send_query((const struct sockaddr *)&t->peer,
                                (int)t->peerlen, pkt, (size_t)plen,
                                tid, sizeof(tid), 5000,
                                on_rep_response, p) == 0) {
            p->pending++;
        }
    }
    if (p->pending == 0) memset(p, 0, sizeof(*p));
}

typedef struct {
    int *budget;     /* how many items we may still kick off this sweep */
} rep_walk_ctx;

static int
republish_one(const uint8_t target[BEP44_TARGET_LEN], void *closure)
{
    rep_walk_ctx *w = closure;
    if (*w->budget <= 0) return 1;        /* stop iteration */

    /* Skip if already in flight for the same target. */
    for (int i = 0; i < REP_MAX_INFLIGHT; i++) {
        if (g_reps[i].in_use
            && memcmp(g_reps[i].target, target, BEP44_TARGET_LEN) == 0)
            return 0;
    }

    rep_op *p = rep_alloc();
    if (!p) return 1;                     /* table full — defer */
    if (state_load_item(target, &p->item) < 0) {
        memset(p, 0, sizeof(*p));
        return 0;
    }
    memcpy(p->target, target, BEP44_TARGET_LEN);
    if (lookup_start(p->target, 15000, on_rep_lookup_done, p) == NULL) {
        memset(p, 0, sizeof(*p));
        return 0;
    }
    (*w->budget)--;
    return 0;
}

static void
maybe_republish(bep44_ctx_t *ctx)
{
    if (ctx->republish_secs <= 0) return;
    time_t now = time(NULL);
    if (now < ctx->next_republish_at) return;
    /* Cap how much we kick off in one sweep — REP_MAX_INFLIGHT slots
     * means at most that many lookups concurrently. The walk picks up
     * items in directory order; nodes left over this sweep get caught
     * next time around. */
    int budget = REP_MAX_INFLIGHT;
    rep_walk_ctx w = { &budget };
    state_walk_items(republish_one, &w);
    ctx->next_republish_at = now + ctx->republish_secs;
}

int
bep44_step(bep44_ctx_t *ctx, int timeout_ms)
{
    if (!ctx || !ctx->open) return -1;
    int wrap_wake = timeout_ms;
    int look_wake = timeout_ms;
    dht_wrap_step(NULL, 0, NULL, 0, &wrap_wake);
    lookup_tick(&look_wake);
    maybe_republish(ctx);
    if (ctx->upnp_active) {
        time_t now = time(NULL);
        if (now >= ctx->upnp_next_refresh) {
            (void)upnp_refresh();
            ctx->upnp_next_refresh = now + (ctx->upnp_lifetime > 60
                                           ? ctx->upnp_lifetime / 2 : 30);
        }
    }
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

int
bep44_add_peer(bep44_ctx_t *ctx, const char *ipv4, uint16_t port)
{
    if (!ctx || !ctx->open || !ipv4) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ipv4, &sa.sin_addr) != 1) return -1;
    return dht_wrap_insert_warm(&sa);
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

    /* Persist for republish + inbound serve. */
    {
        stored_item si = { 0 };
        si.mutable_ = 1;
        si.origin   = ITEM_ORIGIN_SELF;
        memcpy(si.pk, kp->pk, BEP44_PK_LEN);
        si.seq = seq;
        if (salt_len) { memcpy(si.salt, salt, salt_len); si.salt_len = salt_len; }
        memcpy(si.sig, p->sig, BEP44_SIG_LEN);
        memcpy(si.v, v_bencoded, v_len);
        si.v_len = v_len;
        (void)state_save_item(p->target, &si);
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

    /* Persist for republish + inbound serve. */
    {
        stored_item si = { 0 };
        si.mutable_ = 0;
        si.origin   = ITEM_ORIGIN_SELF;
        memcpy(si.v, v_bencoded, v_len);
        si.v_len = v_len;
        (void)state_save_item(p->target, &si);
    }

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
