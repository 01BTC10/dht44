/*
 * Iterative BEP 44 lookup over jech/dht's routing table:
 *
 *   1. Seed shortlist with up to LOOKUP_TOP_K (8) addresses from jech's
 *      table (no node id known yet — jech doesn't expose ids).
 *   2. Send `get` to up to LOOKUP_ALPHA (3) fresh nodes in parallel,
 *      preferring those closest (by 20-byte XOR) to target.
 *   3. On each response, learn the responder's id, ingest the compact
 *      `nodes` field (26 B per node, id+ip+port), absorb v/k/seq/sig if
 *      present, remember the token. Insert any new candidates by distance.
 *   4. Continue until the LOOKUP_TOP_K closest known nodes have all either
 *      responded or timed out, or the overall deadline expires.
 */

#include "lookup.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "bencode.h"
#include "bep44.h"
#include "dht_wrap.h"
#include "observe.h"

static int lookup_verbose(void) {
    static int v = -1;
    if (v < 0) v = getenv("DHT44_LOOKUP_DEBUG") ? 1 : 0;
    return v;
}

#define LDBG(...) do { if (lookup_verbose()) fprintf(stderr, __VA_ARGS__); } while (0)

#define COMPACT_NODE_LEN  26  /* 20 id + 4 ip + 2 port (IPv4, "nodes") */
#define COMPACT_NODE6_LEN 38  /* 20 id + 16 ip + 2 port (IPv6, "nodes6") */

enum {
    NODE_FRESH = 0,
    NODE_INFLIGHT,
    NODE_RESPONDED,
    NODE_FAILED,
};

struct lookup_node {
    struct sockaddr_storage peer;
    socklen_t          peerlen;
    uint8_t            id[BEP44_NODE_ID_LEN];
    int                has_id;
    uint8_t            state;
    uint8_t            token[64];
    size_t             token_len;
};

struct query_slot {
    lookup_run *L;
    int         node_idx;
    int         in_use;
    struct timeval send_tv;     /* wall-clock at send, for RTT */
};

struct lookup_run {
    int            in_use;

    uint8_t        target[BEP44_TARGET_LEN];
    time_t         deadline;
    int            in_flight;

    struct lookup_node shortlist[LOOKUP_SHORTLIST];
    int            shortlist_count;

    lookup_value   values[LOOKUP_MAX_VALUES];
    int            values_count;

    lookup_token   tokens[LOOKUP_TOP_K];
    int            tokens_count;

    struct query_slot slots[LOOKUP_ALPHA];

    lookup_cb      cb;
    void          *closure;

    int            completed;
};

/* The pool of concurrent lookups. */
static struct lookup_run g_pool[LOOKUP_MAX_CONCURRENT];

/* ============================================================
 * XOR distance + shortlist
 * ============================================================ */

/* Returns -1, 0, 1 for distance(a, target) vs distance(b, target).
 * If either side lacks a known id, that side sorts AFTER the known-id side. */
static int
xor_cmp(const struct lookup_node *a, const struct lookup_node *b,
        const uint8_t *target)
{
    if (a->has_id && !b->has_id) return -1;
    if (!a->has_id && b->has_id) return 1;
    if (!a->has_id && !b->has_id) return 0;
    for (int i = 0; i < BEP44_NODE_ID_LEN; i++) {
        uint8_t da = a->id[i] ^ target[i];
        uint8_t db = b->id[i] ^ target[i];
        if (da != db) return da < db ? -1 : 1;
    }
    return 0;
}

/* Family-aware sockaddr equality (ip + port match). */
static int
sa_eq(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a;
        const struct sockaddr_in *y = (const struct sockaddr_in *)b;
        return x->sin_addr.s_addr == y->sin_addr.s_addr
            && x->sin_port        == y->sin_port;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port
            && memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
    }
    return 0;
}

/* Insert sorted by distance. Returns the inserted index, or -1 if the
 * candidate is already present or shortlist is full. Accepts both v4 and
 * v6 peers — storage is sockaddr_storage with a peerlen tag. */
static int
shortlist_insert(lookup_run *L, const uint8_t *id_or_null,
                 const struct sockaddr *peer, socklen_t peerlen)
{
    if (peerlen > (socklen_t)sizeof(struct sockaddr_storage)) return -1;
    /* dedupe by addr */
    for (int i = 0; i < L->shortlist_count; i++) {
        if (sa_eq((const struct sockaddr *)&L->shortlist[i].peer, peer)) {
            /* upgrade id if we just learned it */
            if (id_or_null && !L->shortlist[i].has_id) {
                memcpy(L->shortlist[i].id, id_or_null, BEP44_NODE_ID_LEN);
                L->shortlist[i].has_id = 1;
            }
            return -1;
        }
    }
    if (L->shortlist_count >= LOOKUP_SHORTLIST) return -1;

    struct lookup_node n = {0};
    memcpy(&n.peer, peer, peerlen);
    n.peerlen = peerlen;
    n.state = NODE_FRESH;
    if (id_or_null) {
        memcpy(n.id, id_or_null, BEP44_NODE_ID_LEN);
        n.has_id = 1;
    }
    /* find position by XOR */
    int pos = L->shortlist_count;
    for (int i = 0; i < L->shortlist_count; i++) {
        if (xor_cmp(&n, &L->shortlist[i], L->target) < 0) {
            pos = i;
            break;
        }
    }
    /* shift right */
    if (pos < L->shortlist_count) {
        memmove(&L->shortlist[pos + 1], &L->shortlist[pos],
                sizeof(*L->shortlist) * (size_t)(L->shortlist_count - pos));
    }
    L->shortlist[pos] = n;
    L->shortlist_count++;
    return pos;
}

static void
shortlist_resort(lookup_run *L)
{
    /* simple insertion sort by xor distance, in place */
    for (int i = 1; i < L->shortlist_count; i++) {
        struct lookup_node x = L->shortlist[i];
        int j = i - 1;
        while (j >= 0 && xor_cmp(&x, &L->shortlist[j], L->target) < 0) {
            L->shortlist[j + 1] = L->shortlist[j];
            j--;
        }
        L->shortlist[j + 1] = x;
    }
}

/* ============================================================
 * Completion logic
 * ============================================================ */

static void
finish(lookup_run *L)
{
    if (L->completed) return;
    L->completed = 1;
    if (lookup_verbose()) {
        int responded = 0, failed = 0, fresh = 0, inflight = 0;
        for (int i = 0; i < L->shortlist_count; i++) {
            switch (L->shortlist[i].state) {
                case NODE_RESPONDED: responded++; break;
                case NODE_FAILED:    failed++;    break;
                case NODE_FRESH:     fresh++;     break;
                case NODE_INFLIGHT:  inflight++;  break;
            }
        }
        LDBG("[lookup] FINISH shortlist=%d (responded=%d failed=%d "
             "fresh=%d inflight=%d) values=%d tokens=%d\n",
             L->shortlist_count, responded, failed, fresh, inflight,
             L->values_count, L->tokens_count);
    }
    if (L->cb) {
        L->cb(0,
              L->values, (size_t)L->values_count,
              L->tokens, (size_t)L->tokens_count,
              L->closure);
    }
    L->in_use = 0;
}

static int
top_k_done(const lookup_run *L)
{
    int k = LOOKUP_TOP_K < L->shortlist_count ? LOOKUP_TOP_K : L->shortlist_count;
    if (k == 0) return L->in_flight == 0;
    int done = 0;
    for (int i = 0; i < k; i++) {
        if (L->shortlist[i].state == NODE_RESPONDED
            || L->shortlist[i].state == NODE_FAILED) {
            done++;
        }
    }
    return done >= k;
}

/* ============================================================
 * Slot management
 * ============================================================ */

static struct query_slot *
slot_acquire(lookup_run *L, int node_idx)
{
    for (int i = 0; i < LOOKUP_ALPHA; i++) {
        if (!L->slots[i].in_use) {
            L->slots[i].in_use  = 1;
            L->slots[i].L       = L;
            L->slots[i].node_idx = node_idx;
            return &L->slots[i];
        }
    }
    return NULL;
}

static void
slot_release(struct query_slot *s)
{
    s->in_use = 0;
    s->L = NULL;
    s->node_idx = -1;
}

/* ============================================================
 * Sending and response handling
 * ============================================================ */

static void on_tx(bep44_tx_event ev,
                  const struct sockaddr *peer, int peerlen,
                  const bencode_value *r,
                  const bencode_value *e,
                  void *closure);

static void send_more(lookup_run *L);

static void
send_to(lookup_run *L, int node_idx)
{
    struct lookup_node *n = &L->shortlist[node_idx];
    struct query_slot *slot = slot_acquire(L, node_idx);
    if (!slot) return;

    uint8_t tid[2];
    dht_wrap_random_tid(tid);

    uint8_t pkt[256];
    ssize_t plen = bep44_build_get_query(pkt, sizeof(pkt),
                                         tid, sizeof(tid),
                                         dht_wrap_node_id(),
                                         L->target, NULL);
    if (plen < 0) {
        slot_release(slot);
        n->state = NODE_FAILED;
        return;
    }
    /* 15s default per query; lookup deadline overrides */
    int qto = 5000;
    if (dht_wrap_send_query((const struct sockaddr *)&n->peer,
                            (int)n->peerlen,
                            pkt, (size_t)plen,
                            tid, sizeof(tid),
                            qto, on_tx, slot) < 0) {
        slot_release(slot);
        n->state = NODE_FAILED;
        return;
    }
    n->state = NODE_INFLIGHT;
    L->in_flight++;
    gettimeofday(&slot->send_tv, NULL);

    if (lookup_verbose()) {
        char ip[INET6_ADDRSTRLEN];
        unsigned port = 0;
        if (n->peer.ss_family == AF_INET) {
            const struct sockaddr_in *p4 = (const struct sockaddr_in *)&n->peer;
            inet_ntop(AF_INET, &p4->sin_addr, ip, sizeof(ip));
            port = ntohs(p4->sin_port);
        } else {
            const struct sockaddr_in6 *p6 = (const struct sockaddr_in6 *)&n->peer;
            inet_ntop(AF_INET6, &p6->sin6_addr, ip, sizeof(ip));
            port = ntohs(p6->sin6_port);
        }
        LDBG("[lookup] -> get to %s:%u (idx=%d, has_id=%d)\n",
             ip, port, node_idx, n->has_id);
    }
}

static void
send_more(lookup_run *L)
{
    while (L->in_flight < LOOKUP_ALPHA
           && L->shortlist_count > 0
           && !L->completed) {
        int picked = -1;
        int k = LOOKUP_TOP_K < L->shortlist_count ? LOOKUP_TOP_K : L->shortlist_count;
        for (int i = 0; i < k; i++) {
            if (L->shortlist[i].state == NODE_FRESH) { picked = i; break; }
        }
        if (picked < 0) break;
        send_to(L, picked);
    }
}

static void
ingest_compact_nodes(lookup_run *L, const uint8_t *bytes, size_t len)
{
    for (size_t off = 0; off + COMPACT_NODE_LEN <= len; off += COMPACT_NODE_LEN) {
        const uint8_t *id = bytes + off;
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr, bytes + off + 20, 4);
        memcpy(&sa.sin_port, bytes + off + 24, 2);
        shortlist_insert(L, id, (const struct sockaddr *)&sa, sizeof(sa));
    }
    shortlist_resort(L);
}

/* Parallel parser for BEP 5 "nodes6" (38-byte records: 20 id + 16 ip + 2 port). */
static void
ingest_compact_nodes6(lookup_run *L, const uint8_t *bytes, size_t len)
{
    for (size_t off = 0; off + COMPACT_NODE6_LEN <= len;
         off += COMPACT_NODE6_LEN) {
        const uint8_t *id = bytes + off;
        struct sockaddr_in6 sa = {0};
        sa.sin6_family = AF_INET6;
        memcpy(&sa.sin6_addr, bytes + off + 20, 16);
        memcpy(&sa.sin6_port, bytes + off + 36, 2);
        shortlist_insert(L, id, (const struct sockaddr *)&sa, sizeof(sa));
    }
    shortlist_resort(L);
}

static void
ingest_value(lookup_run *L, const struct sockaddr *peer, socklen_t peerlen,
             const bencode_value *r)
{
    const bencode_value *v = bencode_dict_get(r, "v");
    if (!v) return;
    /* `v` is a bencode value of any type — we re-emit its bencoded form */
    if (L->values_count >= LOOKUP_MAX_VALUES) return;

    lookup_value *lv = &L->values[L->values_count];
    memset(lv, 0, sizeof(*lv));
    if (peer && peerlen > 0
        && peerlen <= (socklen_t)sizeof(lv->from)) {
        memcpy(&lv->from, peer, peerlen);
        lv->fromlen = peerlen;
    }

    /* Store the BENCODED form of v (e.g. "9:hello 888"), not the decoded
     * bytes. Downstream IPC serialisation expects the bencoded form so that
     * a `bencode_str(...)` call wraps it with one outer length prefix and
     * the CLI can re-parse to extract the inner value.
     *
     * For BEP 44 the `v` field is most commonly a bencode string; non-string
     * v is theoretically allowed but unusual. We only support strings here. */
    if (v->type == BENCODE_STR) {
        bencode_writer w;
        bencode_writer_init(&w, lv->v, sizeof(lv->v));
        bencode_str(&w, v->str.bytes, v->str.len);
        ssize_t n = bencode_writer_finish(&w);
        if (n < 0) return;
        lv->v_len = (size_t)n;
    } else {
        /* Emit a generic re-encoding.  TODO: support non-string v.  For now
         * skip — daemons typically wrap as bencode string. */
        return;
    }

    const bencode_value *k   = bencode_dict_get(r, "k");
    const bencode_value *sig = bencode_dict_get(r, "sig");
    const bencode_value *seq = bencode_dict_get(r, "seq");
    if (k && sig && seq && k->type == BENCODE_STR && sig->type == BENCODE_STR
        && seq->type == BENCODE_INT
        && k->str.len == BEP44_PK_LEN && sig->str.len == BEP44_SIG_LEN) {
        memcpy(lv->k, k->str.bytes, BEP44_PK_LEN);
        memcpy(lv->sig, sig->str.bytes, BEP44_SIG_LEN);
        lv->seq = seq->i;
        lv->mutable_ = 1;
    }
    L->values_count++;
}

static void
record_token(lookup_run *L, const struct sockaddr *peer, socklen_t peerlen,
             const bencode_value *token)
{
    if (!token || token->type != BENCODE_STR
        || token->str.len == 0 || token->str.len > sizeof(L->tokens[0].token)) {
        return;
    }
    if (L->tokens_count >= LOOKUP_TOP_K) return;
    if (peerlen <= 0 || peerlen > (socklen_t)sizeof(L->tokens[0].peer)) return;
    lookup_token *t = &L->tokens[L->tokens_count++];
    memcpy(&t->peer, peer, peerlen);
    t->peerlen = peerlen;
    memcpy(t->token, token->str.bytes, token->str.len);
    t->token_len = token->str.len;
}

static void
on_tx(bep44_tx_event ev,
      const struct sockaddr *peer, int peerlen,
      const bencode_value *r,
      const bencode_value *e,
      void *closure)
{
    (void)peerlen; (void)e;
    struct query_slot *slot = closure;
    lookup_run *L = slot ? slot->L : NULL;
    int node_idx = slot ? slot->node_idx : -1;
    if (!L) return;

    /* RTT sample (milliseconds) — computed before slot_release. */
    int rtt_ms = -1;
    if (slot && ev == BEP44_TX_RESPONSE && slot->send_tv.tv_sec) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long dms = (now.tv_sec - slot->send_tv.tv_sec) * 1000
                 + (now.tv_usec - slot->send_tv.tv_usec) / 1000;
        if (dms >= 0 && dms < 60000) rtt_ms = (int)dms;
    }

    if (L->in_flight > 0) L->in_flight--;
    if (slot) slot_release(slot);

    if (node_idx >= 0 && node_idx < L->shortlist_count) {
        L->shortlist[node_idx].state = (ev == BEP44_TX_RESPONSE)
                                       ? NODE_RESPONDED : NODE_FAILED;
    }

    if (ev == BEP44_TX_RESPONSE && r && r->type == BENCODE_DICT) {
        /* learn responder's id, if we didn't have it */
        const bencode_value *id = bencode_dict_get(r, "id");
        if (id && id->type == BENCODE_STR && id->str.len == BEP44_NODE_ID_LEN
            && node_idx >= 0 && !L->shortlist[node_idx].has_id) {
            memcpy(L->shortlist[node_idx].id, id->str.bytes, BEP44_NODE_ID_LEN);
            L->shortlist[node_idx].has_id = 1;
            shortlist_resort(L);
        }

        if (observe_enabled()) {
            const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;
            if (rtt_ms >= 0) observe_rtt(p4, rtt_ms);
            if (id && id->type == BENCODE_STR
                && id->str.len == BEP44_NODE_ID_LEN) {
                /* enrich peer with node_id via a zero-delta upsert */
                extern void db_upsert_peer(const struct sockaddr_in *,
                    const uint8_t *, int, const uint8_t *, size_t,
                    int, int, int, char);
                db_upsert_peer(p4, id->str.bytes, 1, NULL, 0, -1, -1, -1, 0);
            }
            /* Archive any BEP 44 item we just learned (mutable tuples). */
            const bencode_value *vv  = bencode_dict_get(r, "v");
            const bencode_value *kk  = bencode_dict_get(r, "k");
            const bencode_value *sq  = bencode_dict_get(r, "seq");
            const bencode_value *sg  = bencode_dict_get(r, "sig");
            if (vv && vv->type == BENCODE_STR) {
                uint8_t venc[BEP44_MAX_V + 16];
                bencode_writer w;
                bencode_writer_init(&w, venc, sizeof(venc));
                bencode_str(&w, vv->str.bytes, vv->str.len);
                ssize_t vlen = bencode_writer_finish(&w);
                if (vlen > 0) {
                    int mut = (kk && kk->type == BENCODE_STR
                               && kk->str.len == BEP44_PK_LEN
                               && sg && sg->type == BENCODE_STR
                               && sg->str.len == BEP44_SIG_LEN
                               && sq && sq->type == BENCODE_INT) ? 1 : 0;
                    observe_bep44_item(
                        L->target, mut,
                        mut ? kk->str.bytes : NULL, mut ? (size_t)kk->str.len : 0,
                        NULL, 0,
                        mut ? sq->i : 0,
                        mut ? sg->str.bytes : NULL, mut ? (size_t)sg->str.len : 0,
                        venc, (size_t)vlen);
                }
            }
        }

        const bencode_value *nodes  = bencode_dict_get(r, "nodes");
        const bencode_value *nodes6 = bencode_dict_get(r, "nodes6");
        size_t added = 0;
        int before = L->shortlist_count;
        if (nodes  && nodes->type  == BENCODE_STR)
            ingest_compact_nodes (L, nodes->str.bytes,  nodes->str.len);
        if (nodes6 && nodes6->type == BENCODE_STR)
            ingest_compact_nodes6(L, nodes6->str.bytes, nodes6->str.len);
        added = (size_t)(L->shortlist_count - before);

        const bencode_value *token = bencode_dict_get(r, "token");
        record_token(L, peer, (socklen_t)peerlen, token);
        ingest_value(L, peer, (socklen_t)peerlen, r);

        if (lookup_verbose()) {
            char ip[INET6_ADDRSTRLEN];
            unsigned port = 0;
            if (peer->sa_family == AF_INET) {
                const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;
                inet_ntop(AF_INET, &p4->sin_addr, ip, sizeof(ip));
                port = ntohs(p4->sin_port);
            } else {
                const struct sockaddr_in6 *p6 = (const struct sockaddr_in6 *)peer;
                inet_ntop(AF_INET6, &p6->sin6_addr, ip, sizeof(ip));
                port = ntohs(p6->sin6_port);
            }
            const bencode_value *v = bencode_dict_get(r, "v");
            LDBG("[lookup] <- reply %s:%u: nodes_added=%zu has_token=%d "
                 "has_v=%d shortlist=%d values=%d\n",
                 ip, port, added,
                 token && token->type == BENCODE_STR ? 1 : 0,
                 v ? 1 : 0,
                 L->shortlist_count, L->values_count);
        }
    } else if (lookup_verbose()) {
        char ip[INET6_ADDRSTRLEN];
        unsigned port = 0;
        if (peer->sa_family == AF_INET) {
            const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;
            inet_ntop(AF_INET, &p4->sin_addr, ip, sizeof(ip));
            port = ntohs(p4->sin_port);
        } else {
            const struct sockaddr_in6 *p6 = (const struct sockaddr_in6 *)peer;
            inet_ntop(AF_INET6, &p6->sin6_addr, ip, sizeof(ip));
            port = ntohs(p6->sin6_port);
        }
        LDBG("[lookup] <- %s from %s:%u\n",
             ev == BEP44_TX_TIMEOUT ? "timeout" :
             ev == BEP44_TX_ERROR   ? "error"   : "??",
             ip, port);
    }

    if (top_k_done(L)) {
        finish(L);
        return;
    }
    send_more(L);
}

/* ============================================================
 * Public API
 * ============================================================ */

lookup_run *
lookup_start(const uint8_t target[BEP44_TARGET_LEN],
             int timeout_ms,
             lookup_cb cb, void *closure)
{
    /* Acquire a free slot in the global pool. */
    lookup_run *L = NULL;
    for (size_t i = 0; i < LOOKUP_MAX_CONCURRENT; i++) {
        if (!g_pool[i].in_use) { L = &g_pool[i]; break; }
    }
    if (!L) {
        fprintf(stderr, "[dht44:lookup] all %d slots in use\n",
                LOOKUP_MAX_CONCURRENT);
        return NULL;
    }
    memset(L, 0, sizeof(*L));
    L->in_use = 1;
    memcpy(L->target, target, BEP44_TARGET_LEN);
    L->cb = cb;
    L->closure = closure;
    L->deadline = time(NULL) + (timeout_ms + 999) / 1000;

    /*
     * Kick jech's own iterative find_node/get_peers search toward target so
     * closer peers flow into the routing table in parallel with our BEP 44
     * iteration. Fire-and-forget — we'll pick up newly-discovered peers by
     * re-seeding during send_more.
     */
    dht_wrap_kick_search(target);

    /*
     * Seed shortlist from jech's routing table, target-sorted so the
     * closest-by-XOR nodes (with their ids) end up at the head. This fixes
     * cross-daemon convergence: two daemons querying the same target now
     * start from (approximately) the same neighborhood instead of each
     * daemon's own-bucket view.
     */
    struct sockaddr_in seed[LOOKUP_SHORTLIST];
    uint8_t seed_ids[LOOKUP_SHORTLIST][BEP44_NODE_ID_LEN];
    int n = dht_wrap_closest_to(target, seed, seed_ids, LOOKUP_SHORTLIST);
    for (int i = 0; i < n; i++) {
        shortlist_insert(L, seed_ids[i],
                         (const struct sockaddr *)&seed[i], sizeof(seed[i]));
    }
    /* Also seed from the v6 routing table (if populated). */
    struct sockaddr_in6 seed6[LOOKUP_TOP_K];
    uint8_t seed6_ids[LOOKUP_TOP_K][BEP44_NODE_ID_LEN];
    int n6 = dht_wrap_closest6_to(target, seed6, seed6_ids, LOOKUP_TOP_K);
    for (int i = 0; i < n6; i++) {
        shortlist_insert(L, seed6_ids[i],
                         (const struct sockaddr *)&seed6[i], sizeof(seed6[i]));
    }
    n += n6;
    /* Fallback: if neither family returned anything (very early boot),
     * seed from whatever is in the v4 table without ids. */
    if (n == 0) {
        int m = dht_wrap_get_nodes(seed, LOOKUP_TOP_K);
        for (int i = 0; i < m; i++) {
            shortlist_insert(L, NULL,
                             (const struct sockaddr *)&seed[i], sizeof(seed[i]));
        }
        n = m;
    }
    if (lookup_verbose()) {
        char hex[BEP44_TARGET_LEN * 2 + 1];
        static const char *d = "0123456789abcdef";
        for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
            hex[i*2] = d[target[i] >> 4]; hex[i*2+1] = d[target[i] & 0xf];
        }
        hex[BEP44_TARGET_LEN*2] = 0;
        LDBG("[lookup] START target=%s seeded=%d (target-sorted)\n", hex, n);
    }
    if (L->shortlist_count == 0) {
        /* nothing to query — finish immediately as a no-op */
        finish(L);
        return NULL;
    }

    send_more(L);

    if (L->in_flight == 0) {
        /* couldn't send any (e.g. all sends failed) */
        finish(L);
        return NULL;
    }
    return L;
}

void
lookup_tick(int *next_wake_ms)
{
    time_t now = time(NULL);
    long soonest_ms = 60 * 60 * 1000;       /* default 1h ceiling */

    for (size_t i = 0; i < LOOKUP_MAX_CONCURRENT; i++) {
        lookup_run *L = &g_pool[i];
        if (!L->in_use || L->completed) continue;
        if (L->deadline <= now) {
            finish(L);
            continue;
        }
        long ms = (long)(L->deadline - now) * 1000;
        if (ms < soonest_ms) soonest_ms = ms;
    }
    if (next_wake_ms) {
        if (soonest_ms < 0) soonest_ms = 0;
        *next_wake_ms = (int)soonest_ms;
    }
}
