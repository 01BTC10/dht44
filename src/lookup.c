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

static int lookup_verbose(void) {
    static int v = -1;
    if (v < 0) v = getenv("DHT44_LOOKUP_DEBUG") ? 1 : 0;
    return v;
}

#define LDBG(...) do { if (lookup_verbose()) fprintf(stderr, __VA_ARGS__); } while (0)

#define COMPACT_NODE_LEN 26   /* 20 id + 4 ip + 2 port */

enum {
    NODE_FRESH = 0,
    NODE_INFLIGHT,
    NODE_RESPONDED,
    NODE_FAILED,
};

struct lookup_node {
    struct sockaddr_in peer;
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

static int
sa_eq(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr
        && a->sin_port        == b->sin_port;
}

/* Insert sorted by distance. Returns the inserted index, or -1 if the
 * candidate is already present or shortlist is full. */
static int
shortlist_insert(lookup_run *L, const uint8_t *id_or_null,
                 const struct sockaddr_in *peer)
{
    /* dedupe by addr */
    for (int i = 0; i < L->shortlist_count; i++) {
        if (sa_eq(&L->shortlist[i].peer, peer)) {
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
    n.peer = *peer;
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
                            (int)sizeof(n->peer),
                            pkt, (size_t)plen,
                            tid, sizeof(tid),
                            qto, on_tx, slot) < 0) {
        slot_release(slot);
        n->state = NODE_FAILED;
        return;
    }
    n->state = NODE_INFLIGHT;
    L->in_flight++;

    if (lookup_verbose()) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &n->peer.sin_addr, ip, sizeof(ip));
        LDBG("[lookup] -> get to %s:%u (idx=%d, has_id=%d)\n",
             ip, ntohs(n->peer.sin_port), node_idx, n->has_id);
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
        shortlist_insert(L, id, &sa);
    }
    shortlist_resort(L);
}

static void
ingest_value(lookup_run *L, const struct sockaddr *peer,
             const bencode_value *r)
{
    const bencode_value *v = bencode_dict_get(r, "v");
    if (!v) return;
    /* `v` is a bencode value of any type — we re-emit its bencoded form */
    if (L->values_count >= LOOKUP_MAX_VALUES) return;

    /* Compute the encoded length of `v` by re-walking. Easier: store as
     * encoded bytes by using a writer with the original `r` source
     * available through r->str.bytes/etc. For strings we know exactly. */

    lookup_value *lv = &L->values[L->values_count];
    memset(lv, 0, sizeof(*lv));
    if (peer) lv->from = *(const struct sockaddr_in *)peer;

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
record_token(lookup_run *L, const struct sockaddr *peer,
             const bencode_value *token)
{
    if (!token || token->type != BENCODE_STR
        || token->str.len == 0 || token->str.len > sizeof(L->tokens[0].token)) {
        return;
    }
    if (L->tokens_count >= LOOKUP_TOP_K) return;
    lookup_token *t = &L->tokens[L->tokens_count++];
    t->peer = *(const struct sockaddr_in *)peer;
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

        const bencode_value *nodes = bencode_dict_get(r, "nodes");
        size_t added = 0;
        if (nodes && nodes->type == BENCODE_STR) {
            int before = L->shortlist_count;
            ingest_compact_nodes(L, nodes->str.bytes, nodes->str.len);
            added = (size_t)(L->shortlist_count - before);
        }

        const bencode_value *token = bencode_dict_get(r, "token");
        record_token(L, peer, token);
        ingest_value(L, peer, r);

        if (lookup_verbose()) {
            const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &p4->sin_addr, ip, sizeof(ip));
            const bencode_value *v = bencode_dict_get(r, "v");
            LDBG("[lookup] <- reply %s:%u: nodes_added=%zu has_token=%d "
                 "has_v=%d shortlist=%d values=%d\n",
                 ip, ntohs(p4->sin_port), added,
                 token && token->type == BENCODE_STR ? 1 : 0,
                 v ? 1 : 0,
                 L->shortlist_count, L->values_count);
        }
    } else if (lookup_verbose()) {
        const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &p4->sin_addr, ip, sizeof(ip));
        LDBG("[lookup] <- %s from %s:%u\n",
             ev == BEP44_TX_TIMEOUT ? "timeout" :
             ev == BEP44_TX_ERROR   ? "error"   : "??",
             ip, ntohs(p4->sin_port));
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

    /* Seed shortlist from jech's table. We don't know ids; insertion sort
     * places them at the end. They'll be re-sorted as we learn ids. */
    struct sockaddr_in seed[LOOKUP_TOP_K];
    int n = dht_wrap_get_nodes(seed, LOOKUP_TOP_K);
    for (int i = 0; i < n; i++) {
        shortlist_insert(L, NULL, &seed[i]);
    }
    if (lookup_verbose()) {
        char hex[BEP44_TARGET_LEN * 2 + 1];
        static const char *d = "0123456789abcdef";
        for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
            hex[i*2] = d[target[i] >> 4]; hex[i*2+1] = d[target[i] & 0xf];
        }
        hex[BEP44_TARGET_LEN*2] = 0;
        LDBG("[lookup] START target=%s seeded=%d\n", hex, n);
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
