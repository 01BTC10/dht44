#define _POSIX_C_SOURCE 200809L
#include "crawl.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "bencode.h"
#include "bep44.h"
#include "db.h"
#include "dht_wrap.h"
#include "observe.h"

#define TAG "[dht44:crawl] "

#define CRAWL_MAX_WORKERS   32
#define CRAWL_SHORTLIST     24          /* candidate cap per walk */
#define CRAWL_TOP_K          8          /* termination: top-K all terminated */
#define CRAWL_TX_TIMEOUT_MS 3000

enum {
    CAND_FRESH     = 0,
    CAND_INFLIGHT  = 1,
    CAND_RESPONDED = 2,
    CAND_FAILED    = 3,
};

struct cand {
    struct sockaddr_in peer;
    uint8_t id[BEP44_NODE_ID_LEN];
    uint8_t has_id;
    uint8_t state;
};

struct worker {
    int          in_use;
    uint8_t      target[BEP44_NODE_ID_LEN];
    struct cand  sl[CRAWL_SHORTLIST];
    int          sl_count;
    int          hops;
    int          max_hops;
    int          in_flight;           /* 0 or 1 */
    int          inflight_idx;        /* index into sl, -1 if none */
    struct timeval send_tv;
};

static struct worker g_workers[CRAWL_MAX_WORKERS];
static int           g_worker_n      = 0;
static int           g_pkts_cap      = 100;
static int           g_pkts_this_sec = 0;
static time_t        g_sec_mark      = 0;
static int           g_enabled       = 0;

/* ============================================================
 * XOR distance + shortlist
 * ============================================================ */

/* Return -1, 0, 1 for distance(a, target) vs distance(b, target).
 * Entries without an id sort AFTER entries with one. */
static int
xor_cmp(const struct cand *a, const struct cand *b, const uint8_t *target)
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

/* Insert-or-upgrade a candidate. Returns the final index, or -1 if full.
 * Dedupe by peer address; upgrade id if we just learned one. */
static int
sl_insert(struct worker *w, const struct sockaddr_in *peer,
          const uint8_t *id_or_null)
{
    for (int i = 0; i < w->sl_count; i++) {
        if (sa_eq(&w->sl[i].peer, peer)) {
            if (id_or_null && !w->sl[i].has_id) {
                memcpy(w->sl[i].id, id_or_null, BEP44_NODE_ID_LEN);
                w->sl[i].has_id = 1;
                /* moving this entry may change sort order; bubble it left */
                while (i > 0
                       && xor_cmp(&w->sl[i], &w->sl[i - 1], w->target) < 0) {
                    struct cand tmp = w->sl[i - 1];
                    w->sl[i - 1] = w->sl[i];
                    w->sl[i] = tmp;
                    if (w->inflight_idx == i)     w->inflight_idx = i - 1;
                    else if (w->inflight_idx == i - 1) w->inflight_idx = i;
                    i--;
                }
            }
            return i;
        }
    }
    if (w->sl_count >= CRAWL_SHORTLIST) return -1;

    struct cand c = {0};
    c.peer = *peer;
    c.state = CAND_FRESH;
    if (id_or_null) {
        memcpy(c.id, id_or_null, BEP44_NODE_ID_LEN);
        c.has_id = 1;
    }
    /* position by XOR order */
    int pos = w->sl_count;
    for (int i = 0; i < w->sl_count; i++) {
        if (xor_cmp(&c, &w->sl[i], w->target) < 0) { pos = i; break; }
    }
    if (pos < w->sl_count) {
        memmove(&w->sl[pos + 1], &w->sl[pos],
                sizeof(w->sl[0]) * (size_t)(w->sl_count - pos));
        if (w->inflight_idx >= pos) w->inflight_idx++;
    }
    w->sl[pos] = c;
    w->sl_count++;
    return pos;
}

static int
pick_next_fresh(struct worker *w)
{
    for (int i = 0; i < w->sl_count; i++) {
        if (w->sl[i].state == CAND_FRESH) return i;
    }
    return -1;
}

static int
top_k_done(const struct worker *w)
{
    int k = CRAWL_TOP_K < w->sl_count ? CRAWL_TOP_K : w->sl_count;
    if (k == 0) return 0;
    for (int i = 0; i < k; i++) {
        if (w->sl[i].state != CAND_RESPONDED && w->sl[i].state != CAND_FAILED)
            return 0;
    }
    return 1;
}

static void
rand_target(uint8_t t[BEP44_NODE_ID_LEN])
{
    randombytes_buf(t, BEP44_NODE_ID_LEN);
}

/* Reset the worker for a new random target; re-seed shortlist from jech's
 * routing table. */
static void
worker_reseed(struct worker *w)
{
    rand_target(w->target);
    w->sl_count = 0;
    w->hops = 0;
    w->inflight_idx = -1;

    struct sockaddr_in seed[CRAWL_SHORTLIST];
    uint8_t seed_ids[CRAWL_SHORTLIST][BEP44_NODE_ID_LEN];
    int n = dht_wrap_closest_to(w->target, seed, seed_ids, CRAWL_SHORTLIST);
    for (int i = 0; i < n; i++) sl_insert(w, &seed[i], seed_ids[i]);
}

/* ============================================================
 * find_node builder + tx callback
 * ============================================================ */

static ssize_t
build_find_node(uint8_t *out, size_t cap,
                const uint8_t tid[2],
                const uint8_t our_id[BEP44_NODE_ID_LEN],
                const uint8_t target[BEP44_NODE_ID_LEN])
{
    bencode_writer w;
    bencode_writer_init(&w, out, cap);
    bencode_dict_open(&w);
      bencode_cstr(&w, "a");
      bencode_dict_open(&w);
        bencode_cstr(&w, "id");     bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
        bencode_cstr(&w, "target"); bencode_str(&w, target, BEP44_NODE_ID_LEN);
      bencode_dict_close(&w);
      bencode_cstr(&w, "q"); bencode_cstr(&w, "find_node");
      bencode_cstr(&w, "t"); bencode_str(&w, tid, 2);
      bencode_cstr(&w, "y"); bencode_cstr(&w, "q");
    bencode_dict_close(&w);
    return bencode_writer_finish(&w);
}

/* Ingest a response's compact-nodes blob into the worker's shortlist and
 * record each (responder → neighbour) edge in the db for graph view. */
static void
ingest_compact_nodes(struct worker *w, const struct sockaddr_in *responder,
                     const uint8_t *b, size_t n)
{
    /* Each record is 26 bytes: 20 id + 4 ip + 2 port (both network order). */
    for (size_t i = 0; i + 26 <= n; i += 26) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr.s_addr, b + i + 20, 4);
        memcpy(&sa.sin_port,        b + i + 24, 2);
        sl_insert(w, &sa, b + i);
        if (responder) db_upsert_edge(responder, &sa);
    }
}

static void
on_tx(bep44_tx_event ev,
      const struct sockaddr *peer, int peerlen,
      const bencode_value *r,
      const bencode_value *e,
      void *closure)
{
    (void)peerlen; (void)e;
    struct worker *w = closure;
    if (!w || !w->in_use) return;
    w->in_flight = 0;
    int idx = w->inflight_idx;
    w->inflight_idx = -1;

    const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;

    /* RTT */
    if (ev == BEP44_TX_RESPONSE && w->send_tv.tv_sec) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long dms = (now.tv_sec - w->send_tv.tv_sec) * 1000
                 + (now.tv_usec - w->send_tv.tv_usec) / 1000;
        if (dms >= 0 && dms < 60000) observe_rtt(p4, (int)dms);
    }

    /* Update shortlist state for the probed candidate. */
    if (idx >= 0 && idx < w->sl_count) {
        w->sl[idx].state = (ev == BEP44_TX_RESPONSE)
                           ? CAND_RESPONDED : CAND_FAILED;
    }

    if (ev != BEP44_TX_RESPONSE || !r || r->type != BENCODE_DICT) return;

    /* Responder's node id */
    const bencode_value *id = bencode_dict_get(r, "id");
    if (id && id->type == BENCODE_STR && id->str.len == BEP44_NODE_ID_LEN) {
        db_upsert_peer(p4, id->str.bytes, 1, NULL, 0, -1, -1, -1, 0);
        /* also update our shortlist entry if its id wasn't known */
        if (idx >= 0 && !w->sl[idx].has_id) {
            memcpy(w->sl[idx].id, id->str.bytes, BEP44_NODE_ID_LEN);
            w->sl[idx].has_id = 1;
        }
    }

    /* Ingest compact-nodes directly into OUR shortlist. This is the fix:
     * instead of relying on jech's routing table catching up, we feed the
     * newly learned peers directly into the XOR-sorted worker shortlist
     * so the next probe advances to a closer node immediately. */
    const bencode_value *nodes = bencode_dict_get(r, "nodes");
    if (nodes && nodes->type == BENCODE_STR) {
        ingest_compact_nodes(w, p4, nodes->str.bytes, nodes->str.len);
    }
}

/* ============================================================
 * Worker tick
 * ============================================================ */

static void
worker_send_probe(struct worker *w)
{
    if (w->in_flight) return;

    /* Termination: top-K all terminated → walk done, start a new target. */
    if (top_k_done(w) || w->hops >= w->max_hops) {
        worker_reseed(w);
        if (w->sl_count == 0) return;      /* routing table still warming up */
    }

    int idx = pick_next_fresh(w);
    if (idx < 0) {
        /* No fresh candidates but top-K not all done (e.g. most failed).
         * Treat as walk-complete and move on. */
        worker_reseed(w);
        return;
    }

    struct cand *c = &w->sl[idx];

    uint8_t tid[2];
    dht_wrap_random_tid(tid);
    uint8_t pkt[256];
    ssize_t plen = build_find_node(pkt, sizeof(pkt),
                                   tid, dht_wrap_node_id(), w->target);
    if (plen < 0) return;

    if (dht_wrap_send_query((const struct sockaddr *)&c->peer,
                            (int)sizeof(c->peer),
                            pkt, (size_t)plen,
                            tid, sizeof(tid),
                            CRAWL_TX_TIMEOUT_MS,
                            on_tx, w) < 0) {
        c->state = CAND_FAILED;
        return;
    }
    gettimeofday(&w->send_tv, NULL);
    c->state = CAND_INFLIGHT;
    w->inflight_idx = idx;
    w->in_flight = 1;
    w->hops++;
    g_pkts_this_sec++;
}

/* ============================================================
 * Public API
 * ============================================================ */

int
crawl_start(int workers, int max_pkts_per_sec)
{
    if (g_enabled) return 0;
    if (workers < 1) workers = 1;
    if (workers > CRAWL_MAX_WORKERS) workers = CRAWL_MAX_WORKERS;
    if (max_pkts_per_sec < 1) max_pkts_per_sec = 100;
    g_worker_n = workers;
    g_pkts_cap = max_pkts_per_sec;
    memset(g_workers, 0, sizeof(g_workers));
    for (int i = 0; i < g_worker_n; i++) {
        g_workers[i].in_use = 1;
        g_workers[i].max_hops = 16;
        g_workers[i].inflight_idx = -1;
        /* rand_target + seed happens on first tick via worker_reseed, because
         * jech's routing table may still be empty at crawl_start time. */
        rand_target(g_workers[i].target);
    }
    g_enabled = 1;
    fprintf(stderr, TAG "started %d workers, cap %d pkts/s\n",
            g_worker_n, g_pkts_cap);
    return 0;
}

void
crawl_stop(void)
{
    g_enabled = 0;
    memset(g_workers, 0, sizeof(g_workers));
}

void
crawl_tick(void)
{
    if (!g_enabled) return;
    time_t now = time(NULL);
    if (now != g_sec_mark) { g_sec_mark = now; g_pkts_this_sec = 0; }
    if (g_pkts_this_sec >= g_pkts_cap) return;

    for (int i = 0; i < g_worker_n; i++) {
        if (g_pkts_this_sec >= g_pkts_cap) break;
        struct worker *w = &g_workers[i];
        if (!w->in_use) continue;
        if (w->sl_count == 0) worker_reseed(w);
        worker_send_probe(w);
    }
}
