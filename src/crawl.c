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
#define CRAWL_SHORTLIST     64          /* candidate cap per walk */
#define CRAWL_TOP_K         20          /* termination: top-K all terminated */
#define CRAWL_TX_TIMEOUT_MS 3000

enum {
    CAND_FRESH     = 0,
    CAND_INFLIGHT  = 1,
    CAND_RESPONDED = 2,
    CAND_FAILED    = 3,
};

struct cand {
    struct sockaddr_storage peer;
    socklen_t peerlen;
    uint8_t id[BEP44_NODE_ID_LEN];
    uint8_t has_id;
    uint8_t state;
};

enum {
    WMODE_FIND_NODE        = 0,
    WMODE_SAMPLE_INFOHASHES = 1,
};

struct worker {
    int          in_use;
    int          family;              /* AF_INET or AF_INET6 */
    int          mode;                /* WMODE_* */
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

/* ------------------------------------------------------------------
 * Two cooldown tables:
 *
 * 1. RECENT (30s) — general "don't hammer the same peer" back-off,
 *    applied to every probe so one hot peer doesn't monopolise
 *    workers.
 * 2. BEP51 (peer-declared interval) — BEP 51 responses carry an
 *    `interval` field the responder asks us to honour before we
 *    sample_infohashes them again. Typical value is 6 hours. Separate
 *    LRU so it doesn't fight the 30s general cooldown.
 * ------------------------------------------------------------------ */
#define RECENT_CAP           1024         /* must be power of 2 */
#define RECENT_COOLDOWN_S    30
#define BEP51_CAP            2048
#define BEP51_DEFAULT_INTERVAL_S 3600     /* 1h if peer didn't advertise */

struct recent_entry {
    struct sockaddr_storage peer;
    socklen_t          peerlen;
    time_t             ts;
    int                in_use;
};
static struct recent_entry g_recent[RECENT_CAP];
static int                 g_recent_next = 0;      /* FIFO index */

/* BEP 51 "do not re-sample" table. `expires` is the absolute wall-clock
 * after which we may ask this peer for samples again. */
struct bep51_entry {
    struct sockaddr_storage peer;
    socklen_t          peerlen;
    time_t             expires;
    int                in_use;
};
static struct bep51_entry g_bep51[BEP51_CAP];
static int                g_bep51_next = 0;

static int sa_eq_generic(const struct sockaddr *, const struct sockaddr *);

static int
bep51_is_cooling(const struct sockaddr *p)
{
    time_t now = time(NULL);
    for (int i = 0; i < BEP51_CAP; i++) {
        const struct bep51_entry *b = &g_bep51[i];
        if (!b->in_use) continue;
        if (b->expires <= now) continue;
        if (sa_eq_generic((const struct sockaddr *)&b->peer, p)) return 1;
    }
    return 0;
}

static void
bep51_mark(const struct sockaddr *p, socklen_t peerlen, int interval_s)
{
    if (peerlen > (socklen_t)sizeof(struct sockaddr_storage)) return;
    if (interval_s <= 0) interval_s = BEP51_DEFAULT_INTERVAL_S;
    /* Sanity cap: clamp to 24h — some peers return absurd values. */
    if (interval_s > 86400) interval_s = 86400;

    int i = g_bep51_next;
    memcpy(&g_bep51[i].peer, p, peerlen);
    g_bep51[i].peerlen = peerlen;
    g_bep51[i].expires = time(NULL) + interval_s;
    g_bep51[i].in_use  = 1;
    g_bep51_next = (i + 1) % BEP51_CAP;
}

/* Family-aware equality, copy of the one in dht_wrap. */
static int
sa_eq_generic(const struct sockaddr *a, const struct sockaddr *b)
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

static int
recent_is_hot(const struct sockaddr *p)
{
    time_t cutoff = time(NULL) - RECENT_COOLDOWN_S;
    for (int i = 0; i < RECENT_CAP; i++) {
        const struct recent_entry *r = &g_recent[i];
        if (!r->in_use) continue;
        if (r->ts < cutoff) continue;
        if (sa_eq_generic((const struct sockaddr *)&r->peer, p)) return 1;
    }
    return 0;
}

static void
recent_mark(const struct sockaddr *p, socklen_t peerlen)
{
    if (peerlen > (socklen_t)sizeof(struct sockaddr_storage)) return;
    int i = g_recent_next;
    memcpy(&g_recent[i].peer, p, peerlen);
    g_recent[i].peerlen = peerlen;
    g_recent[i].ts      = time(NULL);
    g_recent[i].in_use  = 1;
    g_recent_next = (i + 1) % RECENT_CAP;
}

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

/* Insert-or-upgrade a candidate. Returns the final index, or -1 if full.
 * Dedupe by peer address; upgrade id if we just learned one. Only accepts
 * peers matching the worker's family (v6 worker ignores v4 candidates and
 * vice versa). */
static int
sl_insert(struct worker *w, const struct sockaddr *peer, socklen_t peerlen,
          const uint8_t *id_or_null)
{
    if (peer->sa_family != w->family) return -1;
    if (peerlen > (socklen_t)sizeof(struct sockaddr_storage)) return -1;

    for (int i = 0; i < w->sl_count; i++) {
        if (sa_eq_generic((const struct sockaddr *)&w->sl[i].peer, peer)) {
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
    struct cand c = {0};
    memcpy(&c.peer, peer, peerlen);
    c.peerlen = peerlen;
    c.state = CAND_FRESH;
    if (id_or_null) {
        memcpy(c.id, id_or_null, BEP44_NODE_ID_LEN);
        c.has_id = 1;
    }
    /* Sorted-insertion position (0 = closest, count = farthest). */
    int pos = w->sl_count;
    for (int i = 0; i < w->sl_count; i++) {
        if (xor_cmp(&c, &w->sl[i], w->target) < 0) { pos = i; break; }
    }

    if (w->sl_count >= CRAWL_SHORTLIST) {
        /* Mirror of the lookup.c fix (commit 48a3958). When the
         * shortlist is full, evict the farthest FRESH entry to make
         * room — only if the new candidate is closer than it.
         * INFLIGHT / RESPONDED / FAILED stay so top_k_done counting
         * and the worker's per-tick bookkeeping remain coherent.
         * Without this, the worker dead-ends in its seed neighborhood
         * and never iterates outward toward the actual closest peers,
         * which truncates per-walk peer discovery and biases BEP 51
         * sample_infohashes coverage toward the same ring.
         *
         * inflight_idx is INFLIGHT-stated, so it's never the eviction
         * target — but eviction's memmove can shift it. Adjust the
         * stored index when the affected window crosses it. */
        int evict = -1;
        for (int i = w->sl_count - 1; i >= 0; i--) {
            if (w->sl[i].state == CAND_FRESH) { evict = i; break; }
        }
        if (evict < 0) return -1;          /* nothing evictable */
        if (pos > evict) return -1;        /* candidate isn't closer */
        if (evict > pos) {
            memmove(&w->sl[pos + 1], &w->sl[pos],
                    sizeof(w->sl[0]) * (size_t)(evict - pos));
            if (w->inflight_idx >= pos && w->inflight_idx < evict)
                w->inflight_idx++;
        }
        w->sl[pos] = c;
        return pos;
    }

    /* Not full — normal insert. */
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
    /* First pass: prefer fresh candidates that aren't on cooldown. Sample
     * workers additionally respect the peer-declared BEP 51 interval. */
    for (int i = 0; i < w->sl_count; i++) {
        if (w->sl[i].state != CAND_FRESH) continue;
        const struct sockaddr *p = (const struct sockaddr *)&w->sl[i].peer;
        if (recent_is_hot(p)) continue;
        if (w->mode == WMODE_SAMPLE_INFOHASHES && bep51_is_cooling(p)) continue;
        return i;
    }
    /* Fallback: if every fresh candidate is on cooldown, use one anyway so
     * the walk doesn't stall. Better to re-probe than to freeze. */
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
 * routing table (the one that matches the worker's family). */
static void
worker_reseed(struct worker *w)
{
    rand_target(w->target);
    w->sl_count = 0;
    w->hops = 0;
    w->inflight_idx = -1;

    if (w->family == AF_INET) {
        struct sockaddr_in seed[CRAWL_SHORTLIST];
        uint8_t seed_ids[CRAWL_SHORTLIST][BEP44_NODE_ID_LEN];
        int n = dht_wrap_closest_to(w->target, seed, seed_ids, CRAWL_SHORTLIST);
        for (int i = 0; i < n; i++) {
            sl_insert(w, (const struct sockaddr *)&seed[i], sizeof(seed[i]),
                      seed_ids[i]);
        }
    } else {
        struct sockaddr_in6 seed[CRAWL_SHORTLIST];
        uint8_t seed_ids[CRAWL_SHORTLIST][BEP44_NODE_ID_LEN];
        int n = dht_wrap_closest6_to(w->target, seed, seed_ids, CRAWL_SHORTLIST);
        for (int i = 0; i < n; i++) {
            sl_insert(w, (const struct sockaddr *)&seed[i], sizeof(seed[i]),
                      seed_ids[i]);
        }
    }
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
        bencode_cstr(&w, "want");
        bencode_list_open(&w);
          bencode_cstr(&w, "n4");
          bencode_cstr(&w, "n6");
        bencode_list_close(&w);
      bencode_dict_close(&w);
      bencode_cstr(&w, "q"); bencode_cstr(&w, "find_node");
      bencode_cstr(&w, "t"); bencode_str(&w, tid, 2);
      bencode_cstr(&w, "y"); bencode_cstr(&w, "q");
    bencode_dict_close(&w);
    return bencode_writer_finish(&w);
}

/* BEP 51 sample_infohashes query. Same shape as find_node but asks the
 * responder to sample from their stored infohashes at the given target. */
static ssize_t
build_sample_infohashes(uint8_t *out, size_t cap,
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
        bencode_cstr(&w, "want");
        bencode_list_open(&w);
          bencode_cstr(&w, "n4");
          bencode_cstr(&w, "n6");
        bencode_list_close(&w);
      bencode_dict_close(&w);
      bencode_cstr(&w, "q"); bencode_cstr(&w, "sample_infohashes");
      bencode_cstr(&w, "t"); bencode_str(&w, tid, 2);
      bencode_cstr(&w, "y"); bencode_cstr(&w, "q");
    bencode_dict_close(&w);
    return bencode_writer_finish(&w);
}

/* Ingest a response's compact-nodes blob into the worker's shortlist and
 * record each (responder → neighbour) edge in the db for graph view. */
static void
ingest_compact_nodes(struct worker *w, const struct sockaddr *responder,
                     socklen_t responderlen,
                     const uint8_t *b, size_t n)
{
    /* 26-byte records: 20 id + 4 ip + 2 port. Goes into the v4 worker's
     * shortlist (rejected by sl_insert for a v6 worker); always records
     * responder→neighbour edges regardless of the worker's family. */
    for (size_t i = 0; i + 26 <= n; i += 26) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr.s_addr, b + i + 20, 4);
        memcpy(&sa.sin_port,        b + i + 24, 2);
        sl_insert(w, (const struct sockaddr *)&sa, sizeof(sa), b + i);
        if (responder) db_upsert_edge(responder, responderlen,
                                      (const struct sockaddr *)&sa, sizeof(sa));
    }
}

/* 38-byte compact6 records: 20 id + 16 ip + 2 port. Enters the shortlist
 * only on v6 workers; always records edges. */
static void
ingest_compact_nodes6(struct worker *w, const struct sockaddr *responder,
                      socklen_t responderlen,
                      const uint8_t *b, size_t n)
{
    for (size_t i = 0; i + 38 <= n; i += 38) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        memcpy(&sa.sin6_addr, b + i + 20, 16);
        memcpy(&sa.sin6_port, b + i + 36,  2);
        sl_insert(w, (const struct sockaddr *)&sa, sizeof(sa), b + i);
        if (responder) db_upsert_edge(responder, responderlen,
                                      (const struct sockaddr *)&sa, sizeof(sa));
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

    /* RTT */
    if (ev == BEP44_TX_RESPONSE && w->send_tv.tv_sec) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long dms = (now.tv_sec - w->send_tv.tv_sec) * 1000
                 + (now.tv_usec - w->send_tv.tv_usec) / 1000;
        if (dms >= 0 && dms < 60000) observe_rtt(peer, (socklen_t)peerlen, (int)dms);
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
        db_upsert_peer(peer, (socklen_t)peerlen, id->str.bytes, 1,
                       NULL, 0, -1, -1, -1, 0);
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
    const bencode_value *nodes  = bencode_dict_get(r, "nodes");
    const bencode_value *nodes6 = bencode_dict_get(r, "nodes6");
    if (nodes && nodes->type == BENCODE_STR) {
        ingest_compact_nodes(w, peer, (socklen_t)peerlen,
                             nodes->str.bytes, nodes->str.len);
    }
    if (nodes6 && nodes6->type == BENCODE_STR) {
        ingest_compact_nodes6(w, peer, (socklen_t)peerlen,
                              nodes6->str.bytes, nodes6->str.len);
    }

    /* BEP 51 sample_infohashes reply: 20-byte hashes concatenated. Presence
     * of this field (even empty) confirms the peer supports BEP 51. */
    const bencode_value *samples = bencode_dict_get(r, "samples");
    if (samples && samples->type == BENCODE_STR) {
        db_mark_peer_bep51(peer, (socklen_t)peerlen);
        const uint8_t *s = samples->str.bytes;
        size_t slen = samples->str.len;
        for (size_t i = 0; i + 20 <= slen; i += 20) {
            db_upsert_infohash(s + i, "bep51");
        }
        /* Honour the peer's declared re-sample interval. */
        const bencode_value *iv = bencode_dict_get(r, "interval");
        int interval_s = (iv && iv->type == BENCODE_INT) ? (int)iv->i : 0;
        bep51_mark(peer, (socklen_t)peerlen, interval_s);
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
    ssize_t plen;
    if (w->mode == WMODE_SAMPLE_INFOHASHES) {
        plen = build_sample_infohashes(pkt, sizeof(pkt),
                                       tid, dht_wrap_node_id(), w->target);
    } else {
        plen = build_find_node(pkt, sizeof(pkt),
                               tid, dht_wrap_node_id(), w->target);
    }
    if (plen < 0) return;

    if (dht_wrap_send_query((const struct sockaddr *)&c->peer,
                            (int)c->peerlen,
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
    recent_mark((const struct sockaddr *)&c->peer, c->peerlen);
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

    /* Assign families round-robin. If only 1 worker requested, it's v4;
     * otherwise 1/4 of workers walk v6 (v6 peer population is smaller so
     * we don't need to match v4's parallelism). Workers on an unsupported
     * family degrade gracefully: worker_reseed returns an empty shortlist
     * when jech's v6 table is empty, and pick_next_fresh returns -1, so
     * the worker just idles until v6 peers show up. */
    /* Family assignment: 1/4 v6, rest v4 (if v6 socket bound).
     * Mode assignment: 1/4 BEP 51 sample_infohashes workers, rest find_node.
     * These axes are independent, so the mix is v4/find_node, v4/sample,
     * v6/find_node, v6/sample. */
    int v6_enabled = dht_wrap_socket6() >= 0;
    for (int i = 0; i < g_worker_n; i++) {
        g_workers[i].in_use = 1;
        g_workers[i].max_hops = 48;
        g_workers[i].inflight_idx = -1;
        g_workers[i].family = (v6_enabled && g_worker_n > 1 && (i % 4) == 3)
                              ? AF_INET6 : AF_INET;
        g_workers[i].mode   = ((i % 4) == 1) ? WMODE_SAMPLE_INFOHASHES
                                             : WMODE_FIND_NODE;
        rand_target(g_workers[i].target);
    }
    int v6_n = 0, sample_n = 0;
    for (int i = 0; i < g_worker_n; i++) {
        if (g_workers[i].family == AF_INET6)           v6_n++;
        if (g_workers[i].mode   == WMODE_SAMPLE_INFOHASHES) sample_n++;
    }
    g_enabled = 1;
    fprintf(stderr,
        TAG "started %d workers (v4=%d v6=%d, find_node=%d sample=%d), cap %d pkts/s\n",
        g_worker_n, g_worker_n - v6_n, v6_n,
        g_worker_n - sample_n, sample_n, g_pkts_cap);
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
