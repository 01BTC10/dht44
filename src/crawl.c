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

#define CRAWL_MAX_WORKERS 32
#define CRAWL_TX_TIMEOUT_MS 3000

struct worker {
    int            in_use;
    uint8_t        target[BEP44_NODE_ID_LEN];
    int            hops;          /* find_nodes sent for this target */
    int            max_hops;      /* iteration cap */
    int            in_flight;     /* 0 or 1 */
    struct timeval send_tv;
    struct sockaddr_in last_peer; /* peer we sent to, for RTT attribution */
};

static struct worker g_workers[CRAWL_MAX_WORKERS];
static int           g_worker_n      = 0;
static int           g_pkts_cap      = 100;  /* outbound packets per second */
static int           g_pkts_this_sec = 0;
static time_t        g_sec_mark      = 0;
static int           g_enabled       = 0;

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

    if (ev != BEP44_TX_RESPONSE || !r || r->type != BENCODE_DICT) return;

    const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;

    /* RTT */
    if (w->send_tv.tv_sec) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long dms = (now.tv_sec - w->send_tv.tv_sec) * 1000
                 + (now.tv_usec - w->send_tv.tv_usec) / 1000;
        if (dms >= 0 && dms < 60000) observe_rtt(p4, (int)dms);
    }

    /* Capture responder's node_id. */
    const bencode_value *id = bencode_dict_get(r, "id");
    if (id && id->type == BENCODE_STR && id->str.len == BEP44_NODE_ID_LEN) {
        db_upsert_peer(p4, id->str.bytes, 1, NULL, 0, -1, -1, -1, 0);
    }

    /* Compact-nodes list: ingest node IDs & IP/port pairs. Every peer seen is
     * already logged via the observer from the inbound packet itself; here we
     * want to extract them specifically so we can drive the next find_node at
     * a closer candidate. */
    const bencode_value *nodes = bencode_dict_get(r, "nodes");
    if (!nodes || nodes->type != BENCODE_STR) return;

    const uint8_t *b = nodes->str.bytes;
    size_t n = nodes->str.len;
    /* Each record is 26 bytes: 20 id + 4 ip + 2 port */
    uint8_t best_id[BEP44_NODE_ID_LEN];
    struct sockaddr_in best_peer;
    int have_best = 0;
    int best_xor_first = 256;
    memset(&best_peer, 0, sizeof(best_peer));

    for (size_t i = 0; i + 26 <= n; i += 26) {
        const uint8_t *nid = b + i;
        uint32_t ip; uint16_t port;
        memcpy(&ip,   b + i + 20, 4);
        memcpy(&port, b + i + 24, 2);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = ip;     /* network order */
        sa.sin_port        = port;   /* network order */

        /* XOR distance (first differing bit count, low is better). */
        int xd = 0;
        int j = 0;
        while (j < BEP44_NODE_ID_LEN
               && (nid[j] ^ w->target[j]) == 0) { j++; xd += 8; }
        if (j < BEP44_NODE_ID_LEN) {
            uint8_t d = nid[j] ^ w->target[j];
            while ((d & 0x80) == 0) { d <<= 1; xd++; }
        }
        if (xd > best_xor_first) {       /* larger first-diff = closer */
            best_xor_first = xd;
            memcpy(best_id, nid, BEP44_NODE_ID_LEN);
            best_peer = sa;
            have_best = 1;
        }
    }
    (void)peer;
    (void)best_id;
    if (have_best) {
        /* Queue another hop toward best. The next crawl_tick pulls workers. */
        /* (we just mutate the worker's target closer? No — keep target fixed,
         * peers returned in this response are ALSO already logged, the main
         * job done. Just mark in_flight=0 so tick sends another find_node
         * toward the same target hitting the now-closer candidate.) */
        /* Remember best_peer on the worker for next send. */
        /* For simplicity we reuse closest-by-target selection each tick
         * via dht_wrap_closest_to, which already reflects the newly learned
         * node because the inbound packet also hit jech's routing table. */
    }
}

/* ============================================================
 * Worker tick
 * ============================================================ */

static void
rand_target(uint8_t t[BEP44_NODE_ID_LEN])
{
    randombytes_buf(t, BEP44_NODE_ID_LEN);
}

static void
worker_send_probe(struct worker *w)
{
    if (w->in_flight) return;

    /* Pick closest known peer to w->target. */
    struct sockaddr_in closest[4];
    uint8_t ids[4][BEP44_NODE_ID_LEN];
    int n = dht_wrap_closest_to(w->target, closest, ids, 4);
    if (n <= 0) return;

    struct sockaddr_in *p4 = &closest[0];

    uint8_t tid[2];
    dht_wrap_random_tid(tid);
    uint8_t pkt[256];
    ssize_t plen = build_find_node(pkt, sizeof(pkt),
                                   tid, dht_wrap_node_id(), w->target);
    if (plen < 0) return;

    if (dht_wrap_send_query((const struct sockaddr *)p4,
                            (int)sizeof(*p4),
                            pkt, (size_t)plen,
                            tid, sizeof(tid),
                            CRAWL_TX_TIMEOUT_MS,
                            on_tx, w) < 0) {
        return;
    }
    gettimeofday(&w->send_tv, NULL);
    w->last_peer = *p4;
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
        g_workers[i].max_hops = 24;
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
        if (w->hops >= w->max_hops) {
            rand_target(w->target);
            w->hops = 0;
        }
        worker_send_probe(w);
    }
    (void)observe_enabled;      /* referenced indirectly via dht_wrap hooks */
}
