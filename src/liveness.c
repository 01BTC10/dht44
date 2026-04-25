#include "liveness.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "db.h"

/* Provided by jech/dht (vendor/jech-dht/dht.h). */
extern int dht_ping_node(const struct sockaddr *sa, int salen);

#define TAG "[dht44:liveness] "

static int      g_window_s   = 0;       /* re-ping cadence per peer */
static int      g_max_pps    = 0;       /* upper bound on ping rate */
static int      g_prune_s    = 0;       /* prune peers stale this long */
static time_t   g_last_tick  = 0;
static time_t   g_last_prune = 0;
static int64_t  g_pings_sent = 0;

#define BATCH 64                        /* candidates pulled per tick */

void
liveness_start(int window_hours, int max_pps, int prune_days)
{
    if (window_hours <= 0) window_hours = 6;
    if (max_pps      <= 0) max_pps      = 50;
    g_window_s   = window_hours * 3600;
    g_max_pps    = max_pps;
    g_prune_s    = (prune_days > 0) ? prune_days * 86400 : 0;
    g_last_tick  = 0;
    g_last_prune = 0;
    g_pings_sent = 0;
    fprintf(stderr, TAG "started: window=%dh, max_pps=%d, prune=%dd\n",
            window_hours, max_pps, prune_days);
}

void
liveness_stop(void)
{
    fprintf(stderr, TAG "stopped (sent %lld pings total)\n",
            (long long)g_pings_sent);
    g_window_s = g_max_pps = g_prune_s = 0;
}

static void
do_prune(time_t now)
{
    if (g_prune_s <= 0) return;
    /* Run once per hour. */
    if (g_last_prune && now - g_last_prune < 3600) return;
    g_last_prune = now;
    int n = db_prune_peers_older_than((int64_t)now - g_prune_s);
    if (n > 0) fprintf(stderr, TAG "pruned %d peers (last_seen older than %dd)\n",
                       n, g_prune_s / 86400);
}

void
liveness_tick(void)
{
    if (g_window_s <= 0) return;
    time_t now = time(NULL);
    if (g_last_tick == 0) g_last_tick = now;

    /* Pace: send up to g_max_pps pings per second; one tick covers the
     * elapsed wall time since the previous tick. */
    long elapsed = (long)(now - g_last_tick);
    if (elapsed <= 0) {
        do_prune(now);
        return;
    }
    if (elapsed > 5) elapsed = 5;       /* cap catch-up after a stall */
    int budget = g_max_pps * (int)elapsed;
    if (budget > BATCH * 4) budget = BATCH * 4;
    g_last_tick = now;

    int64_t threshold = (int64_t)now - g_window_s;
    while (budget > 0) {
        struct sockaddr_storage addrs[BATCH];
        int                     lens [BATCH];
        int n = db_select_liveness_candidates(
                    budget < BATCH ? budget : BATCH,
                    threshold, addrs, lens);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) {
            dht_ping_node((struct sockaddr *)&addrs[i], lens[i]);
            db_mark_pinged((struct sockaddr *)&addrs[i], lens[i], (int64_t)now);
            g_pings_sent++;
        }
        budget -= n;
        if (n < BATCH) break;           /* exhausted candidates */
    }

    do_prune(now);
}
