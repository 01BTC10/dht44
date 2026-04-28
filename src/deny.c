#define _POSIX_C_SOURCE 200809L
#include "deny.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "[dht44:deny] "

/* Reason constants. Stable pointers — callers can compare by pointer
 * (strong) or by strcmp (also fine). */
const char *DENY_REASON_REPUTATION = "reputation";
const char *DENY_REASON_RATE_LIMIT = "rate_limit";
const char *DENY_REASON_CLASSIFIER = "classifier";

/* "Strength" of each reason for upgrade-on-conflict. Higher wins. */
static int
reason_rank(const char *r)
{
    if (r == DENY_REASON_REPUTATION) return 3;
    if (r == DENY_REASON_CLASSIFIER) return 2;
    if (r == DENY_REASON_RATE_LIMIT) return 1;
    /* Untrusted strings are never higher than known constants. */
    if (!r) return 0;
    if (strcmp(r, "reputation") == 0) return 3;
    if (strcmp(r, "classifier") == 0) return 2;
    if (strcmp(r, "rate_limit") == 0) return 1;
    return 0;
}

/* Slot key: redacted-friendly string ip + port. We store the ip as a
 * char[] so v4 + v6 handle uniformly. Empty key = free slot. */
struct slot {
    char     ip[INET6_ADDRSTRLEN];
    uint16_t port;
    uint16_t reason_rank;            /* see reason_rank() */
    const char *reason;              /* interned constant */
    time_t   expires_at;
};

#define SLOT_EMPTY(s) ((s)->ip[0] == 0)

static struct slot *g_slots   = NULL;
static int          g_cap     = 0;        /* power of 2 */
static int          g_mask    = 0;
static int          g_count   = 0;
/* Per-reason live counts kept in sync via deny_add / deny_tick. */
static int          g_count_by_reason[4] = {0};   /* 0=other, 1=rate, 2=cls, 3=rep */

static uint32_t
fnv1a(const char *p)
{
    uint32_t h = 2166136261u;
    while (*p) { h ^= (uint8_t)*p++; h *= 16777619u; }
    return h;
}

static int
peer_to_str(const struct sockaddr *peer, socklen_t peerlen,
            char *out_ip, size_t out_cap, uint16_t *out_port)
{
    (void)peerlen;
    if (!peer || !out_ip || out_cap < INET6_ADDRSTRLEN) return -1;
    if (peer->sa_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)peer;
        if (!inet_ntop(AF_INET, &sa->sin_addr, out_ip, out_cap)) return -1;
        if (out_port) *out_port = ntohs(sa->sin_port);
        return 0;
    }
    if (peer->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)peer;
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, out_ip, out_cap)) return -1;
        if (out_port) *out_port = ntohs(sa->sin6_port);
        return 0;
    }
    return -1;
}

/* Open-addressed lookup. Returns slot index (claimed or empty) the
 * caller can write to / read from. -1 if the table is somehow
 * unallocated. */
static int
locate(const char *ip, uint16_t port)
{
    if (g_cap == 0) return -1;
    uint32_t h = fnv1a(ip) ^ (uint32_t)port * 16777619u;
    int slot = (int)(h & (uint32_t)g_mask);
    for (int probes = 0; probes < g_cap; probes++) {
        struct slot *s = &g_slots[slot];
        if (SLOT_EMPTY(s)) return slot;
        if (s->port == port && strcmp(s->ip, ip) == 0) return slot;
        slot = (slot + 1) & g_mask;
    }
    return -1;          /* table full — shouldn't happen with FIFO eviction */
}

/* Compact step: when load factor exceeds 0.5, rehash into a 2x table.
 * Cheap because deny set is bounded by FIFO eviction; growth happens
 * a couple of times during warmup, never at steady state. */
static int
maybe_grow(void)
{
    if ((int64_t)g_count * 2 < (int64_t)g_cap) return 0;
    int new_cap = g_cap ? g_cap * 2 : 256;
    struct slot *n = calloc((size_t)new_cap, sizeof(*n));
    if (!n) return -1;
    struct slot *old = g_slots;
    int old_cap = g_cap;
    g_slots = n;
    g_cap   = new_cap;
    g_mask  = new_cap - 1;
    g_count = 0;
    memset(g_count_by_reason, 0, sizeof(g_count_by_reason));
    if (old) {
        for (int i = 0; i < old_cap; i++) {
            if (SLOT_EMPTY(&old[i])) continue;
            int idx = locate(old[i].ip, old[i].port);
            if (idx >= 0) {
                g_slots[idx] = old[i];
                g_count++;
                g_count_by_reason[old[i].reason_rank]++;
            }
        }
        free(old);
    }
    return 0;
}

/* ---------- public API ---------- */

int
deny_init(void)
{
    if (g_slots) return 0;
    g_cap   = 256;
    g_mask  = g_cap - 1;
    g_slots = calloc((size_t)g_cap, sizeof(*g_slots));
    g_count = 0;
    memset(g_count_by_reason, 0, sizeof(g_count_by_reason));
    if (!g_slots) return -1;
    fprintf(stderr, TAG "ready (cap=%d)\n", g_cap);
    return 0;
}

void
deny_shutdown(void)
{
    free(g_slots);
    g_slots = NULL;
    g_cap = g_mask = g_count = 0;
    memset(g_count_by_reason, 0, sizeof(g_count_by_reason));
}

void
deny_add(const struct sockaddr *peer, socklen_t peerlen,
         const char *reason, int ttl_s)
{
    if (!peer || !reason || ttl_s <= 0) return;
    if (g_cap == 0 && deny_init() < 0) return;
    if (maybe_grow() < 0) return;

    char ip[INET6_ADDRSTRLEN]; uint16_t port = 0;
    if (peer_to_str(peer, peerlen, ip, sizeof(ip), &port) < 0) return;

    int slot = locate(ip, port);
    if (slot < 0) return;
    struct slot *s = &g_slots[slot];
    int  new_rank  = reason_rank(reason);
    time_t now     = time(NULL);
    time_t new_exp = now + ttl_s;
    if (SLOT_EMPTY(s)) {
        snprintf(s->ip, sizeof(s->ip), "%s", ip);
        s->port        = port;
        s->reason      = reason;
        s->reason_rank = (uint16_t)new_rank;
        s->expires_at  = new_exp;
        g_count++;
        g_count_by_reason[new_rank]++;
    } else {
        /* Upgrade reason if stronger; always extend expiry. */
        if (new_rank > s->reason_rank) {
            g_count_by_reason[s->reason_rank]--;
            g_count_by_reason[new_rank]++;
            s->reason      = reason;
            s->reason_rank = (uint16_t)new_rank;
        }
        if (new_exp > s->expires_at) s->expires_at = new_exp;
    }
}

const char *
deny_check(const struct sockaddr *peer, socklen_t peerlen)
{
    if (!peer || g_cap == 0) return NULL;
    char ip[INET6_ADDRSTRLEN]; uint16_t port = 0;
    if (peer_to_str(peer, peerlen, ip, sizeof(ip), &port) < 0) return NULL;
    int slot = locate(ip, port);
    if (slot < 0) return NULL;
    struct slot *s = &g_slots[slot];
    if (SLOT_EMPTY(s)) return NULL;
    if (s->expires_at <= time(NULL)) return NULL;     /* lazy expiry */
    return s->reason;
}

void
deny_tick(time_t now)
{
    if (g_cap == 0) return;
    /* Linear sweep is fine — deny set is bounded (~10K worst case)
     * and tick runs at 1 Hz alongside db_flush. */
    for (int i = 0; i < g_cap; i++) {
        struct slot *s = &g_slots[i];
        if (SLOT_EMPTY(s)) continue;
        if (s->expires_at > now) continue;
        g_count_by_reason[s->reason_rank]--;
        memset(s, 0, sizeof(*s));
        g_count--;
        /* Open-addressing leaves a "tombstone" hole — next insert at
         * this slot is fine; subsequent lookups for keys that originally
         * hashed past it would break. We rehash forward instead. */
        int next = (i + 1) & g_mask;
        while (!SLOT_EMPTY(&g_slots[next])) {
            struct slot tmp = g_slots[next];
            memset(&g_slots[next], 0, sizeof(g_slots[next]));
            g_count_by_reason[tmp.reason_rank]--;
            g_count--;
            int re = locate(tmp.ip, tmp.port);
            if (re >= 0) {
                g_slots[re] = tmp;
                g_count++;
                g_count_by_reason[tmp.reason_rank]++;
            }
            next = (next + 1) & g_mask;
        }
    }
}

void
deny_stats(int *out_total, int out_by_reason[3])
{
    if (out_total) *out_total = g_count;
    if (out_by_reason) {
        /* Public order: rep=0, rate=1, cls=2. Internal order is by rank. */
        out_by_reason[0] = g_count_by_reason[3];   /* rep */
        out_by_reason[1] = g_count_by_reason[1];   /* rate */
        out_by_reason[2] = g_count_by_reason[2];   /* cls */
    }
}
