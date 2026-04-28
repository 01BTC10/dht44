#define _POSIX_C_SOURCE 200809L
#include "reputation.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "[dht44:reputation] "

/* ---------- interned string pool (labels + sources) ----------
 *
 * Open-addressed hash table keyed on FNV-1a. Both lookup paths return
 * a `const char *` borrow into the pool. reputation_clear() frees the
 * pool wholesale.
 *
 * The pool needs to handle 100K+ unique labels (iBlockList "combined"
 * mirrors carry per-organisation descriptions). A naive linear scan
 * is O(n²) in load time and made the daemon spin for minutes on
 * startup before the table size hit a steady state. */
struct strpool {
    /* Entries: `count` valid pointers, kept dense. */
    char  **items;
    int     count;
    int     cap;
    /* Hash index: open addressing, indices into `items`. -1 = empty.
     * Sized as 2 * count (next power of 2) so load factor < 0.5. */
    int    *hash;
    int     hash_cap;       /* always a power of 2 */
    int     hash_mask;
};

static uint32_t
fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

static int
strpool_grow_hash(struct strpool *p, int new_cap)
{
    int *n = malloc((size_t)new_cap * sizeof(*n));
    if (!n) return -1;
    for (int i = 0; i < new_cap; i++) n[i] = -1;
    for (int i = 0; i < p->count; i++) {
        uint32_t h = fnv1a(p->items[i]);
        int slot = h & (uint32_t)(new_cap - 1);
        while (n[slot] != -1) slot = (slot + 1) & (new_cap - 1);
        n[slot] = i;
    }
    free(p->hash);
    p->hash     = n;
    p->hash_cap = new_cap;
    p->hash_mask = new_cap - 1;
    return 0;
}

static const char *
strpool_intern(struct strpool *p, const char *s)
{
    if (p->hash_cap == 0) {
        if (strpool_grow_hash(p, 256) < 0) return NULL;
    }
    uint32_t h    = fnv1a(s);
    int      slot = h & (uint32_t)p->hash_mask;
    while (p->hash[slot] != -1) {
        if (strcmp(p->items[p->hash[slot]], s) == 0) return p->items[p->hash[slot]];
        slot = (slot + 1) & p->hash_mask;
    }

    if (p->count == p->cap) {
        int new_cap = p->cap ? p->cap * 2 : 256;
        char **n = realloc(p->items, (size_t)new_cap * sizeof(*n));
        if (!n) return NULL;
        p->items = n;
        p->cap   = new_cap;
    }
    char *copy = strdup(s);
    if (!copy) return NULL;
    int idx = p->count++;
    p->items[idx] = copy;
    p->hash[slot] = idx;

    /* Rehash if load factor exceeds 0.5. */
    if (p->count * 2 >= p->hash_cap) {
        if (strpool_grow_hash(p, p->hash_cap * 2) < 0) {
            /* lookup table is now stale but items[] is intact;
             * subsequent inserts will degrade but not corrupt. */
        }
    }
    return copy;
}

static void
strpool_clear(struct strpool *p)
{
    for (int i = 0; i < p->count; i++) free(p->items[i]);
    free(p->items);
    free(p->hash);
    p->items = NULL;
    p->hash  = NULL;
    p->count = p->cap = p->hash_cap = p->hash_mask = 0;
}

/* ---------- range arrays ---------- */
struct range4 {
    uint32_t    start;          /* host order */
    uint32_t    end;
    const char *source;         /* interned */
    const char *label;          /* interned */
};

struct range6 {
    uint8_t     start[16];
    uint8_t     end[16];
    const char *source;
    const char *label;
};

static struct strpool g_pool;

static struct range4 *g_v4    = NULL;
static int            g_v4_n  = 0;
static int            g_v4_cap = 0;

static struct range6 *g_v6    = NULL;
static int            g_v6_n  = 0;
static int            g_v6_cap = 0;

/* Per-source counters (boot stat). */
static int g_iblocklist_n = 0;
static int g_tor_n        = 0;

/* ---------- helpers ---------- */
static int
range4_cmp(const void *a, const void *b)
{
    const struct range4 *x = a, *y = b;
    if (x->start < y->start) return -1;
    if (x->start > y->start) return 1;
    return 0;
}

static int
range6_cmp(const void *a, const void *b)
{
    const struct range6 *x = a, *y = b;
    return memcmp(x->start, y->start, 16);
}

static int
push_v4(uint32_t start, uint32_t end, const char *source, const char *label)
{
    if (g_v4_n == g_v4_cap) {
        int new_cap = g_v4_cap ? g_v4_cap * 2 : 1024;
        struct range4 *n = realloc(g_v4, (size_t)new_cap * sizeof(*n));
        if (!n) return -1;
        g_v4 = n;
        g_v4_cap = new_cap;
    }
    g_v4[g_v4_n].start  = start;
    g_v4[g_v4_n].end    = end;
    g_v4[g_v4_n].source = source;
    g_v4[g_v4_n].label  = label;
    g_v4_n++;
    return 0;
}

static int
push_v6(const uint8_t start[16], const uint8_t end[16],
        const char *source, const char *label)
{
    if (g_v6_n == g_v6_cap) {
        int new_cap = g_v6_cap ? g_v6_cap * 2 : 256;
        struct range6 *n = realloc(g_v6, (size_t)new_cap * sizeof(*n));
        if (!n) return -1;
        g_v6 = n;
        g_v6_cap = new_cap;
    }
    memcpy(g_v6[g_v6_n].start, start, 16);
    memcpy(g_v6[g_v6_n].end,   end,   16);
    g_v6[g_v6_n].source = source;
    g_v6[g_v6_n].label  = label;
    g_v6_n++;
    return 0;
}

/* Strip leading + trailing whitespace, including \r from CRLF files.
 * Returns a pointer into the buffer. */
static char *
strip(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return s;
}

/* ---------- iBlockList .p2p loader ----------
 * Format: "Description:start_ip-end_ip" per line. Comments # ; and blank
 * lines ignored. We normalise the "description" by truncating at the
 * first '/' so labels stay short ("Anti-P2P" not the full chain). */
static int
load_iblocklist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;             /* silently skip if missing */

    const char *src = strpool_intern(&g_pool, "iblocklist");
    if (!src) { fclose(f); return -1; }

    char  buf[1024];
    int   added = 0;
    int   skipped = 0;
    while (fgets(buf, sizeof(buf), f)) {
        char *line = strip(buf);
        if (!*line || *line == '#' || *line == ';') continue;

        char *colon = strrchr(line, ':');
        char *dash  = colon ? strchr(colon + 1, '-') : NULL;
        if (!colon || !dash) { skipped++; continue; }

        *colon = 0;
        *dash  = 0;
        const char *desc = line;
        const char *a    = colon + 1;
        const char *b    = dash + 1;

        struct in_addr ia, ib;
        if (inet_pton(AF_INET, a, &ia) != 1) { skipped++; continue; }
        if (inet_pton(AF_INET, b, &ib) != 1) { skipped++; continue; }
        uint32_t start = ntohl(ia.s_addr);
        uint32_t end   = ntohl(ib.s_addr);
        if (end < start) { skipped++; continue; }

        /* Truncate at first '/' for a compact label. */
        char short_desc[128];
        size_t dlen = strlen(desc);
        if (dlen >= sizeof(short_desc)) dlen = sizeof(short_desc) - 1;
        memcpy(short_desc, desc, dlen);
        short_desc[dlen] = 0;
        char *slash = strchr(short_desc, '/');
        if (slash) *slash = 0;
        /* Trim again — some entries have trailing whitespace before the colon. */
        size_t L = strlen(short_desc);
        while (L > 0 && isspace((unsigned char)short_desc[L - 1])) short_desc[--L] = 0;
        if (L == 0) snprintf(short_desc, sizeof(short_desc), "blocked");

        const char *label = strpool_intern(&g_pool, short_desc);
        if (!label) continue;
        if (push_v4(start, end, src, label) == 0) added++;
    }
    fclose(f);

    g_iblocklist_n = added;
    fprintf(stderr, TAG "iblocklist: loaded %d ranges from %s%s\n",
            added, path,
            skipped ? " " : "");
    if (skipped)
        fprintf(stderr, TAG "iblocklist: skipped %d malformed lines\n", skipped);
    return added;
}

/* ---------- Tor exit list loader ----------
 * Format: one IP per line, v4 or v6. # comments allowed. */
static int
load_tor_exits(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    const char *src   = strpool_intern(&g_pool, "tor");
    const char *label = strpool_intern(&g_pool, "exit");
    if (!src || !label) { fclose(f); return -1; }

    char  buf[256];
    int   added = 0;
    while (fgets(buf, sizeof(buf), f)) {
        char *line = strip(buf);
        if (!*line || *line == '#' || *line == ';') continue;

        struct in_addr ia;
        if (inet_pton(AF_INET, line, &ia) == 1) {
            uint32_t a = ntohl(ia.s_addr);
            if (push_v4(a, a, src, label) == 0) added++;
            continue;
        }
        struct in6_addr ib;
        if (inet_pton(AF_INET6, line, &ib) == 1) {
            if (push_v6(ib.s6_addr, ib.s6_addr, src, label) == 0) added++;
            continue;
        }
    }
    fclose(f);

    g_tor_n = added;
    fprintf(stderr, TAG "tor-exits: loaded %d entries from %s\n", added, path);
    return added;
}

/* ---------- public API ---------- */
int
reputation_load_dir(const char *dir)
{
    if (!dir) return 0;
    char path[512];

    snprintf(path, sizeof(path), "%s/bt_level1.p2p", dir);
    if (load_iblocklist(path) < 0) return -1;

    snprintf(path, sizeof(path), "%s/tor-exits.txt", dir);
    if (load_tor_exits(path) < 0) return -1;

    /* Sort once; lookups are binary-search. */
    if (g_v4_n) qsort(g_v4, (size_t)g_v4_n, sizeof(*g_v4), range4_cmp);
    if (g_v6_n) qsort(g_v6, (size_t)g_v6_n, sizeof(*g_v6), range6_cmp);

    fprintf(stderr, TAG "ready: %d v4 ranges, %d v6 entries\n",
            g_v4_n, g_v6_n);
    return 0;
}

void
reputation_clear(void)
{
    free(g_v4); g_v4 = NULL; g_v4_n = g_v4_cap = 0;
    free(g_v6); g_v6 = NULL; g_v6_n = g_v6_cap = 0;
    strpool_clear(&g_pool);
    g_iblocklist_n = g_tor_n = 0;
}

/* Find the largest range whose start <= addr, then check end >= addr.
 * Returns the range index or -1. */
static int
binsearch_v4(uint32_t addr)
{
    if (g_v4_n == 0) return -1;
    int lo = 0, hi = g_v4_n - 1, found = -1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_v4[mid].start <= addr) { found = mid; lo = mid + 1; }
        else                          hi = mid - 1;
    }
    if (found < 0) return -1;
    return (g_v4[found].end >= addr) ? found : -1;
}

static int
binsearch_v6(const uint8_t addr[16])
{
    if (g_v6_n == 0) return -1;
    int lo = 0, hi = g_v6_n - 1, found = -1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (memcmp(g_v6[mid].start, addr, 16) <= 0) { found = mid; lo = mid + 1; }
        else                                          hi = mid - 1;
    }
    if (found < 0) return -1;
    return (memcmp(g_v6[found].end, addr, 16) >= 0) ? found : -1;
}

int
reputation_lookup(const struct sockaddr *addr,
                  const char **out_source,
                  const char **out_label)
{
    if (out_source) *out_source = NULL;
    if (out_label)  *out_label  = NULL;
    if (!addr) return 0;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)addr;
        int idx = binsearch_v4(ntohl(sa->sin_addr.s_addr));
        if (idx < 0) return 0;
        if (out_source) *out_source = g_v4[idx].source;
        if (out_label)  *out_label  = g_v4[idx].label;
        return 1;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)addr;
        int idx = binsearch_v6(sa->sin6_addr.s6_addr);
        if (idx < 0) return 0;
        if (out_source) *out_source = g_v6[idx].source;
        if (out_label)  *out_label  = g_v6[idx].label;
        return 1;
    }
    return 0;
}

int reputation_iblocklist_count(void) { return g_iblocklist_n; }
int reputation_tor_count(void)        { return g_tor_n; }
