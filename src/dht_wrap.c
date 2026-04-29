/*
 * jech/dht glue (callbacks + init/bootstrap/loop step + BEP 44 dispatch).
 *
 * jech/dht owns the routing table and BEP 5 wire ops; we own BEP 44. Every
 * received packet is peeked: if it is a BEP 44 query (y="q" && q∈{get,put})
 * or a response to one of our pending BEP 44 transactions, we dispatch it
 * locally and DO NOT forward to dht_periodic. Everything else (pings,
 * find_node, get_peers, etc.) goes to dht_periodic so jech keeps its table
 * fresh.
 */

#define _GNU_SOURCE

#include "dht_wrap.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <sodium.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

#include "bencode.h"
#include "db.h"
#include "deny.h"
#include "dht.h"
#include "observe.h"
#include "reputation.h"
#include "state.h"

/* ============================================================
 * jech-required callbacks
 * ============================================================ */

int
dht_sendto(int sockfd, const void *buf, int len, int flags,
           const struct sockaddr *to, int tolen)
{
    return sendto(sockfd, buf, (size_t)len, flags, to, (socklen_t)tolen);
}

int
dht_blacklisted(const struct sockaddr *sa, int salen)
{
    (void)sa; (void)salen;
    return 0;
}

void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, v1, (size_t)len1);
    EVP_DigestUpdate(ctx, v2, (size_t)len2);
    EVP_DigestUpdate(ctx, v3, (size_t)len3);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    int copy = (int)dlen < hash_size ? (int)dlen : hash_size;
    memcpy(hash_return, digest, (size_t)copy);
    if (copy < hash_size) {
        memset((char *)hash_return + copy, 0, (size_t)(hash_size - copy));
    }
}

int
dht_random_bytes(void *buf, size_t size)
{
    randombytes_buf(buf, size);
    return (int)size;
}

/* ============================================================
 * Internal state
 * ============================================================ */

#define MAX_PENDING_TX 256
#define MAX_RECV       2048

struct pending_tx {
    int            in_use;
    uint8_t        tid[2];
    struct sockaddr_storage peer;
    socklen_t      peerlen;
    time_t         deadline;
    bep44_tx_cb    cb;
    void          *closure;
};

static int                s_sock  = -1;       /* AF_INET UDP */
static int                s_sock6 = -1;       /* AF_INET6 UDP, -1 if disabled */
static uint8_t            s_node_id[20];
static int                s_initialised = 0;

static struct pending_tx  s_pending[MAX_PENDING_TX];

static bep44_query_cb     s_query_cb = NULL;
static void              *s_query_cb_closure = NULL;

/* ============================================================
 * Bencode peek (hot path, no allocation)
 * ============================================================ */

static int
peek_skip_value(const uint8_t *buf, size_t len, size_t *pos)
{
    if (*pos >= len) return -1;
    int c = buf[*pos];
    if (c == 'i') {
        (*pos)++;
        if (*pos < len && buf[*pos] == '-') (*pos)++;
        size_t start = *pos;
        while (*pos < len && buf[*pos] >= '0' && buf[*pos] <= '9') (*pos)++;
        if (*pos == start) return -1;
        if (*pos >= len || buf[*pos] != 'e') return -1;
        (*pos)++;
        return 0;
    }
    if (c == 'l') {
        (*pos)++;
        while (*pos < len && buf[*pos] != 'e') {
            if (peek_skip_value(buf, len, pos) < 0) return -1;
        }
        if (*pos >= len) return -1;
        (*pos)++;
        return 0;
    }
    if (c == 'd') {
        (*pos)++;
        while (*pos < len && buf[*pos] != 'e') {
            if (peek_skip_value(buf, len, pos) < 0) return -1;     /* key  */
            if (peek_skip_value(buf, len, pos) < 0) return -1;     /* val  */
        }
        if (*pos >= len) return -1;
        (*pos)++;
        return 0;
    }
    if (c >= '0' && c <= '9') {
        size_t n = 0;
        while (*pos < len && buf[*pos] >= '0' && buf[*pos] <= '9') {
            n = n * 10 + (size_t)(buf[*pos] - '0');
            (*pos)++;
        }
        if (*pos >= len || buf[*pos] != ':') return -1;
        (*pos)++;
        if (n > len - *pos) return -1;
        *pos += n;
        return 0;
    }
    return -1;
}

static int
peek_string_at(const uint8_t *buf, size_t len, size_t pos,
               const uint8_t **out, size_t *out_len)
{
    if (pos >= len || buf[pos] < '0' || buf[pos] > '9') return -1;
    size_t n = 0;
    while (pos < len && buf[pos] >= '0' && buf[pos] <= '9') {
        n = n * 10 + (size_t)(buf[pos] - '0');
        pos++;
    }
    if (pos >= len || buf[pos] != ':') return -1;
    pos++;
    if (n > len - pos) return -1;
    *out = buf + pos;
    *out_len = n;
    return 0;
}

int
dht_wrap_peek_top(const uint8_t *buf, size_t len, dht_wrap_peek *out)
{
    out->y = out->q = out->t = out->v = NULL;
    out->y_len = out->q_len = out->t_len = out->v_len = 0;
    out->ro = -1;
    if (len < 2 || buf[0] != 'd') return -1;

    size_t pos = 1;
    while (pos < len && buf[pos] != 'e') {
        const uint8_t *key;
        size_t klen;
        if (peek_string_at(buf, len, pos, &key, &klen) < 0) return -1;
        size_t after_key = (size_t)(key - buf) + klen;
        size_t val_start = after_key;
        size_t val_end = val_start;
        if (peek_skip_value(buf, len, &val_end) < 0) return -1;

        if (klen == 1) {
            const uint8_t **slot = NULL;
            size_t *slot_len = NULL;
            switch (key[0]) {
                case 'y': slot = &out->y; slot_len = &out->y_len; break;
                case 'q': slot = &out->q; slot_len = &out->q_len; break;
                case 't': slot = &out->t; slot_len = &out->t_len; break;
                case 'v': slot = &out->v; slot_len = &out->v_len; break;
            }
            if (slot) {
                /* must be a string */
                const uint8_t *vbytes;
                size_t vlen;
                if (peek_string_at(buf, len, val_start, &vbytes, &vlen) == 0) {
                    *slot = vbytes;
                    *slot_len = vlen;
                }
            }
        } else if (klen == 2 && key[0] == 'r' && key[1] == 'o') {
            /* "ro" — bencode integer "i0e" or "i1e" */
            if (val_start < len && buf[val_start] == 'i'
                && val_end > val_start + 2 && buf[val_end - 1] == 'e') {
                size_t p = val_start + 1;
                int neg = 0;
                if (p < len && buf[p] == '-') { neg = 1; p++; }
                long n = 0;
                while (p < val_end - 1 && buf[p] >= '0' && buf[p] <= '9') {
                    n = n * 10 + (buf[p] - '0');
                    p++;
                }
                if (p == val_end - 1) out->ro = neg ? 0 : (n ? 1 : 0);
            }
        }
        pos = val_end;
    }
    if (out->y == NULL || out->t == NULL) return -1;
    return 0;
}

/* ============================================================
 * Pending-tx table
 * ============================================================ */

/* Family-aware sockaddr equality (ip + port match, ignoring trailing bytes). */
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

static struct pending_tx *
pending_find_match(const uint8_t *tid, size_t tid_len,
                   const struct sockaddr *peer)
{
    if (tid_len != 2) return NULL;
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (!s_pending[i].in_use) continue;
        if (s_pending[i].tid[0] != tid[0] || s_pending[i].tid[1] != tid[1]) continue;
        if (!sa_eq_generic((const struct sockaddr *)&s_pending[i].peer, peer)) continue;
        return &s_pending[i];
    }
    return NULL;
}

static void
pending_release(struct pending_tx *t)
{
    t->in_use = 0;
    t->cb = NULL;
    t->closure = NULL;
}

static int
pending_register(const uint8_t tid[2],
                 const struct sockaddr *peer, socklen_t peerlen,
                 int timeout_ms, bep44_tx_cb cb, void *closure)
{
    if (peerlen > (socklen_t)sizeof(struct sockaddr_storage)) return -1;
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (s_pending[i].in_use) continue;
        s_pending[i].in_use = 1;
        s_pending[i].tid[0] = tid[0];
        s_pending[i].tid[1] = tid[1];
        memcpy(&s_pending[i].peer, peer, peerlen);
        s_pending[i].peerlen = peerlen;
        s_pending[i].deadline = time(NULL) + (timeout_ms + 999) / 1000;
        s_pending[i].cb = cb;
        s_pending[i].closure = closure;
        return 0;
    }
    fprintf(stderr, "[dht44:dht_wrap] pending tx table full\n");
    return -1;
}

static void
pending_sweep(void)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (!s_pending[i].in_use) continue;
        if (s_pending[i].deadline > now) continue;
        bep44_tx_cb  cb = s_pending[i].cb;
        void        *cl = s_pending[i].closure;
        struct sockaddr_storage peer = s_pending[i].peer;
        socklen_t peerlen = s_pending[i].peerlen;
        pending_release(&s_pending[i]);
        if (cb) cb(BEP44_TX_TIMEOUT,
                   (const struct sockaddr *)&peer, (int)peerlen,
                   NULL, NULL, cl);
    }
}

static int
pending_next_deadline_ms(void)
{
    time_t now = time(NULL);
    time_t soonest = 0;
    int found = 0;
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (!s_pending[i].in_use) continue;
        if (!found || s_pending[i].deadline < soonest) {
            soonest = s_pending[i].deadline;
            found = 1;
        }
    }
    if (!found) return INT32_MAX;
    if (soonest <= now) return 0;
    long ms = (long)(soonest - now) * 1000;
    return ms > INT32_MAX ? INT32_MAX : (int)ms;
}

void
dht_wrap_random_tid(uint8_t out[2])
{
    randombytes_buf(out, 2);
}

/* ============================================================
 * Lifecycle
 * ============================================================ */

/* Helper: open a non-blocking UDP socket of the given family, bound to port.
 * Returns fd on success, -1 on failure (errno preserved). For AF_INET6 we
 * set IPV6_V6ONLY=1 so v4-mapped traffic doesn't double-count. */
static int
udp_bind(int family, uint16_t port)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int e = errno; close(fd); errno = e; return -1;
    }

    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t slen;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_ANY);
        a->sin_port = htons(port);
        slen = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_any;
        a->sin6_port = htons(port);
        slen = sizeof(*a);
    }
    if (bind(fd, (struct sockaddr *)&ss, slen) < 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    return fd;
}

int
dht_wrap_init(uint16_t port)
{
    return dht_wrap_init_opt(port, /*want_ipv6=*/1);
}

int
dht_wrap_init_opt(uint16_t port, int want_ipv6)
{
    if (s_initialised) {
        fprintf(stderr, "[dht44:dht_wrap] already initialised\n");
        return -1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "[dht44:dht_wrap] sodium_init failed\n");
        return -1;
    }
    memset(s_pending, 0, sizeof(s_pending));

    s_sock = udp_bind(AF_INET, port);
    if (s_sock < 0) {
        fprintf(stderr, "[dht44:dht_wrap] bind v4 :%u: %s\n",
                (unsigned)port, strerror(errno));
        return -1;
    }

    if (want_ipv6) {
        s_sock6 = udp_bind(AF_INET6, port);
        if (s_sock6 < 0) {
            fprintf(stderr, "[dht44:dht_wrap] bind v6 [::]:%u: %s (continuing v4-only)\n",
                    (unsigned)port, strerror(errno));
        }
    }

    if (state_get_node_id(s_node_id) < 0) {
        close(s_sock); s_sock = -1;
        if (s_sock6 >= 0) { close(s_sock6); s_sock6 = -1; }
        return -1;
    }

    /* Optional jech-internal debug logging via env var */
    if (getenv("DHT_DEBUG")) {
        extern FILE *dht_debug;
        dht_debug = stderr;
    }
    /* Version: "DH44" — 4 bytes. Pass both fds to jech so it maintains a
     * v4 and v6 routing table; s_sock6 may be -1 if v6 is disabled. */
    if (dht_init(s_sock, s_sock6, s_node_id, (const unsigned char *)"DH44") < 0) {
        fprintf(stderr, "[dht44:dht_wrap] dht_init failed\n");
        close(s_sock); s_sock = -1;
        if (s_sock6 >= 0) { close(s_sock6); s_sock6 = -1; }
        return -1;
    }
    s_initialised = 1;
    fprintf(stderr, "[dht44:dht_wrap] bound :%u v4%s\n", (unsigned)port,
            s_sock6 >= 0 ? " + v6" : " (v6 disabled)");
    return 0;
}

void
dht_wrap_uninit(void)
{
    if (s_initialised) {
        dht_uninit();
        s_initialised = 0;
    }
    if (s_sock  >= 0) { close(s_sock);  s_sock  = -1; }
    if (s_sock6 >= 0) { close(s_sock6); s_sock6 = -1; }
    memset(s_pending, 0, sizeof(s_pending));
    s_query_cb = NULL;
    s_query_cb_closure = NULL;
}

int dht_wrap_socket(void)  { return s_sock;  }
int dht_wrap_socket6(void) { return s_sock6; }
const uint8_t *dht_wrap_node_id(void) { return s_node_id; }

void
dht_wrap_set_query_handler(bep44_query_cb cb, void *closure)
{
    s_query_cb = cb;
    s_query_cb_closure = closure;
}

/* ============================================================
 * Bootstrap
 * ============================================================ */

static const struct {
    const char *host;
    const char *port;
} ROUTERS[] = {
    { "router.bittorrent.com",   "6881" },
    { "dht.transmissionbt.com",  "6881" },
    { "router.utorrent.com",     "6881" },
    { "router.bitcomet.com",     "6881" },
};

int
dht_wrap_ping_routers(void)
{
    if (!s_initialised) return -1;
    int pinged = 0;
    for (size_t i = 0; i < sizeof(ROUTERS) / sizeof(ROUTERS[0]); i++) {
        /* Resolve both A and AAAA so v6 routers get pinged over s_sock6. */
        struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
        struct addrinfo *res = NULL;
        int rc = getaddrinfo(ROUTERS[i].host, ROUTERS[i].port, &hints, &res);
        if (rc != 0) {
            fprintf(stderr, "[dht44:dht_wrap] resolve %s: %s\n",
                    ROUTERS[i].host, gai_strerror(rc));
            continue;
        }
        int v4_done = 0, v6_done = 0;
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET  && v4_done) continue;
            if (ai->ai_family == AF_INET6 && v6_done) continue;
            if (ai->ai_family == AF_INET6 && s_sock6 < 0) continue;
            if (dht_ping_node(ai->ai_addr, (int)ai->ai_addrlen) >= 0) {
                pinged++;
                if (ai->ai_family == AF_INET)  v4_done = 1;
                if (ai->ai_family == AF_INET6) v6_done = 1;
            }
        }
        freeaddrinfo(res);
    }
    return pinged;
}

int
dht_wrap_insert_warm(const struct sockaddr_in *sa)
{
    /* dht_insert_node requires a node_id, which we don't have for warm-start
     * peers (nodes.bin only stores addresses). Soft-bootstrap by pinging:
     * jech inserts the responder into the table with the correct id. */
    if (!s_initialised) return -1;
    return dht_ping_node((const struct sockaddr *)sa, (int)sizeof(*sa));
}

int
dht_wrap_insert_warm6(const struct sockaddr_in6 *sa)
{
    if (!s_initialised || s_sock6 < 0) return -1;
    return dht_ping_node((const struct sockaddr *)sa, (int)sizeof(*sa));
}

void
dht_wrap_status(int *good, int *dubious)
{
    int g = 0, d = 0, c = 0, in = 0;
    if (s_initialised) dht_nodes(AF_INET, &g, &d, &c, &in);
    if (good)    *good    = g;
    if (dubious) *dubious = d;
}

void
dht_wrap_status6(int *good, int *dubious)
{
    int g = 0, d = 0, c = 0, in = 0;
    if (s_initialised && s_sock6 >= 0) dht_nodes(AF_INET6, &g, &d, &c, &in);
    if (good)    *good    = g;
    if (dubious) *dubious = d;
}

int
dht_wrap_get_nodes(struct sockaddr_in *out, int max)
{
    if (!s_initialised || max <= 0) return 0;
    int n = max;
    int n6 = 0;     /* jech writes *num6 unconditionally; pass dummy. */
    if (dht_get_nodes(out, &n, NULL, &n6) < 0) return 0;
    return n;
}

int
dht_wrap_get_nodes6(struct sockaddr_in6 *out, int max)
{
    if (!s_initialised || s_sock6 < 0 || max <= 0) return 0;
    int n4 = 0;
    int n6 = max;
    if (dht_get_nodes(NULL, &n4, out, &n6) < 0) return 0;
    return n6;
}

int
dht_wrap_closest_to(const uint8_t target[20],
                    struct sockaddr_in *out,
                    uint8_t (*out_ids)[20],
                    int max)
{
    if (!s_initialised || max <= 0) return 0;
    return dht_closest_nodes(target, AF_INET, out, NULL, out_ids, max);
}

int
dht_wrap_closest6_to(const uint8_t target[20],
                     struct sockaddr_in6 *out,
                     uint8_t (*out_ids)[20],
                     int max)
{
    if (!s_initialised || s_sock6 < 0 || max <= 0) return 0;
    return dht_closest_nodes(target, AF_INET6, NULL, out, out_ids, max);
}

int
dht_wrap_kick_search(const uint8_t target[20])
{
    if (!s_initialised) return -1;
    /* port=0 means don't announce_peer on completion; we just want the
     * find_node / get_peers iterations to populate our routing table. */
    return dht_search(target, 0, AF_INET, NULL, NULL);
}

/* ============================================================
 * BEP 44 dispatch (inbound)
 * ============================================================ */

static void
dispatch_query(const struct sockaddr *peer, int peerlen,
               const dht_wrap_peek *p,
               const uint8_t *buf, size_t len)
{
    int qkind;
    if      (p->q_len == 3  && memcmp(p->q, "get", 3) == 0)               qkind = 0; /* BEP 44 get */
    else if (p->q_len == 3  && memcmp(p->q, "put", 3) == 0)               qkind = 1; /* BEP 44 put */
    else if (p->q_len == 17 && memcmp(p->q, "sample_infohashes", 17) == 0)
                                                                          qkind = 2; /* BEP 51 */
    else                                                                  return;

    if (!s_query_cb) return;

    bencode_arena *a;
    bencode_value *root = bencode_parse(buf, len, &a);
    if (!root) return;
    const bencode_value *aa = bencode_dict_get(root, "a");
    if (aa && aa->type == BENCODE_DICT) {
        s_query_cb(peer, peerlen, p->t, p->t_len, qkind, aa, s_query_cb_closure);
    }
    bencode_free(a);
}

static void
dispatch_response(const struct sockaddr *peer, int peerlen,
                  const dht_wrap_peek *p,
                  const uint8_t *buf, size_t len,
                  int is_error)
{
    (void)peerlen;
    struct pending_tx *t = pending_find_match(p->t, p->t_len, peer);
    if (!t) return;     /* not ours, or already fired */

    bep44_tx_cb cb = t->cb;
    void *closure = t->closure;
    struct sockaddr_storage saved = t->peer;
    socklen_t savedlen = t->peerlen;
    pending_release(t);

    bencode_arena *a;
    bencode_value *root = bencode_parse(buf, len, &a);
    if (!root) {
        if (cb) cb(is_error ? BEP44_TX_ERROR : BEP44_TX_RESPONSE,
                   (const struct sockaddr *)&saved, (int)savedlen,
                   NULL, NULL, closure);
        return;
    }
    const bencode_value *r = bencode_dict_get(root, "r");
    const bencode_value *e = bencode_dict_get(root, "e");
    if (cb) cb(is_error ? BEP44_TX_ERROR : BEP44_TX_RESPONSE,
               (const struct sockaddr *)&saved, (int)savedlen,
               r, e, closure);
    bencode_free(a);
}

/* ============================================================
 * Event pump
 * ============================================================ */

/*
 * Returns 1 if we handled the packet, 0 if it should be forwarded to
 * dht_periodic.
 */
static int
maybe_handle_bep44(const uint8_t *buf, size_t len,
                   const struct sockaddr *from, int fromlen)
{
    if (fromlen != (int)sizeof(struct sockaddr_in)
        && fromlen != (int)sizeof(struct sockaddr_in6)) return 0;
    dht_wrap_peek p;
    if (dht_wrap_peek_top(buf, len, &p) < 0) return 0;

    /* Outbound y must be 1-byte: "q", "r", or "e" */
    if (p.y_len != 1) return 0;
    if (p.y[0] == 'q' && p.q_len > 0) {
        if ((p.q_len == 3 && memcmp(p.q, "get", 3) == 0)
            || (p.q_len == 3 && memcmp(p.q, "put", 3) == 0)
            || (p.q_len == 17 && memcmp(p.q, "sample_infohashes", 17) == 0)) {
            dispatch_query(from, fromlen, &p, buf, len);
            return 1;
        }
        return 0;
    }
    if (p.y[0] == 'r' || p.y[0] == 'e') {
        if (pending_find_match(p.t, p.t_len, from)) {
            dispatch_response(from, fromlen, &p, buf, len, p.y[0] == 'e');
            return 1;
        }
    }
    return 0;
}

static void
periodic_cb(void *closure, int event,
            const unsigned char *info_hash,
            const void *data, size_t data_len)
{
    /* jech notifies on DHT_EVENT_VALUES{,6} and DHT_EVENT_SEARCH_DONE{,6}.
     * BEP 44 doesn't use these; the callback exists to satisfy dht_periodic. */
    (void)closure; (void)event; (void)info_hash; (void)data; (void)data_len;
}

/* ============================================================
 * Per-IP packet rate limiter (inline, fixed-size table).
 *
 * Sustained-rate detector. Each slot tracks the previous + current
 * 1-second bucket counts; if the trailing 2-second sum exceeds
 * RATE_THRESHOLD the peer is added to the deny set with a 10-minute
 * TTL.
 *
 * Bounded memory; evicts via direct overwrite when the hash slot is
 * occupied by a different (ip, port) — slightly racy but safe (worst
 * case: one extra slot scan to re-deny on next flood).
 * ============================================================ */
#define RATE_SLOTS         1024
#define RATE_THRESHOLD     20      /* >10 pkt/s sustained over 2s */

struct rate_slot {
    char     ip[INET6_ADDRSTRLEN];
    uint16_t port;
    uint16_t bucket_now_ct;
    uint16_t bucket_prev_ct;
    int64_t  bucket_now_sec;       /* unix second of the current bucket */
};

static struct rate_slot g_rate[RATE_SLOTS];

/* Drop counters for /api/stats. Indices: 0=reputation, 1=rate, 2=classifier. */
static uint64_t g_denied_pkts[3] = {0, 0, 0};

/* Returns 1 if the rate-limiter just decided to deny this peer (and
 * registered it with the deny set), 0 otherwise. */
static int
rate_check_and_maybe_deny(const struct sockaddr *from, int fromlen)
{
    if (!from) return 0;
    char ip[INET6_ADDRSTRLEN]; uint16_t port = 0;
    if (from->sa_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)from;
        if (!inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip))) return 0;
        port = ntohs(sa->sin_port);
    } else if (from->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)from;
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip))) return 0;
        port = ntohs(sa->sin6_port);
    } else return 0;

    /* Slot index from FNV-1a-ish hash of ip + port. */
    uint32_t h = 2166136261u;
    for (const char *p = ip; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    h ^= (uint32_t)port * 16777619u;
    struct rate_slot *r = &g_rate[h & (RATE_SLOTS - 1)];

    int64_t now = (int64_t)time(NULL);
    /* Re-key the slot if it's empty or holds a different peer. */
    if (r->ip[0] == 0 || r->port != port || strcmp(r->ip, ip) != 0) {
        snprintf(r->ip, sizeof(r->ip), "%s", ip);
        r->port            = port;
        r->bucket_now_sec  = now;
        r->bucket_now_ct   = 1;
        r->bucket_prev_ct  = 0;
        return 0;
    }
    /* Same peer — advance the bucket if a second rolled over. */
    if (now != r->bucket_now_sec) {
        if (now == r->bucket_now_sec + 1) {
            r->bucket_prev_ct = r->bucket_now_ct;
        } else {
            r->bucket_prev_ct = 0;
        }
        r->bucket_now_sec  = now;
        r->bucket_now_ct   = 0;
    }
    if (r->bucket_now_ct < UINT16_MAX) r->bucket_now_ct++;

    int total = r->bucket_now_ct + r->bucket_prev_ct;
    if (total > RATE_THRESHOLD) {
        deny_add(from, (socklen_t)fromlen, DENY_REASON_RATE_LIMIT, 600);
        return 1;
    }
    return 0;
}

/* Bogon detector — endpoints that violate the public-DHT spec
 * outright. We filter these in three places: the inbound packet
 * receive path (drop without dispatch), find_node/get_peers reply
 * parsing in crawl.c (don't insert into shortlist or emit edge), and
 * by extension anywhere outbound that would try to send to one. */
int
dht_wrap_is_bogon(const struct sockaddr *peer)
{
    if (!peer) return 1;
    if (peer->sa_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)peer;
        if (s4->sin_port == 0) return 1;
        uint32_t a  = ntohl(s4->sin_addr.s_addr);
        uint8_t  b1 = (a >> 24) & 0xff;
        uint8_t  b2 = (a >> 16) & 0xff;
        if (b1 == 0)         return 1;       /* 0.0.0.0/8 */
        if (b1 == 10)        return 1;       /* 10.0.0.0/8 */
        if (b1 == 127)       return 1;       /* 127.0.0.0/8 loopback */
        if (b1 == 169 && b2 == 254) return 1;/* 169.254/16 link-local */
        if (b1 == 172 && b2 >= 16 && b2 <= 31) return 1; /* 172.16/12 */
        if (b1 == 192 && b2 == 168) return 1;/* 192.168/16 */
        if (b1 >= 224)       return 1;       /* multicast + reserved */
        return 0;
    }
    if (peer->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)peer;
        if (s6->sin6_port == 0) return 1;
        const uint8_t *p = s6->sin6_addr.s6_addr;
        /* ::/128 unspecified */
        int all_zero = 1;
        for (int i = 0; i < 15; i++) if (p[i]) { all_zero = 0; break; }
        if (all_zero && (p[15] == 0 || p[15] == 1)) return 1;
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80) return 1; /* fe80::/10 */
        if (p[0] == 0xff) return 1;                          /* ff00::/8 */
        return 0;
    }
    return 1;
}

void
dht_wrap_get_deny_stats(uint64_t out_by_reason[3])
{
    if (!out_by_reason) return;
    out_by_reason[0] = g_denied_pkts[0];
    out_by_reason[1] = g_denied_pkts[1];
    out_by_reason[2] = g_denied_pkts[2];
}

/* Read previously-saved cumulative drop counts out of the kv store.
 * Called once after db_open at boot — turns the in-memory counter
 * into a true running total across restarts, matching how queries /
 * peers / infohashes naturally persist via the underlying tables. */
void
dht_wrap_load_deny_stats(void)
{
    g_denied_pkts[0] = (uint64_t)db_kv_get_i64("denied_pkts.reputation", 0);
    g_denied_pkts[1] = (uint64_t)db_kv_get_i64("denied_pkts.rate_limit", 0);
    g_denied_pkts[2] = (uint64_t)db_kv_get_i64("denied_pkts.classifier", 0);
}

/* Push current cumulative counts back to the kv store. Called from
 * the daemon's 1 Hz tick alongside db_flush. The values are
 * monotonically non-decreasing, so an UPSERT-overwrite is safe. */
void
dht_wrap_save_deny_stats(void)
{
    db_kv_set_i64("denied_pkts.reputation", (int64_t)g_denied_pkts[0]);
    db_kv_set_i64("denied_pkts.rate_limit", (int64_t)g_denied_pkts[1]);
    db_kv_set_i64("denied_pkts.classifier", (int64_t)g_denied_pkts[2]);
}

int
dht_wrap_step(const void *buf, size_t buflen,
              const struct sockaddr *from, int fromlen,
              int *next_wake_ms)
{
    if (!s_initialised) return -1;

    int forward = 1;
    if (buf && buflen > 0) {
        /* Bogon source: a packet from 0.0.0.0:0 or a similar
         * protocol-violating endpoint can't have a real client behind
         * it. Drop BEFORE observe so we don't pollute peers/queries
         * with junk; tick jech with NULL so its timers still advance. */
        if (from && dht_wrap_is_bogon(from)) {
            time_t tosleep_b = 1;
            dht_periodic(NULL, 0, NULL, 0, &tosleep_b, periodic_cb, NULL);
            pending_sweep();
            long jech_ms_b  = (long)tosleep_b * 1000;
            int  pend_ms_b  = pending_next_deadline_ms();
            long combined_b = jech_ms_b < pend_ms_b ? jech_ms_b : pend_ms_b;
            if (combined_b < 0) combined_b = 0;
            if (combined_b > INT32_MAX) combined_b = INT32_MAX;
            *next_wake_ms = (int)combined_b;
            return 0;
        }

        /* Observe every inbound packet before dispatch — the deny path
         * below skips dispatch but observe always records, so the
         * dashboard still shows what bad actors are doing. */
        if (observe_enabled()
            && (fromlen == (int)sizeof(struct sockaddr_in)
                || fromlen == (int)sizeof(struct sockaddr_in6))) {
            dht_wrap_peek op;
            if (dht_wrap_peek_top(buf, buflen, &op) == 0) {
                observe_packet(OBSERVE_IN, from, (socklen_t)fromlen,
                               buf, buflen, &op);
            }
        }

        /* Deny check: log + drop without dispatching to BEP 44 or jech.
         * Three populating sources, all consulted here:
         *   1. existing entry in the deny set (classifier or earlier
         *      reputation/rate-limit add still within TTL)
         *   2. iBlockList strong-match seen for the first time —
         *      lazy-add into deny set so subsequent packets are O(1)
         *   3. per-IP packet rate exceeded — adds to deny set with
         *      10-min TTL, deny_check picks it up next packet
         * Returning early here means: no maybe_handle_bep44 (no BEP 44
         * response), no dht_periodic forwarding (no jech routing-table
         * insertion). The peer effectively stops existing for us. */
        const char *deny_reason = deny_check(from, (socklen_t)fromlen);
        if (!deny_reason) {
            const char *rs = NULL, *rl = NULL;
            if (reputation_lookup(from, &rs, &rl)
                && rs && rl
                && reputation_label_is_strong(rs, rl)) {
                deny_add(from, (socklen_t)fromlen,
                         DENY_REASON_REPUTATION, 3600);
                deny_reason = DENY_REASON_REPUTATION;
            }
        }
        if (!deny_reason && rate_check_and_maybe_deny(from, fromlen)) {
            deny_reason = DENY_REASON_RATE_LIMIT;
        }
        if (deny_reason) {
            int idx = (deny_reason == DENY_REASON_REPUTATION) ? 0
                    : (deny_reason == DENY_REASON_RATE_LIMIT) ? 1 : 2;
            g_denied_pkts[idx]++;
            /* Tick jech without forwarding so its internal timers
             * still advance. Same path as the BEP 44 intercept. */
            time_t tosleep_d = 1;
            dht_periodic(NULL, 0, NULL, 0, &tosleep_d, periodic_cb, NULL);
            pending_sweep();
            long jech_ms_d  = (long)tosleep_d * 1000;
            int  pend_ms_d  = pending_next_deadline_ms();
            long combined_d = jech_ms_d < pend_ms_d ? jech_ms_d : pend_ms_d;
            if (combined_d < 0) combined_d = 0;
            if (combined_d > INT32_MAX) combined_d = INT32_MAX;
            *next_wake_ms = (int)combined_d;
            return 0;
        }

        forward = !maybe_handle_bep44(buf, buflen, from, fromlen);
    }

    time_t tosleep = 1;     /* seconds, jech writes back */
    if (forward) {
        dht_periodic(forward && buf ? buf : NULL,
                     forward && buf ? buflen : 0,
                     forward ? from : NULL,
                     forward ? fromlen : 0,
                     &tosleep, periodic_cb, NULL);
    } else {
        /* still tick */
        dht_periodic(NULL, 0, NULL, 0, &tosleep, periodic_cb, NULL);
    }

    pending_sweep();

    long jech_ms = (long)tosleep * 1000;
    int  pend_ms = pending_next_deadline_ms();
    long combined = jech_ms < pend_ms ? jech_ms : pend_ms;
    if (combined < 0) combined = 0;
    if (combined > INT32_MAX) combined = INT32_MAX;
    *next_wake_ms = (int)combined;
    return 0;
}

/* ============================================================
 * Outbound send
 * ============================================================ */

int
dht_wrap_sendto(const struct sockaddr *peer, int peerlen,
                const void *packet, size_t packet_len)
{
    /* Route to the socket that matches the destination family. */
    int fd = -1;
    if (peer->sa_family == AF_INET)  fd = s_sock;
    if (peer->sa_family == AF_INET6) fd = s_sock6;
    if (fd < 0) return -1;

    ssize_t w = sendto(fd, packet, packet_len, 0, peer, (socklen_t)peerlen);
    if (w < 0) {
        fprintf(stderr, "[dht44:dht_wrap] sendto: %s\n", strerror(errno));
        return -1;
    }
    if (observe_enabled()
        && (peerlen == (int)sizeof(struct sockaddr_in)
            || peerlen == (int)sizeof(struct sockaddr_in6))) {
        dht_wrap_peek op;
        if (dht_wrap_peek_top(packet, packet_len, &op) == 0) {
            observe_packet(OBSERVE_OUT, peer, (socklen_t)peerlen,
                           packet, packet_len, &op);
        }
    }
    return 0;
}

int
dht_wrap_send_query(const struct sockaddr *peer, int peerlen,
                    const void *packet, size_t packet_len,
                    const uint8_t *tid, size_t tid_len,
                    int timeout_ms,
                    bep44_tx_cb cb, void *closure)
{
    if (tid_len != 2) return -1;
    if (peerlen != (int)sizeof(struct sockaddr_in)
        && peerlen != (int)sizeof(struct sockaddr_in6)) return -1;
    if (pending_register(tid, peer, (socklen_t)peerlen,
                         timeout_ms, cb, closure) < 0) {
        return -1;
    }
    if (dht_wrap_sendto(peer, peerlen, packet, packet_len) < 0) {
        /* roll back the registration so the callback isn't fired on an
         * unrelated future packet that happens to match */
        struct pending_tx *t = pending_find_match(tid, tid_len, peer);
        if (t) pending_release(t);
        return -1;
    }
    return 0;
}
