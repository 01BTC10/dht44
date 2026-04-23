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

#include "bencode.h"
#include "dht.h"
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
    struct sockaddr_in peer;
    time_t         deadline;
    bep44_tx_cb    cb;
    void          *closure;
};

static int                s_sock = -1;
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
    out->y = out->q = out->t = NULL;
    out->y_len = out->q_len = out->t_len = 0;
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
        }
        pos = val_end;
    }
    if (out->y == NULL || out->t == NULL) return -1;
    return 0;
}

/* ============================================================
 * Pending-tx table
 * ============================================================ */

static int
sa_eq(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr
        && a->sin_port        == b->sin_port;
}

static struct pending_tx *
pending_find_match(const uint8_t *tid, size_t tid_len,
                   const struct sockaddr_in *peer)
{
    if (tid_len != 2) return NULL;
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (!s_pending[i].in_use) continue;
        if (s_pending[i].tid[0] != tid[0] || s_pending[i].tid[1] != tid[1]) continue;
        if (!sa_eq(&s_pending[i].peer, peer)) continue;
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
pending_register(const uint8_t tid[2], const struct sockaddr_in *peer,
                 int timeout_ms, bep44_tx_cb cb, void *closure)
{
    for (size_t i = 0; i < MAX_PENDING_TX; i++) {
        if (s_pending[i].in_use) continue;
        s_pending[i].in_use = 1;
        s_pending[i].tid[0] = tid[0];
        s_pending[i].tid[1] = tid[1];
        s_pending[i].peer = *peer;
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
        struct sockaddr_in peer = s_pending[i].peer;
        pending_release(&s_pending[i]);
        if (cb) cb(BEP44_TX_TIMEOUT,
                   (const struct sockaddr *)&peer, (int)sizeof(peer),
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

int
dht_wrap_init(uint16_t port)
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

    s_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_sock < 0) {
        fprintf(stderr, "[dht44:dht_wrap] socket: %s\n", strerror(errno));
        return -1;
    }
    int flags = fcntl(s_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(s_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "[dht44:dht_wrap] non-blocking: %s\n", strerror(errno));
        close(s_sock);
        s_sock = -1;
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[dht44:dht_wrap] bind :%u: %s\n",
                (unsigned)port, strerror(errno));
        close(s_sock);
        s_sock = -1;
        return -1;
    }

    if (state_get_node_id(s_node_id) < 0) {
        close(s_sock);
        s_sock = -1;
        return -1;
    }

    /* Version: "DH44" — 4 bytes */
    if (dht_init(s_sock, -1, s_node_id, (const unsigned char *)"DH44") < 0) {
        fprintf(stderr, "[dht44:dht_wrap] dht_init failed\n");
        close(s_sock);
        s_sock = -1;
        return -1;
    }
    s_initialised = 1;
    return 0;
}

void
dht_wrap_uninit(void)
{
    if (s_initialised) {
        dht_uninit();
        s_initialised = 0;
    }
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    memset(s_pending, 0, sizeof(s_pending));
    s_query_cb = NULL;
    s_query_cb_closure = NULL;
}

int dht_wrap_socket(void) { return s_sock; }
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
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
        struct addrinfo *res = NULL;
        int rc = getaddrinfo(ROUTERS[i].host, ROUTERS[i].port, &hints, &res);
        if (rc != 0) {
            fprintf(stderr, "[dht44:dht_wrap] resolve %s: %s\n",
                    ROUTERS[i].host, gai_strerror(rc));
            continue;
        }
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            if (dht_ping_node(ai->ai_addr, (int)ai->ai_addrlen) >= 0) {
                pinged++;
                break;     /* one address per host is enough */
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

void
dht_wrap_status(int *good, int *dubious)
{
    int g = 0, d = 0, c = 0, in = 0;
    if (s_initialised) dht_nodes(AF_INET, &g, &d, &c, &in);
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

/* ============================================================
 * BEP 44 dispatch (inbound)
 * ============================================================ */

static void
dispatch_query(const struct sockaddr *peer, int peerlen,
               const dht_wrap_peek *p,
               const uint8_t *buf, size_t len)
{
    int is_put;
    if (p->q_len == 3 && memcmp(p->q, "get", 3) == 0)        is_put = 0;
    else if (p->q_len == 3 && memcmp(p->q, "put", 3) == 0)   is_put = 1;
    else                                                     return;

    if (!s_query_cb) return;

    bencode_arena *a;
    bencode_value *root = bencode_parse(buf, len, &a);
    if (!root) return;
    const bencode_value *aa = bencode_dict_get(root, "a");
    if (aa && aa->type == BENCODE_DICT) {
        s_query_cb(peer, peerlen, p->t, p->t_len, is_put, aa, s_query_cb_closure);
    }
    bencode_free(a);
}

static void
dispatch_response(const struct sockaddr_in *peer,
                  const dht_wrap_peek *p,
                  const uint8_t *buf, size_t len,
                  int is_error)
{
    struct pending_tx *t = pending_find_match(p->t, p->t_len, peer);
    if (!t) return;     /* not ours, or already fired */

    bep44_tx_cb cb = t->cb;
    void *closure = t->closure;
    struct sockaddr_in saved = t->peer;
    pending_release(t);

    bencode_arena *a;
    bencode_value *root = bencode_parse(buf, len, &a);
    if (!root) {
        if (cb) cb(is_error ? BEP44_TX_ERROR : BEP44_TX_RESPONSE,
                   (const struct sockaddr *)&saved, (int)sizeof(saved),
                   NULL, NULL, closure);
        return;
    }
    const bencode_value *r = bencode_dict_get(root, "r");
    const bencode_value *e = bencode_dict_get(root, "e");
    if (cb) cb(is_error ? BEP44_TX_ERROR : BEP44_TX_RESPONSE,
               (const struct sockaddr *)&saved, (int)sizeof(saved),
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
    if (fromlen != (int)sizeof(struct sockaddr_in)) return 0;   /* IPv4 only */
    dht_wrap_peek p;
    if (dht_wrap_peek_top(buf, len, &p) < 0) return 0;

    /* Outbound y must be 1-byte: "q", "r", or "e" */
    if (p.y_len != 1) return 0;
    if (p.y[0] == 'q' && p.q_len > 0) {
        if ((p.q_len == 3 && memcmp(p.q, "get", 3) == 0)
            || (p.q_len == 3 && memcmp(p.q, "put", 3) == 0)) {
            dispatch_query(from, fromlen, &p, buf, len);
            return 1;
        }
        return 0;
    }
    if (p.y[0] == 'r' || p.y[0] == 'e') {
        const struct sockaddr_in *peer = (const struct sockaddr_in *)from;
        if (pending_find_match(p.t, p.t_len, peer)) {
            dispatch_response(peer, &p, buf, len, p.y[0] == 'e');
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

int
dht_wrap_step(const void *buf, size_t buflen,
              const struct sockaddr *from, int fromlen,
              int *next_wake_ms)
{
    if (!s_initialised) return -1;

    int forward = 1;
    if (buf && buflen > 0) {
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
    if (s_sock < 0) return -1;
    ssize_t w = sendto(s_sock, packet, packet_len, 0, peer, (socklen_t)peerlen);
    if (w < 0) {
        fprintf(stderr, "[dht44:dht_wrap] sendto: %s\n", strerror(errno));
        return -1;
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
    if (peerlen != (int)sizeof(struct sockaddr_in) || tid_len != 2) return -1;
    if (pending_register(tid, (const struct sockaddr_in *)peer,
                         timeout_ms, cb, closure) < 0) {
        return -1;
    }
    if (dht_wrap_sendto(peer, peerlen, packet, packet_len) < 0) {
        /* roll back the registration so the callback isn't fired on an
         * unrelated future packet that happens to match */
        struct pending_tx *t = pending_find_match(tid, tid_len,
                                                  (const struct sockaddr_in *)peer);
        if (t) pending_release(t);
        return -1;
    }
    return 0;
}
