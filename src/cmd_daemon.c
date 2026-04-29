/*
 * dht44 daemon — long-running event loop.
 *
 *   - owns UDP socket + jech routing table (via dht_wrap)
 *   - owns the iterative lookup engine (lookup)
 *   - listens on the local IPC socket and serves CLI requests
 *   - serves inbound BEP 44 get/put queries from peers
 *   - persists nodes.bin every 5 min and on SIGINT
 *   - republishes saved items on a configurable interval
 *   - manages a UPnP IGD UDP mapping (if --no-upnp not set)
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <sodium.h>

#include "bencode.h"
#include "bep44.h"
#include "commands.h"
#include "crawl.h"
#include "db.h"
#include "liveness.h"
#include "dht_wrap.h"
#include "http_ws.h"
#include "ipc.h"
#include "lookup.h"
#include "observe.h"
#include "classifier.h"
#include "deny.h"
#include "redact.h"
#include "reputation.h"
#include "state.h"
#include "upnp.h"

/* ============================================================
 * Args
 * ============================================================ */

#define MAX_BOOTSTRAP 8

typedef struct {
    uint16_t port;
    int      republish_min;
    int      no_upnp;
    int      upnp_lifetime;
    int      no_routers;            /* skip pinging public bootstrap routers */
    int      no_ipv6;               /* skip binding the v6 UDP socket */
    const char *bootstrap[MAX_BOOTSTRAP];
    int      bootstrap_count;

    /* crawler */
    int      crawl;                 /* 0 = passive, 1 = active crawl workers */
    int      crawl_workers;
    int      crawl_pps;             /* outbound pkts/sec cap */

    /* liveness sweeper */
    int      liveness;              /* 0 = off, 1 = on (defaults on with --crawl) */
    int      liveness_set;          /* user explicitly set --liveness/--no-liveness */
    int      liveness_window_h;     /* re-ping cadence per peer */
    int      liveness_pps;          /* upper bound on ping rate */
    int      prune_days;            /* delete peers with last_seen older than this */

    /* web + geoip */
    uint16_t web_port;              /* 0 = web disabled */
    const char *web_static;         /* NULL = built-in UI */
    const char *geoip_city;         /* NULL = none */
    const char *geoip_asn;          /* NULL = none */
    int      web_show_full_ips;     /* 0 = redact (default), 1 = show full */

    /* Reputation lists (loaded by reputation.c at boot). */
    const char *reputation_dir;     /* NULL = $DHT44_HOME/reputation/ */
} daemon_args;

static const char USAGE_DAEMON[] =
    "usage: dht44 daemon [--port N] [--republish MIN] [--no-upnp]\n"
    "                    [--upnp-lifetime SEC] [--bootstrap HOST:PORT]...\n"
    "                    [--no-routers] [--no-ipv6]\n"
    "                    [--crawl] [--crawl-workers N] [--crawl-pps N]\n"
    "                    [--liveness | --no-liveness]\n"
    "                    [--liveness-window-hours H] [--liveness-pps N]\n"
    "                    [--prune-days D]\n"
    "                    [--web PORT] [--web-static DIR]\n"
    "                    [--geoip-city PATH] [--geoip-asn PATH]\n"
    "                    [--web-show-full-ips]   (default: redact to /24, /48)\n"
    "                    [--reputation-dir PATH] (default: $DHT44_HOME/reputation)\n";

static int
parse_args(int argc, char **argv, daemon_args *a)
{
    memset(a, 0, sizeof(*a));
    a->port = 6881;
    a->republish_min = 60;
    a->upnp_lifetime = 3600;
    a->crawl_workers = 8;
    a->crawl_pps = 100;
    a->liveness_window_h = 6;
    a->liveness_pps = 50;
    a->prune_days = 7;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            a->port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--republish") == 0 && i + 1 < argc) {
            a->republish_min = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-upnp") == 0) {
            a->no_upnp = 1;
        } else if (strcmp(argv[i], "--no-routers") == 0) {
            a->no_routers = 1;
        } else if (strcmp(argv[i], "--no-ipv6") == 0) {
            a->no_ipv6 = 1;
        } else if (strcmp(argv[i], "--upnp-lifetime") == 0 && i + 1 < argc) {
            a->upnp_lifetime = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bootstrap") == 0 && i + 1 < argc) {
            if (a->bootstrap_count >= MAX_BOOTSTRAP) {
                fprintf(stderr, "[dht44:daemon] too many --bootstrap entries\n");
                return -1;
            }
            a->bootstrap[a->bootstrap_count++] = argv[++i];
        } else if (strcmp(argv[i], "--crawl") == 0) {
            a->crawl = 1;
        } else if (strcmp(argv[i], "--crawl-workers") == 0 && i + 1 < argc) {
            a->crawl_workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--crawl-pps") == 0 && i + 1 < argc) {
            a->crawl_pps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--liveness") == 0) {
            a->liveness = 1; a->liveness_set = 1;
        } else if (strcmp(argv[i], "--no-liveness") == 0) {
            a->liveness = 0; a->liveness_set = 1;
        } else if (strcmp(argv[i], "--liveness-window-hours") == 0 && i + 1 < argc) {
            a->liveness_window_h = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--liveness-pps") == 0 && i + 1 < argc) {
            a->liveness_pps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--prune-days") == 0 && i + 1 < argc) {
            a->prune_days = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--web") == 0 && i + 1 < argc) {
            a->web_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--web-static") == 0 && i + 1 < argc) {
            a->web_static = argv[++i];
        } else if (strcmp(argv[i], "--geoip-city") == 0 && i + 1 < argc) {
            a->geoip_city = argv[++i];
        } else if (strcmp(argv[i], "--geoip-asn") == 0 && i + 1 < argc) {
            a->geoip_asn = argv[++i];
        } else if (strcmp(argv[i], "--web-show-full-ips") == 0) {
            a->web_show_full_ips = 1;
        } else if (strcmp(argv[i], "--reputation-dir") == 0 && i + 1 < argc) {
            a->reputation_dir = argv[++i];
        } else {
            fputs(USAGE_DAEMON, stderr);
            return -1;
        }
    }
    return 0;
}

/* "host:port" → ping. Used by --bootstrap. Accepts both v4 and v6 resolutions;
 * dht_ping_node uses the matching socket jech was initialised with. For v6
 * addresses with IP literals like "[::1]:6881", the caller passes the host
 * without brackets (strrchr picks the last ':', but for IPv6 literals that
 * splits wrong — so we handle bracketed form here). */
static int
ping_host_port(const char *hp)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", hp);

    const char *host;
    const char *port;
    if (buf[0] == '[') {
        /* "[ipv6]:port" */
        char *close = strchr(buf, ']');
        if (!close || close[1] != ':') return -1;
        *close = 0;
        host = buf + 1;
        port = close + 2;
    } else {
        char *colon = strrchr(buf, ':');
        if (!colon) return -1;
        *colon = 0;
        host = buf;
        port = colon + 1;
    }

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int rc = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        extern int dht_ping_node(const struct sockaddr *sa, int salen);
        if (dht_ping_node(ai->ai_addr, (int)ai->ai_addrlen) >= 0) { rc = 0; break; }
    }
    freeaddrinfo(res);
    return rc;
}

/* ============================================================
 * Globals + signal handling
 * ============================================================ */

#define MAX_IPC_CLIENTS 8

static volatile sig_atomic_t g_exit = 0;

static void
on_sigint(int sig)
{
    (void)sig;
    g_exit = 1;
}

static int       g_lock_fd = -1;
static int       g_listen_fd = -1;
static ipc_conn *g_clients[MAX_IPC_CLIENTS] = {0};
static daemon_args g_args;

/* Counters (log every 30s) */
static unsigned long g_pkts_in   = 0;
static unsigned long g_pkts_out  = 0;
static unsigned long g_q_in_get  = 0;
static unsigned long g_q_in_put  = 0;
static unsigned long g_q_out     = 0;
static unsigned long g_ipc_reqs  = 0;
static unsigned long g_items_stored_peer = 0;   /* successful peer-origin puts */

static const char *
sa_str(const struct sockaddr *peer, char buf[24])
{
    const struct sockaddr_in *p = (const struct sockaddr_in *)peer;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
    snprintf(buf, 24, "%s:%u", ip, ntohs(p->sin_port));
    return buf;
}

/* Bridge observe events to the WebSocket broadcaster. */
static void
ws_bridge(const char *topic, const char *json, void *closure)
{
    (void)closure;
    http_ws_publish(topic, json);
}

static void
hex8(char out[17], const uint8_t *bytes)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < 8; i++) {
        out[i * 2]     = d[bytes[i] >> 4];
        out[i * 2 + 1] = d[bytes[i] & 0xf];
    }
    out[16] = '\0';
}

/* ============================================================
 * Token issuance (HMAC-SHA1, fixed daemon-lifetime secret)
 * ============================================================ */

#define TOKEN_LEN 8
static uint8_t g_token_secret[32];

static void
issue_token(uint8_t out[TOKEN_LEN], const struct sockaddr_in *peer,
            const uint8_t target[BEP44_TARGET_LEN])
{
    uint8_t buf[4 + 2 + BEP44_TARGET_LEN];
    memcpy(buf, &peer->sin_addr, 4);
    memcpy(buf + 4, &peer->sin_port, 2);
    memcpy(buf + 6, target, BEP44_TARGET_LEN);

    unsigned char digest[20];
    unsigned int  dlen = sizeof(digest);
    HMAC(EVP_sha1(), g_token_secret, sizeof(g_token_secret),
         buf, sizeof(buf), digest, &dlen);
    memcpy(out, digest, TOKEN_LEN);
}

static int
token_matches(const uint8_t *got, size_t got_len,
              const struct sockaddr_in *peer,
              const uint8_t target[BEP44_TARGET_LEN])
{
    if (got_len != TOKEN_LEN) return 0;
    uint8_t want[TOKEN_LEN];
    issue_token(want, peer, target);
    return sodium_memcmp(got, want, TOKEN_LEN) == 0;
}

/* Items are persisted via state_save_item / state_load_item using the
 * stored_item struct. Format on disk is JSON (see state.h). */

/* ============================================================
 * IPC plumbing
 * ============================================================ */

static int
client_slot_alloc(ipc_conn *c)
{
    for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
        if (g_clients[i] == NULL) {
            g_clients[i] = c;
            return i;
        }
    }
    return -1;
}

static void
client_close(int idx)
{
    if (idx < 0 || idx >= MAX_IPC_CLIENTS) return;
    if (!g_clients[idx]) return;
    ipc_conn_free(g_clients[idx]);
    g_clients[idx] = NULL;
}

static int
send_ipc_dict(ipc_conn *c, const uint8_t *buf, size_t len)
{
    if (!c) return -1;
    return ipc_conn_send(c, buf, len);
}

static void
send_ipc_error(ipc_conn *c, const char *msg)
{
    if (!c) return;     /* client may already have been closed by a sync cb */
    uint8_t buf[256];
    bencode_writer w;
    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_dict_open(&w);
        bencode_cstr(&w, "err"); bencode_cstr(&w, msg);
        bencode_cstr(&w, "ok");  bencode_int(&w, 0);
    bencode_dict_close(&w);
    ssize_t n = bencode_writer_finish(&w);
    if (n > 0) send_ipc_dict(c, buf, (size_t)n);
}

/* ============================================================
 * Per-request "put" context — survives until acks arrive (or time out)
 * ============================================================ */

#define MAX_INFLIGHT_PUTS 64

typedef struct {
    int          in_use;
    int          client_idx;        /* may go to -1 if client disconnects */

    uint8_t      target[BEP44_TARGET_LEN];
    int          mutable_;

    /* mutable item fields (kept by value so we can re-emit) */
    uint8_t      pk[BEP44_PK_LEN];
    uint8_t      sig[BEP44_SIG_LEN];
    int64_t      seq;
    int          has_cas;
    int64_t      cas;
    uint8_t      salt[BEP44_MAX_SALT];
    size_t       salt_len;

    uint8_t      v_bencoded[BEP44_MAX_V];
    size_t       v_len;

    int          pending;
    int          acks;
    int          last_err;
} put_ctx;

static put_ctx g_puts[MAX_INFLIGHT_PUTS];

static put_ctx *
put_ctx_alloc(void)
{
    for (int i = 0; i < MAX_INFLIGHT_PUTS; i++) {
        if (!g_puts[i].in_use) {
            memset(&g_puts[i], 0, sizeof(g_puts[i]));
            g_puts[i].in_use = 1;
            g_puts[i].client_idx = -1;
            return &g_puts[i];
        }
    }
    return NULL;
}

static void
put_ctx_release(put_ctx *p)
{
    p->in_use = 0;
}

static void
put_ctx_complete(put_ctx *p)
{
    if (p->client_idx >= 0 && g_clients[p->client_idx]) {
        char hex[BEP44_TARGET_LEN * 2 + 1] = {0};
        static const char *d = "0123456789abcdef";
        for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
            hex[i * 2]     = d[p->target[i] >> 4];
            hex[i * 2 + 1] = d[p->target[i] & 0xf];
        }
        uint8_t buf[256];
        bencode_writer w;
        bencode_writer_init(&w, buf, sizeof(buf));
        bencode_dict_open(&w);
            bencode_cstr(&w, "acks");   bencode_int(&w, p->acks);
            if (p->last_err) {
                bencode_cstr(&w, "err");
                char emsg[64];
                snprintf(emsg, sizeof(emsg), "DHT err %d", p->last_err);
                bencode_cstr(&w, emsg);
            }
            bencode_cstr(&w, "ok");     bencode_int(&w, p->acks > 0 ? 1 : 0);
            bencode_cstr(&w, "target"); bencode_cstr(&w, hex);
        bencode_dict_close(&w);
        ssize_t n = bencode_writer_finish(&w);
        if (n > 0) send_ipc_dict(g_clients[p->client_idx], buf, (size_t)n);
        client_close(p->client_idx);
    }
    put_ctx_release(p);
}

/* tx callback for one of the per-token KRPC puts */
static void
on_put_response(bep44_tx_event ev,
                const struct sockaddr *peer, int peerlen,
                const bencode_value *r, const bencode_value *e,
                void *closure)
{
    (void)peer; (void)peerlen;
    put_ctx *p = closure;
    if (!p->in_use) return;
    if (ev == BEP44_TX_RESPONSE && r) {
        p->acks++;
    } else if (ev == BEP44_TX_ERROR && e
               && e->type == BENCODE_LIST && e->list.len >= 1
               && e->list.items[0]->type == BENCODE_INT) {
        p->last_err = (int)e->list.items[0]->i;
    }
    if (--p->pending <= 0) {
        put_ctx_complete(p);
    }
}

/* lookup callback — fires once tokens are gathered (or lookup timed out) */
static void
on_put_lookup_done(int rc,
                   const lookup_value *values, size_t value_count,
                   const lookup_token *tokens, size_t token_count,
                   void *closure)
{
    (void)rc; (void)values; (void)value_count;
    put_ctx *p = closure;
    if (!p->in_use) return;

    if (token_count == 0) {
        char tgthex[17]; hex8(tgthex, p->target);
        fprintf(stderr,
                "[dht44:daemon] put target=%s.. → 0 tokens (no peers)\n", tgthex);
        put_ctx_complete(p);
        return;
    }

    p->pending = 0;
    for (size_t i = 0; i < token_count; i++) {
        const lookup_token *t = &tokens[i];
        uint8_t pkt[1500];
        ssize_t plen;
        uint8_t tid[2];
        dht_wrap_random_tid(tid);

        if (p->mutable_) {
            const int64_t *cas_ptr = p->has_cas ? &p->cas : NULL;
            plen = bep44_build_put_query_mutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(), p->pk,
                p->salt_len ? p->salt : NULL, p->salt_len,
                p->seq, cas_ptr, p->sig,
                t->token, t->token_len,
                p->v_bencoded, p->v_len);
        } else {
            plen = bep44_build_put_query_immutable(
                pkt, sizeof(pkt), tid, sizeof(tid),
                dht_wrap_node_id(),
                t->token, t->token_len,
                p->v_bencoded, p->v_len);
        }
        if (plen < 0) continue;

        if (dht_wrap_send_query((const struct sockaddr *)&t->peer,
                                (int)t->peerlen,
                                pkt, (size_t)plen,
                                tid, sizeof(tid),
                                5000, on_put_response, p) == 0) {
            p->pending++;
            g_q_out++;
            g_pkts_out++;
        }
    }
    char tgthex[17]; hex8(tgthex, p->target);
    fprintf(stderr, "[dht44:daemon] put target=%s.. → %d nodes\n",
            tgthex, p->pending);
    if (p->pending == 0) put_ctx_complete(p);
}

/* ============================================================
 * Per-request "get" context
 * ============================================================ */

typedef struct {
    int     in_use;
    int     client_idx;
    int     mutable_;
} get_ctx;

#define MAX_INFLIGHT_GETS 32

static get_ctx g_gets[MAX_INFLIGHT_GETS];

static get_ctx *
get_ctx_alloc(void)
{
    for (int i = 0; i < MAX_INFLIGHT_GETS; i++) {
        if (!g_gets[i].in_use) {
            memset(&g_gets[i], 0, sizeof(g_gets[i]));
            g_gets[i].in_use = 1;
            g_gets[i].client_idx = -1;
            return &g_gets[i];
        }
    }
    return NULL;
}

static void
get_ctx_release(get_ctx *g)
{
    g->in_use = 0;
}

static void
on_get_lookup_done(int rc,
                   const lookup_value *values, size_t value_count,
                   const lookup_token *tokens, size_t token_count,
                   void *closure)
{
    (void)rc; (void)tokens; (void)token_count;
    get_ctx *g = closure;
    if (!g->in_use) return;

    /* pick highest-seq value (mutable) or first one (immutable) */
    const lookup_value *best = NULL;
    for (size_t i = 0; i < value_count; i++) {
        const lookup_value *v = &values[i];
        if (g->mutable_ != v->mutable_) continue;
        if (!best) { best = v; continue; }
        if (g->mutable_ && v->seq > best->seq) best = v;
    }
    fprintf(stderr, "[dht44:daemon] get done: %zu values, %zu tokens, best=%s\n",
            value_count, token_count, best ? "yes" : "no");

    ipc_conn *c = g->client_idx >= 0 ? g_clients[g->client_idx] : NULL;
    if (c) {
        uint8_t buf[2048];
        bencode_writer w;
        bencode_writer_init(&w, buf, sizeof(buf));
        bencode_dict_open(&w);
            bencode_cstr(&w, "found"); bencode_int(&w, best ? 1 : 0);
            if (best && g->mutable_) {
                /* best->v already holds the bencoded form (e.g. "9:hello"); wrap
                 * with bencode_str so the IPC dict is valid bencode and the CLI
                 * can re-parse it to extract the inner value. */
                bencode_cstr(&w, "k");   bencode_str(&w, best->k, BEP44_PK_LEN);
                bencode_cstr(&w, "ok");  bencode_int(&w, 1);
                bencode_cstr(&w, "seq"); bencode_int(&w, best->seq);
                bencode_cstr(&w, "sig"); bencode_str(&w, best->sig, BEP44_SIG_LEN);
                bencode_cstr(&w, "v");   bencode_str(&w, best->v, best->v_len);
            } else if (best) {
                bencode_cstr(&w, "ok"); bencode_int(&w, 1);
                bencode_cstr(&w, "v");  bencode_str(&w, best->v, best->v_len);
            } else {
                bencode_cstr(&w, "ok"); bencode_int(&w, 0);
            }
        bencode_dict_close(&w);
        ssize_t n = bencode_writer_finish(&w);
        if (n > 0) send_ipc_dict(c, buf, (size_t)n);
        client_close(g->client_idx);
    }
    get_ctx_release(g);
}

/* ============================================================
 * IPC op handlers (called once a full request bencode is parsed)
 * ============================================================ */

static void
op_status(int client_idx)
{
    int good = 0, dub = 0;
    dht_wrap_status(&good, &dub);

    uint8_t buf[256];
    bencode_writer w;
    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_dict_open(&w);
        bencode_cstr(&w, "dubious_nodes"); bencode_int(&w, dub);
        bencode_cstr(&w, "good_nodes");    bencode_int(&w, good);
        bencode_cstr(&w, "ok");            bencode_int(&w, 1);
        bencode_cstr(&w, "port");          bencode_int(&w, g_args.port);
        bencode_cstr(&w, "upnp");          bencode_int(&w, g_args.no_upnp ? 0 : 1);
    bencode_dict_close(&w);
    ssize_t n = bencode_writer_finish(&w);
    if (n > 0 && g_clients[client_idx]) {
        send_ipc_dict(g_clients[client_idx], buf, (size_t)n);
    }
    client_close(client_idx);
}

static void
op_ping(int client_idx)
{
    uint8_t buf[16] = "d2:oki1ee";
    if (g_clients[client_idx]) send_ipc_dict(g_clients[client_idx], buf, 9);
    client_close(client_idx);
}

static void
op_put(int client_idx, const bencode_value *req)
{
    const bencode_value *target = bencode_dict_get(req, "target");
    const bencode_value *vbenc  = bencode_dict_get(req, "v");
    const bencode_value *mut    = bencode_dict_get(req, "mutable");
    const bencode_value *cas    = bencode_dict_get(req, "cas");
    const bencode_value *k      = bencode_dict_get(req, "k");
    const bencode_value *salt   = bencode_dict_get(req, "salt");
    const bencode_value *seq    = bencode_dict_get(req, "seq");
    const bencode_value *sig    = bencode_dict_get(req, "sig");

    int is_mutable = (mut && mut->type == BENCODE_INT && mut->i != 0);

    put_ctx *p = put_ctx_alloc();
    if (!p) {
        send_ipc_error(g_clients[client_idx], "too many in-flight puts");
        client_close(client_idx);
        return;
    }
    p->client_idx = client_idx;
    p->mutable_ = is_mutable;

    if (!vbenc || vbenc->type != BENCODE_STR
        || vbenc->str.len > sizeof(p->v_bencoded)) {
        send_ipc_error(g_clients[client_idx], "missing/oversize v");
        put_ctx_release(p); client_close(client_idx); return;
    }
    memcpy(p->v_bencoded, vbenc->str.bytes, vbenc->str.len);
    p->v_len = vbenc->str.len;

    if (is_mutable) {
        if (!target || target->type != BENCODE_STR
            || target->str.len != BEP44_TARGET_LEN
            || !k || k->type != BENCODE_STR || k->str.len != BEP44_PK_LEN
            || !seq || seq->type != BENCODE_INT
            || !sig || sig->type != BENCODE_STR || sig->str.len != BEP44_SIG_LEN) {
            send_ipc_error(g_clients[client_idx],
                           "put_mutable needs target,k,seq,sig,v");
            put_ctx_release(p); client_close(client_idx); return;
        }
        memcpy(p->target, target->str.bytes, BEP44_TARGET_LEN);
        memcpy(p->pk, k->str.bytes, BEP44_PK_LEN);
        memcpy(p->sig, sig->str.bytes, BEP44_SIG_LEN);
        p->seq = seq->i;
        if (salt && salt->type == BENCODE_STR && salt->str.len > 0) {
            if (salt->str.len > BEP44_MAX_SALT) {
                send_ipc_error(g_clients[client_idx], "salt too large");
                put_ctx_release(p); client_close(client_idx); return;
            }
            memcpy(p->salt, salt->str.bytes, salt->str.len);
            p->salt_len = salt->str.len;
        }
        if (cas && cas->type == BENCODE_INT) {
            p->has_cas = 1;
            p->cas = cas->i;
        }

        stored_item si = {0};
        si.mutable_ = 1;
        memcpy(si.pk, p->pk, BEP44_PK_LEN);
        si.seq = p->seq;
        if (p->salt_len) { memcpy(si.salt, p->salt, p->salt_len); si.salt_len = p->salt_len; }
        memcpy(si.sig, p->sig, BEP44_SIG_LEN);
        memcpy(si.v, p->v_bencoded, p->v_len);
        si.v_len = p->v_len;
        state_save_item(p->target, &si);
    } else {
        bep44_immutable_target(p->target, p->v_bencoded, p->v_len);
        stored_item si = {0};
        si.mutable_ = 0;
        memcpy(si.v, p->v_bencoded, p->v_len);
        si.v_len = p->v_len;
        state_save_item(p->target, &si);
    }

    if (lookup_start(p->target, 15000, on_put_lookup_done, p) == NULL) {
        send_ipc_error(g_clients[client_idx], "lookup_start failed");
        put_ctx_release(p);
        client_close(client_idx);
    }
}

static void
op_get(int client_idx, const bencode_value *req)
{
    const bencode_value *target = bencode_dict_get(req, "target");
    const bencode_value *mut    = bencode_dict_get(req, "mutable");
    if (!target || target->type != BENCODE_STR
        || target->str.len != BEP44_TARGET_LEN) {
        send_ipc_error(g_clients[client_idx], "missing/short target");
        client_close(client_idx);
        return;
    }
    int is_mutable = (mut && mut->type == BENCODE_INT && mut->i != 0);
    const bencode_value *nocache = bencode_dict_get(req, "no_cache");
    int skip_local = (nocache && nocache->type == BENCODE_INT && nocache->i != 0);

    uint8_t target_buf[BEP44_TARGET_LEN];
    memcpy(target_buf, target->str.bytes, BEP44_TARGET_LEN);

    /*
     * Short-circuit: if WE persisted this target via a prior put, return
     * the stored copy immediately. Avoids a full network lookup (which
     * may converge to a different set of peers than the put hit) and
     * makes "put then immediately get on the same daemon" reliable.
     * Skipped when the client passed --no-cache (forces a network test).
     */
    stored_item si = {0};
    if (!skip_local
        && state_load_item(target_buf, &si) == 0
        && si.mutable_ == is_mutable) {
        char tgthex[17]; hex8(tgthex, target_buf);
        fprintf(stderr,
                "[dht44:daemon] get target=%s.. served from local store\n",
                tgthex);
        uint8_t buf[2048];
        bencode_writer w;
        bencode_writer_init(&w, buf, sizeof(buf));
        bencode_dict_open(&w);
            bencode_cstr(&w, "found"); bencode_int(&w, 1);
            if (is_mutable) {
                bencode_cstr(&w, "k");   bencode_str(&w, si.pk, BEP44_PK_LEN);
                bencode_cstr(&w, "ok");  bencode_int(&w, 1);
                bencode_cstr(&w, "seq"); bencode_int(&w, si.seq);
                bencode_cstr(&w, "sig"); bencode_str(&w, si.sig, BEP44_SIG_LEN);
                bencode_cstr(&w, "v");   bencode_str(&w, si.v, si.v_len);
            } else {
                bencode_cstr(&w, "ok"); bencode_int(&w, 1);
                bencode_cstr(&w, "v");  bencode_str(&w, si.v, si.v_len);
            }
        bencode_dict_close(&w);
        ssize_t n = bencode_writer_finish(&w);
        if (n > 0 && g_clients[client_idx]) {
            send_ipc_dict(g_clients[client_idx], buf, (size_t)n);
        }
        client_close(client_idx);
        return;
    }

    get_ctx *g = get_ctx_alloc();
    if (!g) {
        send_ipc_error(g_clients[client_idx], "too many in-flight gets");
        client_close(client_idx);
        return;
    }
    g->client_idx = client_idx;
    g->mutable_ = is_mutable;

    if (lookup_start(target_buf, 15000, on_get_lookup_done, g) == NULL) {
        send_ipc_error(g_clients[client_idx], "lookup_start failed");
        get_ctx_release(g);
        client_close(client_idx);
    }
}

static void
dispatch_request(int client_idx, const uint8_t *buf, size_t len)
{
    bencode_arena *a;
    bencode_value *root = bencode_parse(buf, len, &a);
    if (!root || root->type != BENCODE_DICT) {
        send_ipc_error(g_clients[client_idx], "malformed request");
        client_close(client_idx);
        if (a) bencode_free(a);
        return;
    }
    const bencode_value *op = bencode_dict_get(root, "op");
    if (!op || op->type != BENCODE_STR) {
        send_ipc_error(g_clients[client_idx], "missing op");
        client_close(client_idx);
        bencode_free(a);
        return;
    }
    g_ipc_reqs++;
    char op_buf[32] = {0};
    size_t op_copy = op->str.len < sizeof(op_buf) - 1 ? op->str.len : sizeof(op_buf) - 1;
    memcpy(op_buf, op->str.bytes, op_copy);
    fprintf(stderr, "[dht44:daemon] IPC[%d] op=%s\n", client_idx, op_buf);

    if (op->str.len == 4 && memcmp(op->str.bytes, "ping", 4) == 0) {
        op_ping(client_idx);
    } else if (op->str.len == 6 && memcmp(op->str.bytes, "status", 6) == 0) {
        op_status(client_idx);
    } else if (op->str.len == 3 && memcmp(op->str.bytes, "put", 3) == 0) {
        op_put(client_idx, root);
    } else if (op->str.len == 3 && memcmp(op->str.bytes, "get", 3) == 0) {
        op_get(client_idx, root);
    } else {
        send_ipc_error(g_clients[client_idx], "unknown op");
        client_close(client_idx);
    }
    bencode_free(a);
}

/* ============================================================
 * Inbound BEP 44 query handler (peers asking us)
 * ============================================================ */

/* BEP 51 sample_infohashes reply (meta-indexer flavour). We return a random
 * sample of infohashes we've OBSERVED (peers asked us about them via
 * get_peers or other sample_infohashes queries) rather than the spec's
 * "infohashes we announce_peer for" — we're a crawler, not a seed host.
 * This helps other crawlers bootstrap, at the cost of a little more
 * visibility as a research node.
 *
 * Response fields per BEP 51:
 *   id, interval, num, samples, nodes [, nodes6]
 * We always include nodes/nodes6 (this doubles as a find_node reply).
 */
#define BEP51_INTERVAL_SEC 3600        /* peers may re-query after 1h */
#define BEP51_MAX_SAMPLES  50

static void
reply_sample_infohashes(const struct sockaddr *peer, int peerlen,
                        const uint8_t *tid, size_t tid_len,
                        const bencode_value *a)
{
    const bencode_value *t = bencode_dict_get(a, "target");
    if (!t || t->type != BENCODE_STR || t->str.len != BEP44_TARGET_LEN) return;
    uint8_t target[BEP44_TARGET_LEN];
    memcpy(target, t->str.bytes, BEP44_TARGET_LEN);

    /* Sample infohashes. If the infohashes table is empty we return an
     * empty samples blob + num=0 — still a valid reply. */
    uint8_t samples[BEP51_MAX_SAMPLES * BEP44_TARGET_LEN];
    int nsamples = observe_enabled()
                 ? db_sample_infohashes(samples, BEP51_MAX_SAMPLES) : 0;
    int64_t total = observe_enabled() ? db_count_infohashes() : 0;

    /* Closest nodes to the query's target — reuse our routing table. */
    struct sockaddr_in  n4[8];
    struct sockaddr_in6 n6[8];
    uint8_t n4_ids[8][BEP44_NODE_ID_LEN];
    uint8_t n6_ids[8][BEP44_NODE_ID_LEN];
    int nn4 = dht_wrap_closest_to(target, n4, n4_ids, 8);
    int nn6 = dht_wrap_closest6_to(target, n6, n6_ids, 8);

    uint8_t nodes_buf [8 * 26];
    uint8_t nodes6_buf[8 * 38];
    for (int i = 0; i < nn4; i++) {
        memcpy(nodes_buf + i*26,      n4_ids[i],       20);
        memcpy(nodes_buf + i*26 + 20, &n4[i].sin_addr,  4);
        memcpy(nodes_buf + i*26 + 24, &n4[i].sin_port,  2);
    }
    for (int i = 0; i < nn6; i++) {
        memcpy(nodes6_buf + i*38,      n6_ids[i],       20);
        memcpy(nodes6_buf + i*38 + 20, &n6[i].sin6_addr,16);
        memcpy(nodes6_buf + i*38 + 36, &n6[i].sin6_port, 2);
    }

    /* Build the KRPC reply. Outer keys: r, t, y. `r` sub-dict keys in
     * strict alphabetical order: id, interval, nodes, nodes6, num, samples. */
    uint8_t out[4096];
    bencode_writer w;
    bencode_writer_init(&w, out, sizeof(out));
    bencode_dict_open(&w);
      bencode_cstr(&w, "r");
      bencode_dict_open(&w);
        bencode_cstr(&w, "id");       bencode_str(&w, dht_wrap_node_id(), BEP44_NODE_ID_LEN);
        bencode_cstr(&w, "interval"); bencode_int(&w, BEP51_INTERVAL_SEC);
        if (nn4 > 0) {
            bencode_cstr(&w, "nodes");
            bencode_str(&w, nodes_buf, (size_t)(nn4 * 26));
        }
        if (nn6 > 0) {
            bencode_cstr(&w, "nodes6");
            bencode_str(&w, nodes6_buf, (size_t)(nn6 * 38));
        }
        bencode_cstr(&w, "num");      bencode_int(&w, total);
        bencode_cstr(&w, "samples");
        bencode_str(&w, samples, (size_t)(nsamples * 20));
      bencode_dict_close(&w);
      bencode_cstr(&w, "t");          bencode_str(&w, tid, tid_len);
      bencode_cstr(&w, "y");          bencode_cstr(&w, "r");
    bencode_dict_close(&w);
    ssize_t n = bencode_writer_finish(&w);
    if (n > 0) {
        dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        g_pkts_out++;
    }
}

static void
on_inbound_query(const struct sockaddr *peer, int peerlen,
                 const uint8_t *tid, size_t tid_len,
                 int qkind,
                 const bencode_value *a,
                 void *closure)
{
    (void)closure;
    const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;

    if (observe_enabled())
        observe_query_fields(peer, (socklen_t)peerlen, qkind == 1, a);

    if (qkind == 2) {                 /* BEP 51 sample_infohashes */
        reply_sample_infohashes(peer, peerlen, tid, tid_len, a);
        return;
    }
    int is_put = (qkind == 1);

    if (!is_put) {
        /* GET — look up target in our items dir */
        const bencode_value *t = bencode_dict_get(a, "target");
        if (!t || t->type != BENCODE_STR || t->str.len != BEP44_TARGET_LEN) return;
        uint8_t target[BEP44_TARGET_LEN];
        memcpy(target, t->str.bytes, BEP44_TARGET_LEN);
        char addr[24], hex[17];
        sa_str(peer, addr); hex8(hex, target);
        fprintf(stderr, "[dht44:daemon] <- get from %s target=%s..\n", addr, hex);
        g_q_in_get++;

        stored_item si = {0};
        int have = state_load_item(target, &si) == 0;

        uint8_t token[TOKEN_LEN];
        issue_token(token, p4, target);

        uint8_t out[2048];
        ssize_t n;
        if (have && si.mutable_) {
            n = bep44_build_get_response_mutable(
                out, sizeof(out), tid, tid_len,
                dht_wrap_node_id(), si.pk,
                NULL, 0,                          /* nodes (none for now) */
                si.seq, si.sig,
                token, sizeof(token),
                si.v, si.v_len);
        } else if (have) {
            n = bep44_build_get_response_immutable(
                out, sizeof(out), tid, tid_len,
                dht_wrap_node_id(), NULL, 0,
                token, sizeof(token),
                si.v, si.v_len);
        } else {
            /* no data — respond with id only, BEP 5 style */
            n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                         dht_wrap_node_id());
        }
        if (n > 0) {
            dht_wrap_sendto(peer, peerlen, out, (size_t)n);
            g_pkts_out++;
        }
        return;
    }

    /* PUT — full validation + persist for republish + serve */
    const bencode_value *target = bencode_dict_get(a, "target");
    const bencode_value *tok    = bencode_dict_get(a, "token");
    const bencode_value *v      = bencode_dict_get(a, "v");
    const bencode_value *k      = bencode_dict_get(a, "k");
    const bencode_value *salt   = bencode_dict_get(a, "salt");
    const bencode_value *seqv   = bencode_dict_get(a, "seq");
    const bencode_value *sig    = bencode_dict_get(a, "sig");
    const bencode_value *casv   = bencode_dict_get(a, "cas");

    if (!tok || tok->type != BENCODE_STR || !v || v->type != BENCODE_STR) return;

    char addr[24];
    sa_str(peer, addr);
    g_q_in_put++;

    int is_mutable = (k && k->type == BENCODE_STR && k->str.len == BEP44_PK_LEN
                      && sig && sig->type == BENCODE_STR && sig->str.len == BEP44_SIG_LEN
                      && seqv && seqv->type == BENCODE_INT);

    /* Re-encode v as the bencoded form ('hello' → '5:hello') for sig + target. */
    uint8_t vb[BEP44_MAX_V + 16];
    bencode_writer vw;
    bencode_writer_init(&vw, vb, sizeof(vb));
    bencode_str(&vw, v->str.bytes, v->str.len);
    ssize_t vb_len = bencode_writer_finish(&vw);

    /* Compute the canonical target ourselves: SHA1(k||salt) for mutable,
     * SHA1(v_bencoded) for immutable. We ignore any client-supplied target
     * field except as a sanity check below. */
    uint8_t target_buf[BEP44_TARGET_LEN];
    char    tgthex[17];
    size_t  salt_len = (salt && salt->type == BENCODE_STR) ? salt->str.len : 0;
    const uint8_t *salt_bytes = salt_len > 0 ? salt->str.bytes : NULL;

    if (is_mutable) {
        if (salt_len > BEP44_MAX_SALT) {
            fprintf(stderr,
                    "[dht44:daemon] <- put from %s REJECTED: salt too long (%zu)\n",
                    addr, salt_len);
            uint8_t out[128];
            ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                          207, "salt too long");
            if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
            return;
        }
        bep44_target(target_buf, k->str.bytes, salt_bytes, salt_len);
    } else {
        if (vb_len < 0) {
            fprintf(stderr, "[dht44:daemon] <- put from %s REJECTED: v too big\n", addr);
            return;
        }
        bep44_immutable_target(target_buf, vb, (size_t)vb_len);
    }
    hex8(tgthex, target_buf);

    /* Token check (we issued it earlier in response to a get) */
    if (!token_matches(tok->str.bytes, tok->str.len, p4, target_buf)) {
        fprintf(stderr,
                "[dht44:daemon] <- put from %s target=%s.. type=%s REJECTED: bad token\n",
                addr, tgthex, is_mutable ? "mut" : "imm");
        uint8_t out[256];
        ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                      203, "bad token");
        if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
        return;
    }

    /* If client supplied target, sanity-check */
    if (target && target->type == BENCODE_STR
        && target->str.len == BEP44_TARGET_LEN
        && memcmp(target->str.bytes, target_buf, BEP44_TARGET_LEN) != 0) {
        fprintf(stderr,
                "[dht44:daemon] <- put from %s target=%s.. REJECTED: claimed target mismatch\n",
                addr, tgthex);
        uint8_t out[256];
        ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                      203, "target mismatch");
        if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
        return;
    }

    fprintf(stderr,
            "[dht44:daemon] <- put from %s target=%s.. type=%s v_len=%zu%s\n",
            addr, tgthex, is_mutable ? "mut" : "imm", v->str.len,
            is_mutable ? "" : "");

    if (is_mutable) {
        /* Verify signature over [salt? + seq + v_bencoded] */
        uint8_t signable[BEP44_MAX_V + 128];
        ssize_t slen = bep44_signable(signable, sizeof(signable),
                                      salt_bytes, salt_len,
                                      seqv->i, vb, (size_t)vb_len);
        if (slen < 0
            || bep44_verify(sig->str.bytes, k->str.bytes,
                            signable, (size_t)slen) < 0) {
            fprintf(stderr, "[dht44:daemon]    REJECTED: invalid signature\n");
            uint8_t out[256];
            ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                          206, "invalid signature");
            if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
            return;
        }

        /* Seq monotonicity + CAS against current store */
        stored_item existing = {0};
        int have_existing = (state_load_item(target_buf, &existing) == 0);
        if (have_existing && existing.mutable_) {
            if (casv && casv->type == BENCODE_INT && casv->i != existing.seq) {
                fprintf(stderr,
                        "[dht44:daemon]    REJECTED: CAS mismatch (got %lld, have %lld)\n",
                        (long long)casv->i, (long long)existing.seq);
                uint8_t out[256];
                ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                              301, "CAS mismatch");
                if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
                return;
            }
            if (seqv->i <= existing.seq) {
                fprintf(stderr,
                        "[dht44:daemon]    REJECTED: seq regression (got %lld, have %lld)\n",
                        (long long)seqv->i, (long long)existing.seq);
                uint8_t out[256];
                ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len,
                                              302, "seq must be > current");
                if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
                return;
            }
        }

        /* OK — persist */
        stored_item si = {0};
        si.mutable_ = 1;
        /* Preserve self-origin if we already had this target as ours
         * (e.g. another peer is mirroring our value back at us). */
        si.origin   = (have_existing && existing.origin == ITEM_ORIGIN_SELF)
                      ? ITEM_ORIGIN_SELF : ITEM_ORIGIN_PEER;
        memcpy(si.pk, k->str.bytes, BEP44_PK_LEN);
        si.seq = seqv->i;
        if (salt_len) { memcpy(si.salt, salt_bytes, salt_len); si.salt_len = salt_len; }
        memcpy(si.sig, sig->str.bytes, BEP44_SIG_LEN);
        memcpy(si.v, v->str.bytes, v->str.len);
        si.v_len = v->str.len;
        if (state_save_item(target_buf, &si) < 0) {
            fprintf(stderr, "[dht44:daemon]    REJECTED: state_save_item failed\n");
            return;
        }
        if (si.origin == ITEM_ORIGIN_PEER) g_items_stored_peer++;
        if (observe_enabled()) {
            observe_bep44_item(target_buf, 1,
                               si.pk, BEP44_PK_LEN,
                               si.salt_len ? si.salt : NULL, si.salt_len,
                               si.seq,
                               si.sig, BEP44_SIG_LEN,
                               vb, (size_t)vb_len);
        }
        fprintf(stderr,
                "[dht44:daemon]    ACCEPTED (mut, %s, seq %lld%s)\n",
                si.origin == ITEM_ORIGIN_SELF ? "self" : "peer",
                (long long)si.seq,
                have_existing
                    ? (existing.seq < si.seq ? ", replaces older" : ", new")
                    : ", new");
    } else {
        /* Immutable — store v_bencoded so target = SHA1(v_b) holds. */
        stored_item si = {0};
        si.mutable_ = 0;
        si.origin = ITEM_ORIGIN_PEER;       /* immutable inbound is always peer */
        if (vb_len < 0 || (size_t)vb_len > sizeof(si.v)) {
            fprintf(stderr, "[dht44:daemon]    REJECTED: v_bencoded too large\n");
            return;
        }
        memcpy(si.v, vb, (size_t)vb_len);
        si.v_len = (size_t)vb_len;
        if (state_save_item(target_buf, &si) < 0) {
            fprintf(stderr, "[dht44:daemon]    REJECTED: state_save_item failed\n");
            return;
        }
        g_items_stored_peer++;
        if (observe_enabled()) {
            observe_bep44_item(target_buf, 0,
                               NULL, 0, NULL, 0, 0, NULL, 0,
                               si.v, si.v_len);
        }
        fprintf(stderr, "[dht44:daemon]    ACCEPTED (imm, peer)\n");
    }

    uint8_t out[256];
    ssize_t n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                         dht_wrap_node_id());
    if (n > 0) { dht_wrap_sendto(peer, peerlen, out, (size_t)n); g_pkts_out++; }
}

/* ============================================================
 * Periodic tasks
 * ============================================================ */

static void
periodic_save_nodes(void)
{
    struct sockaddr_in nodes[256];
    int n = dht_wrap_get_nodes(nodes, 256);
    state_save_nodes(nodes, n);

    struct sockaddr_in6 nodes6[256];
    int n6 = dht_wrap_get_nodes6(nodes6, 256);
    if (n6 > 0) state_save_nodes6(nodes6, n6);
}

/*
 * Re-push a stored item to the network. Used by the periodic republish timer
 * AND once shortly after daemon startup. Without this the value lives only on
 * the peers the original put hit; over time those peers drop it (~2 h cap) and
 * a restarted daemon's lookup converges to a different set of peers that
 * never received it. Re-publishing tells the CURRENT closest 8 peers about
 * it, which is what subsequent gets will then converge to.
 */
static int
republish_one(const uint8_t target[BEP44_TARGET_LEN], void *closure)
{
    (void)closure;
    stored_item si = {0};
    if (state_load_item(target, &si) < 0) return 0;     /* skip on read error */

    /* Only republish things WE put. Peer-origin items are stored for inbound
     * serving but the original publisher is responsible for keeping them
     * alive on the network — we shouldn't claim ownership by re-publishing. */
    if (si.origin == ITEM_ORIGIN_PEER) return 0;

    put_ctx *p = put_ctx_alloc();
    if (!p) return 0;
    p->client_idx = -1;     /* no IPC client to respond to */
    p->mutable_ = si.mutable_;
    memcpy(p->target, target, BEP44_TARGET_LEN);
    if (si.mutable_) {
        memcpy(p->pk, si.pk, BEP44_PK_LEN);
        memcpy(p->sig, si.sig, BEP44_SIG_LEN);
        p->seq = si.seq;
        if (si.salt_len) {
            memcpy(p->salt, si.salt, si.salt_len);
            p->salt_len = si.salt_len;
        }
    }
    memcpy(p->v_bencoded, si.v, si.v_len);
    p->v_len = si.v_len;

    char hex[17]; hex8(hex, target);
    fprintf(stderr, "[dht44:daemon] republish target=%s.. (mutable=%d)\n",
            hex, si.mutable_);

    if (lookup_start(p->target, 15000, on_put_lookup_done, p) == NULL) {
        put_ctx_release(p);
    }
    return 0;
}

static void
periodic_republish(void)
{
    state_walk_items(republish_one, NULL);
}

/* ============================================================
 * Boot + main loop
 * ============================================================ */

int
cmd_daemon(int argc, char **argv)
{
    if (parse_args(argc, argv, &g_args) < 0) return 1;
    if (sodium_init() < 0) {
        fprintf(stderr, "[dht44:daemon] sodium_init failed\n");
        return 2;
    }

    g_lock_fd = state_lock();
    if (g_lock_fd < 0) return 2;

    if (dht_wrap_init_opt(g_args.port, !g_args.no_ipv6) < 0) {
        state_unlock(g_lock_fd);
        return 2;
    }
    dht_wrap_set_query_handler(on_inbound_query, NULL);

    /* warm-start v4 nodes */
    {
        struct sockaddr_in warm[256];
        int n = 0;
        if (state_load_nodes(warm, 256, &n) == 0 && n > 0) {
            for (int i = 0; i < n; i++) dht_wrap_insert_warm(&warm[i]);
            fprintf(stderr, "[dht44:daemon] warm-start v4: pinged %d saved nodes\n", n);
        }
    }
    /* warm-start v6 nodes */
    {
        struct sockaddr_in6 warm6[256];
        int n6 = 0;
        if (state_load_nodes6(warm6, 256, &n6) == 0 && n6 > 0) {
            for (int i = 0; i < n6; i++) dht_wrap_insert_warm6(&warm6[i]);
            fprintf(stderr, "[dht44:daemon] warm-start v6: pinged %d saved nodes\n", n6);
        }
    }

    /* explicit --bootstrap addresses */
    for (int i = 0; i < g_args.bootstrap_count; i++) {
        if (ping_host_port(g_args.bootstrap[i]) == 0) {
            fprintf(stderr, "[dht44:daemon] bootstrap ping → %s\n",
                    g_args.bootstrap[i]);
        } else {
            fprintf(stderr, "[dht44:daemon] bootstrap ping FAILED → %s\n",
                    g_args.bootstrap[i]);
        }
    }

    if (!g_args.no_upnp) {
        upnp_init(g_args.port, (uint32_t)g_args.upnp_lifetime);
    }

    g_listen_fd = ipc_listen();
    if (g_listen_fd < 0) {
        dht_wrap_uninit();
        state_unlock(g_lock_fd);
        return 2;
    }

    randombytes_buf(g_token_secret, sizeof(g_token_secret));

    /* signal handlers */
    struct sigaction sa = {0};
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Observability: db + web + crawler. Enabled when --web or --crawl. */
    int observe_wanted = (g_args.web_port > 0 || g_args.crawl);
    if (observe_wanted) {
        char home[512], dbpath[640];
        if (state_home(home, sizeof(home)) == 0) {
            snprintf(dbpath, sizeof(dbpath), "%s/observe.db", home);
            if (db_open(dbpath) == 0) {
                observe_set_enabled(1);
            }
        }
    }
    if (g_args.web_port > 0) {
        /* Default-on IP redaction so a public-facing dashboard doesn't leak
         * full peer addresses. Operator opts out with --web-show-full-ips. */
        redact_set_enabled(g_args.web_show_full_ips ? 0 : 1);
        if (g_args.web_show_full_ips) {
            fprintf(stderr, "[dht44:daemon] WARNING: --web-show-full-ips on; "
                            "API will expose full peer IPs\n");
        } else {
            fprintf(stderr, "[dht44:daemon] redacting peer IPs in API output "
                            "(IPv4 /24, IPv6 /48). Use --web-show-full-ips to disable.\n");
        }
        http_ws_init(g_args.web_port, g_args.web_static);
        /* Auto-discover GeoIP DBs at $DHT44_HOME/geoip/{city,asn}-lite.mmdb
         * if the user didn't pass --geoip-* explicitly. The /api/peers
         * country panel and the graph ASN coloring are useless without these
         * files, and the failure mode (silent absence) was confusing. */
        const char *city = g_args.geoip_city;
        const char *asn  = g_args.geoip_asn;
        char auto_city[768], auto_asn[768];
        if (!city || !asn) {
            char home[512];
            if (state_home(home, sizeof(home)) == 0) {
                if (!city) {
                    snprintf(auto_city, sizeof(auto_city), "%s/geoip/city-lite.mmdb", home);
                    if (access(auto_city, R_OK) == 0) city = auto_city;
                }
                if (!asn) {
                    snprintf(auto_asn, sizeof(auto_asn), "%s/geoip/asn-lite.mmdb", home);
                    if (access(auto_asn, R_OK) == 0) asn = auto_asn;
                }
            }
        }
        if (city || asn) {
            http_ws_set_geoip(city, asn);
        }
        observe_set_event_sink(ws_bridge, NULL);

        /* Reputation lists. Default $DHT44_HOME/reputation/. Loader is
         * silent if the dir or files are missing. */
        const char *rep_dir = g_args.reputation_dir;
        char        auto_rep[768];
        if (!rep_dir) {
            char home[512];
            if (state_home(home, sizeof(home)) == 0) {
                snprintf(auto_rep, sizeof(auto_rep), "%s/reputation", home);
                rep_dir = auto_rep;
            }
        }
        if (rep_dir) reputation_load_dir(rep_dir);

        /* Inbound + outbound deny set. Empty at boot; populated lazily
         * from the dht_wrap inline reputation/rate-limit checks and
         * the 60s classifier-refresh tick below. */
        deny_init();
        /* Restore cumulative deny counters so the dashboard's
         * denied_pkts headline doesn't flip back to 0 every restart.
         * Saved 1 Hz alongside db_flush below. */
        dht_wrap_load_deny_stats();
    }
    if (g_args.crawl) {
        crawl_start(g_args.crawl_workers, g_args.crawl_pps);
    }

    /* Liveness sweeper: opt-in via --liveness, but enabled-by-default when
     * the daemon is observing (has a db) so /api/stats can show the alive
     * buckets meaningfully. --no-liveness explicitly disables. */
    int liveness_on = g_args.liveness_set ? g_args.liveness : observe_wanted;
    if (liveness_on && observe_wanted) {
        liveness_start(g_args.liveness_window_h,
                       g_args.liveness_pps,
                       g_args.prune_days);
    }

    fprintf(stderr, "[dht44:daemon] listening UDP :%u, IPC at $DHT44_HOME/sock\n",
            (unsigned)g_args.port);

    time_t next_save     = time(NULL) + 5 * 60;
    /* First republish runs ~60 s after boot so a restarted daemon re-pushes
     * stored items to the current closest peers as soon as the routing table
     * is populated enough. After that, normal cadence (--republish minutes). */
    time_t next_republish = time(NULL) + 60;
    int    initial_republish_done = 0;
    time_t next_upnp     = time(NULL) + 30 * 60;
    time_t next_status   = time(NULL) + 30;
    time_t next_bootstrap_retry = time(NULL) + 2;
    time_t booted_at     = time(NULL);
    int    bootstrap_pinged = 0;
    int    last_good = -1;
    time_t next_flush    = time(NULL) + 1;      /* db + ws heartbeat */
    /* deny-list refresh: every 60s walk the recently-active peers,
     * run classify_compute, deny_add anything class >=monitor. */
    time_t next_deny_refresh = time(NULL) + 60;

    while (!g_exit) {
        int wrap_wake_ms = 1000;
        int look_wake_ms = 1000;
        dht_wrap_step(NULL, 0, NULL, 0, &wrap_wake_ms);
        lookup_tick(&look_wake_ms);
        int wake_ms = wrap_wake_ms < look_wake_ms ? wrap_wake_ms : look_wake_ms;
        if (wake_ms < 50)   wake_ms = 50;
        if (wake_ms > 1000) wake_ms = 1000;

        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        int udp_fd  = dht_wrap_socket();
        int udp6_fd = dht_wrap_socket6();
        if (udp_fd  >= 0) { FD_SET(udp_fd,  &rfds); if (udp_fd  > maxfd) maxfd = udp_fd;  }
        if (udp6_fd >= 0) { FD_SET(udp6_fd, &rfds); if (udp6_fd > maxfd) maxfd = udp6_fd; }
        FD_SET(g_listen_fd, &rfds);
        if (g_listen_fd > maxfd) maxfd = g_listen_fd;
        for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
            if (g_clients[i]) {
                int f = ipc_conn_fd(g_clients[i]);
                FD_SET(f, &rfds);
                if (f > maxfd) maxfd = f;
            }
        }
        struct timeval tv = { wake_ms / 1000, (wake_ms % 1000) * 1000 };
        int sr = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[dht44:daemon] select: %s\n", strerror(errno));
            break;
        }

        /* UDP packet ready on either family's socket. */
        int fds[2] = { udp_fd, udp6_fd };
        for (int fi = 0; fi < 2; fi++) {
            int fd = fds[fi];
            if (fd < 0 || !FD_ISSET(fd, &rfds)) continue;
            uint8_t pkt[2048];
            for (;;) {
                struct sockaddr_storage from;
                socklen_t fromlen = sizeof(from);
                ssize_t n = recvfrom(fd, pkt, sizeof(pkt) - 1, 0,
                                     (struct sockaddr *)&from, &fromlen);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    fprintf(stderr, "[dht44:daemon] recvfrom: %s\n", strerror(errno));
                    break;
                }
                pkt[n] = '\0';        /* jech expects NUL-terminated buffer */
                g_pkts_in++;
                int ww = 1000;
                dht_wrap_step(pkt, (size_t)n,
                              (struct sockaddr *)&from, (int)fromlen, &ww);
            }
        }

        /* IPC accept */
        if (FD_ISSET(g_listen_fd, &rfds)) {
            int c = ipc_accept(g_listen_fd);
            if (c >= 0) {
                ipc_conn *conn = ipc_conn_new(c);
                int slot = conn ? client_slot_alloc(conn) : -1;
                if (slot < 0) {
                    fprintf(stderr, "[dht44:daemon] IPC accept: no slot, dropping\n");
                    if (conn) ipc_conn_free(conn);
                    else close(c);
                } else {
                    fprintf(stderr, "[dht44:daemon] IPC[%d] accepted\n", slot);
                }
            }
        }

        /* Existing IPC clients */
        for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
            if (!g_clients[i]) continue;
            if (!FD_ISSET(ipc_conn_fd(g_clients[i]), &rfds)) continue;
            const uint8_t *msg = NULL;
            size_t msg_len = 0;
            int rc = ipc_conn_try_read(g_clients[i], &msg, &msg_len);
            if (rc < 0) { client_close(i); continue; }
            if (rc == 1) {
                dispatch_request(i, msg, msg_len);
                /* dispatch may have closed the conn already */
                if (g_clients[i]) ipc_conn_consume(g_clients[i]);
            }
        }

        /* late bootstrap if routing table is sparse */
        if (!bootstrap_pinged && time(NULL) - booted_at >= 3) {
            int g = 0, d = 0;
            dht_wrap_status(&g, &d);
            if (g < 4 && !g_args.no_routers) {
                fprintf(stderr, "[dht44:daemon] sparse table (good=%d dub=%d), pinging routers\n", g, d);
                dht_wrap_ping_routers();
            }
            bootstrap_pinged = 1;
        }
        /* Re-ping --bootstrap addresses while we still have no good peers.
         * The first ping at boot can lose the race against a sibling daemon's
         * bind on a shared host. Retry every 2 s until we have anyone. */
        if (g_args.bootstrap_count > 0 && time(NULL) >= next_bootstrap_retry) {
            int g = 0, d = 0;
            dht_wrap_status(&g, &d);
            if (g + d == 0) {
                for (int i = 0; i < g_args.bootstrap_count; i++) {
                    ping_host_port(g_args.bootstrap[i]);
                }
            }
            next_bootstrap_retry = time(NULL) + 2;
        }

        time_t now = time(NULL);
        if (now >= next_save) {
            fprintf(stderr, "[dht44:daemon] saving nodes.bin\n");
            periodic_save_nodes(); next_save = now + 5 * 60;
        }
        if (now >= next_republish) {
            fprintf(stderr, "[dht44:daemon] republish tick%s\n",
                    initial_republish_done ? "" : " (initial post-boot)");
            periodic_republish();
            next_republish = now + (time_t)g_args.republish_min * 60;
            initial_republish_done = 1;
        }
        if (now >= next_upnp) {
            if (!g_args.no_upnp) {
                fprintf(stderr, "[dht44:daemon] upnp refresh\n");
                upnp_refresh();
            }
            next_upnp = now + 30 * 60;
        }
        if (now >= next_status) {
            int g = 0, d = 0, g6 = 0, d6 = 0;
            dht_wrap_status (&g,  &d);
            dht_wrap_status6(&g6, &d6);
            if (g != last_good || g_pkts_in || g_pkts_out || g_ipc_reqs) {
                fprintf(stderr,
                    "[dht44:daemon] table v4[good=%d dub=%d] v6[good=%d dub=%d]  rx=%lu tx=%lu  q_in[get=%lu put=%lu] q_out=%lu  ipc=%lu  stored_for_peers=%lu\n",
                    g, d, g6, d6, g_pkts_in, g_pkts_out,
                    g_q_in_get, g_q_in_put, g_q_out, g_ipc_reqs,
                    g_items_stored_peer);
                last_good = g;
            }
            next_status = now + 30;
        }

        /* Crawler advance + db commit + ws heartbeat. crawl_tick is cheap
         * enough to call every loop; db_flush + heartbeat run 1 Hz. */
        crawl_tick();
        liveness_tick();
        http_ws_service(0);
        if (now >= next_flush) {
            db_flush();
            http_ws_heartbeat();
            deny_tick(now);                    /* evict expired entries */
            dht_wrap_save_deny_stats();        /* persist counters */
            next_flush = now + 1;
        }
        if (now >= next_deny_refresh) {
            /* Pull up to 1000 recently-active (last 6h) peers, run the
             * shared classifier, deny_add class>=monitor. The 6h window
             * matches the alive-bucket the dashboard tracks; older
             * peers haven't sent us packets in a while and their class
             * will be re-confirmed if they come back. */
            static struct db_peer_signal_row buf[1000];
            int n = db_select_peers_with_signals(
                        (int)(sizeof(buf)/sizeof(buf[0])),
                        (int64_t)now - 6 * 3600, buf);
            int added = 0;
            for (int i = 0; i < n; i++) {
                struct peer_signals sig = {0};
                sig.as_src       = buf[i].as_src;
                sig.as_dst       = buf[i].as_dst;
                sig.same_ip      = buf[i].same_ip;
                sig.queries_in   = buf[i].queries_in;
                sig.queries_out  = buf[i].queries_out;
                sig.ro           = buf[i].ro;
                sig.bep42_ok     = buf[i].bep42_ok;
                sig.has_v_string = buf[i].has_v_string;
                /* asn_org / greynoise / iblocklist enrichment skipped
                 * here — the inline reputation_lookup in dht_wrap
                 * already handles iBlockList strong-deny; the 60s
                 * refresh only adds behavioural denials. (Future:
                 * also pre-fetch geoip + greynoise per peer if we
                 * find the score is consistently off because of
                 * missing context.) */
                struct classify_result res;
                classify_compute(&sig, &res);
                if (res.cls && (strcmp(res.cls, "honeypot") == 0
                                || strcmp(res.cls, "monitor") == 0)) {
                    struct sockaddr_storage ss = {0};
                    socklen_t ss_len = 0;
                    if (parse_ip_lenient(buf[i].ip, &ss, &ss_len)) {
                        if (ss.ss_family == AF_INET)
                            ((struct sockaddr_in *)&ss)->sin_port =
                                htons((uint16_t)buf[i].port);
                        else if (ss.ss_family == AF_INET6)
                            ((struct sockaddr_in6 *)&ss)->sin6_port =
                                htons((uint16_t)buf[i].port);
                        deny_add((struct sockaddr *)&ss, ss_len,
                                 DENY_REASON_CLASSIFIER, 3600);
                        added++;
                    }
                }
            }
            int total; int by_reason[3];
            deny_stats(&total, by_reason);
            fprintf(stderr,
                "[dht44:deny] refresh scanned=%d added=%d "
                "set: rep=%d rate=%d cls=%d total=%d\n",
                n, added, by_reason[0], by_reason[1], by_reason[2], total);
            next_deny_refresh = now + 60;
        }
    }

    fprintf(stderr, "[dht44:daemon] shutting down\n");
    liveness_stop();
    crawl_stop();
    periodic_save_nodes();
    if (!g_args.no_upnp) upnp_shutdown();
    for (int i = 0; i < MAX_IPC_CLIENTS; i++) client_close(i);
    if (g_listen_fd >= 0) close(g_listen_fd);
    ipc_cleanup();
    dht_wrap_uninit();
    http_ws_uninit();
    db_close();
    sodium_memzero(g_token_secret, sizeof(g_token_secret));
    state_unlock(g_lock_fd);
    return 0;
}
