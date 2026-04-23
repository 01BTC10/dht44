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
#include "dht_wrap.h"
#include "ipc.h"
#include "lookup.h"
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
    const char *bootstrap[MAX_BOOTSTRAP];
    int      bootstrap_count;
} daemon_args;

static const char USAGE_DAEMON[] =
    "usage: dht44 daemon [--port N] [--republish MIN] [--no-upnp]\n"
    "                    [--upnp-lifetime SEC] [--bootstrap HOST:PORT]...\n"
    "                    [--no-routers]\n";

static int
parse_args(int argc, char **argv, daemon_args *a)
{
    memset(a, 0, sizeof(*a));
    a->port = 6881;
    a->republish_min = 60;
    a->upnp_lifetime = 3600;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            a->port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--republish") == 0 && i + 1 < argc) {
            a->republish_min = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-upnp") == 0) {
            a->no_upnp = 1;
        } else if (strcmp(argv[i], "--no-routers") == 0) {
            a->no_routers = 1;
        } else if (strcmp(argv[i], "--upnp-lifetime") == 0 && i + 1 < argc) {
            a->upnp_lifetime = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bootstrap") == 0 && i + 1 < argc) {
            if (a->bootstrap_count >= MAX_BOOTSTRAP) {
                fprintf(stderr, "[dht44:daemon] too many --bootstrap entries\n");
                return -1;
            }
            a->bootstrap[a->bootstrap_count++] = argv[++i];
        } else {
            fputs(USAGE_DAEMON, stderr);
            return -1;
        }
    }
    return 0;
}

/* "host:port" → ping. Used by --bootstrap */
static int
ping_host_port(const char *hp)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", hp);
    char *colon = strrchr(buf, ':');
    if (!colon) return -1;
    *colon = 0;
    const char *host = buf;
    const char *port = colon + 1;

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
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

static const char *
sa_str(const struct sockaddr *peer, char buf[24])
{
    const struct sockaddr_in *p = (const struct sockaddr_in *)peer;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
    snprintf(buf, 24, "%s:%u", ip, ntohs(p->sin_port));
    return buf;
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

/* ============================================================
 * Item blob helpers
 * Format: seq(8 BE) || salt_len(1) || salt || sig(64) || v_len(2 BE) || v_bencoded
 * ============================================================ */

typedef struct {
    int64_t       seq;
    const uint8_t *salt;
    size_t         salt_len;
    const uint8_t *sig;
    const uint8_t *v;
    size_t         v_len;
} item_view;

static int
parse_item(const uint8_t *bytes, size_t len, item_view *out)
{
    if (len < 8 + 1 + 64 + 2) return -1;
    size_t pos = 0;
    int64_t seq = 0;
    for (int i = 0; i < 8; i++) seq = (seq << 8) | bytes[pos++];
    out->seq = seq;
    size_t salt_len = bytes[pos++];
    if (salt_len > BEP44_MAX_SALT || salt_len + 64 + 2 > len - pos) return -1;
    out->salt = salt_len ? bytes + pos : NULL;
    out->salt_len = salt_len;
    pos += salt_len;
    out->sig = bytes + pos;
    pos += 64;
    if (pos + 2 > len) return -1;
    size_t v_len = ((size_t)bytes[pos] << 8) | bytes[pos + 1];
    pos += 2;
    if (v_len > BEP44_MAX_V || pos + v_len != len) return -1;
    out->v = bytes + pos;
    out->v_len = v_len;
    return 0;
}

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
                                (int)sizeof(t->peer),
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
                bencode_cstr(&w, "k");   bencode_str(&w, best->k, BEP44_PK_LEN);
                bencode_cstr(&w, "ok");  bencode_int(&w, 1);
                bencode_cstr(&w, "seq"); bencode_int(&w, best->seq);
                bencode_cstr(&w, "sig"); bencode_str(&w, best->sig, BEP44_SIG_LEN);
                bencode_cstr(&w, "v");   bencode_raw(&w, best->v, best->v_len);
            } else if (best) {
                bencode_cstr(&w, "ok"); bencode_int(&w, 1);
                bencode_cstr(&w, "v");  bencode_raw(&w, best->v, best->v_len);
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
    const bencode_value *item   = bencode_dict_get(req, "item");
    const bencode_value *vbenc  = bencode_dict_get(req, "v");
    const bencode_value *mut    = bencode_dict_get(req, "mutable");
    const bencode_value *cas    = bencode_dict_get(req, "cas");

    int is_mutable = (mut && mut->type == BENCODE_INT && mut->i != 0);

    put_ctx *p = put_ctx_alloc();
    if (!p) {
        send_ipc_error(g_clients[client_idx], "too many in-flight puts");
        client_close(client_idx);
        return;
    }
    p->client_idx = client_idx;
    p->mutable_ = is_mutable;

    if (is_mutable) {
        if (!target || target->type != BENCODE_STR
            || target->str.len != BEP44_TARGET_LEN
            || !item || item->type != BENCODE_STR) {
            send_ipc_error(g_clients[client_idx], "missing target/item for put_mutable");
            put_ctx_release(p);
            client_close(client_idx);
            return;
        }
        memcpy(p->target, target->str.bytes, BEP44_TARGET_LEN);

        item_view iv;
        if (parse_item(item->str.bytes, item->str.len, &iv) < 0) {
            send_ipc_error(g_clients[client_idx], "malformed item blob");
            put_ctx_release(p);
            client_close(client_idx);
            return;
        }
        p->seq = iv.seq;
        memcpy(p->sig, iv.sig, BEP44_SIG_LEN);
        if (iv.salt_len) {
            memcpy(p->salt, iv.salt, iv.salt_len);
            p->salt_len = iv.salt_len;
        }
        if (iv.v_len > sizeof(p->v_bencoded)) {
            send_ipc_error(g_clients[client_idx], "v too large");
            put_ctx_release(p);
            client_close(client_idx);
            return;
        }
        memcpy(p->v_bencoded, iv.v, iv.v_len);
        p->v_len = iv.v_len;

        /* pubkey: from a separate field "k" in the request */
        const bencode_value *k = bencode_dict_get(req, "k");
        if (!k || k->type != BENCODE_STR || k->str.len != BEP44_PK_LEN) {
            send_ipc_error(g_clients[client_idx], "missing k for put_mutable");
            put_ctx_release(p);
            client_close(client_idx);
            return;
        }
        memcpy(p->pk, k->str.bytes, BEP44_PK_LEN);

        if (cas && cas->type == BENCODE_INT) {
            p->has_cas = 1;
            p->cas = cas->i;
        }
        /* persist for republish */
        state_save_item(p->target, item->str.bytes, item->str.len);
    } else {
        if (!vbenc || vbenc->type != BENCODE_STR
            || vbenc->str.len > sizeof(p->v_bencoded)) {
            send_ipc_error(g_clients[client_idx], "missing v for put_immutable");
            put_ctx_release(p);
            client_close(client_idx);
            return;
        }
        memcpy(p->v_bencoded, vbenc->str.bytes, vbenc->str.len);
        p->v_len = vbenc->str.len;
        bep44_immutable_target(p->target, p->v_bencoded, p->v_len);
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
    get_ctx *g = get_ctx_alloc();
    if (!g) {
        send_ipc_error(g_clients[client_idx], "too many in-flight gets");
        client_close(client_idx);
        return;
    }
    g->client_idx = client_idx;
    g->mutable_ = (mut && mut->type == BENCODE_INT && mut->i != 0);

    uint8_t target_buf[BEP44_TARGET_LEN];
    memcpy(target_buf, target->str.bytes, BEP44_TARGET_LEN);
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

static void
on_inbound_query(const struct sockaddr *peer, int peerlen,
                 const uint8_t *tid, size_t tid_len,
                 int is_put,
                 const bencode_value *a,
                 void *closure)
{
    (void)closure; (void)peerlen;
    const struct sockaddr_in *p4 = (const struct sockaddr_in *)peer;

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

        uint8_t blob[2048];
        size_t blob_len = 0;
        int have = state_load_item(target, blob, sizeof(blob), &blob_len) == 0;

        uint8_t token[TOKEN_LEN];
        issue_token(token, p4, target);

        uint8_t out[2048];
        ssize_t n;
        if (have) {
            item_view iv;
            if (parse_item(blob, blob_len, &iv) == 0 && iv.salt_len == 0) {
                /* immutable response (no k/sig/seq/salt) */
                n = bep44_build_get_response_immutable(
                    out, sizeof(out), tid, tid_len,
                    dht_wrap_node_id(), NULL, 0,
                    token, sizeof(token),
                    iv.v, iv.v_len);
            } else if (parse_item(blob, blob_len, &iv) == 0) {
                /* mutable: we don't store pk in the blob. Skip for v1
                 * (peer will get our id only). TODO: extend item format. */
                n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                             dht_wrap_node_id());
            } else {
                n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                             dht_wrap_node_id());
            }
        } else {
            /* no data — respond with id only, BEP 5 style */
            n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                         dht_wrap_node_id());
        }
        if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        return;
    }

    /* PUT — validate token, sig, accept */
    const bencode_value *target = bencode_dict_get(a, "target");
    const bencode_value *tok    = bencode_dict_get(a, "token");
    const bencode_value *v      = bencode_dict_get(a, "v");
    if (!tok || tok->type != BENCODE_STR || !v || v->type != BENCODE_STR) return;
    {
        char addr[24];
        sa_str(peer, addr);
        fprintf(stderr, "[dht44:daemon] <- put from %s\n", addr);
        g_q_in_put++;
    }

    uint8_t target_buf[BEP44_TARGET_LEN];
    if (target && target->type == BENCODE_STR
        && target->str.len == BEP44_TARGET_LEN) {
        memcpy(target_buf, target->str.bytes, BEP44_TARGET_LEN);
    } else {
        /* compute target ourselves */
        const bencode_value *k = bencode_dict_get(a, "k");
        const bencode_value *salt = bencode_dict_get(a, "salt");
        if (k && k->type == BENCODE_STR && k->str.len == BEP44_PK_LEN) {
            const uint8_t *salt_bytes = NULL;
            size_t salt_len = 0;
            if (salt && salt->type == BENCODE_STR) {
                salt_bytes = salt->str.bytes;
                salt_len = salt->str.len;
            }
            bep44_target(target_buf, k->str.bytes, salt_bytes, salt_len);
        } else {
            bep44_immutable_target(target_buf, v->str.bytes, v->str.len);
        }
    }

    if (!token_matches(tok->str.bytes, tok->str.len, p4, target_buf)) {
        uint8_t out[256];
        ssize_t n = bep44_build_error(out, sizeof(out), tid, tid_len, 203, "bad token");
        if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
        return;
    }

    /* Accept and persist (no sig verification yet for inbound — see TODO) */
    /* TODO commit-12: verify sig, enforce seq monotonicity, handle CAS. */

    uint8_t out[256];
    ssize_t n = bep44_build_put_response(out, sizeof(out), tid, tid_len,
                                         dht_wrap_node_id());
    if (n > 0) dht_wrap_sendto(peer, peerlen, out, (size_t)n);
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
}

static int
republish_one(const uint8_t target[BEP44_TARGET_LEN], void *closure)
{
    (void)closure;
    fprintf(stderr, "[dht44:daemon] republish target ");
    for (size_t i = 0; i < 4; i++) fprintf(stderr, "%02x", target[i]);
    fputs("...\n", stderr);
    /* TODO: actually re-issue the put. For v1 we just log. */
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

    if (dht_wrap_init(g_args.port) < 0) {
        state_unlock(g_lock_fd);
        return 2;
    }
    dht_wrap_set_query_handler(on_inbound_query, NULL);

    /* warm-start nodes */
    {
        struct sockaddr_in warm[256];
        int n = 0;
        if (state_load_nodes(warm, 256, &n) == 0 && n > 0) {
            for (int i = 0; i < n; i++) dht_wrap_insert_warm(&warm[i]);
            fprintf(stderr, "[dht44:daemon] warm-start: pinged %d saved nodes\n", n);
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

    fprintf(stderr, "[dht44:daemon] listening UDP :%u, IPC at $DHT44_HOME/sock\n",
            (unsigned)g_args.port);

    time_t next_save     = time(NULL) + 5 * 60;
    time_t next_republish = time(NULL) + (time_t)g_args.republish_min * 60;
    time_t next_upnp     = time(NULL) + 30 * 60;
    time_t next_status   = time(NULL) + 30;
    time_t next_bootstrap_retry = time(NULL) + 2;
    time_t booted_at     = time(NULL);
    int    bootstrap_pinged = 0;
    int    last_good = -1;

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
        int udp_fd = dht_wrap_socket();
        if (udp_fd >= 0) { FD_SET(udp_fd, &rfds); if (udp_fd > maxfd) maxfd = udp_fd; }
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

        /* UDP packet ready */
        if (udp_fd >= 0 && FD_ISSET(udp_fd, &rfds)) {
            uint8_t pkt[2048];
            for (;;) {
                struct sockaddr_storage from;
                socklen_t fromlen = sizeof(from);
                ssize_t n = recvfrom(udp_fd, pkt, sizeof(pkt) - 1, 0,
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
            fprintf(stderr, "[dht44:daemon] republish tick\n");
            periodic_republish();
            next_republish = now + (time_t)g_args.republish_min * 60;
        }
        if (now >= next_upnp) {
            if (!g_args.no_upnp) {
                fprintf(stderr, "[dht44:daemon] upnp refresh\n");
                upnp_refresh();
            }
            next_upnp = now + 30 * 60;
        }
        if (now >= next_status) {
            int g = 0, d = 0;
            dht_wrap_status(&g, &d);
            if (g != last_good || g_pkts_in || g_pkts_out || g_ipc_reqs) {
                fprintf(stderr,
                    "[dht44:daemon] table good=%d dub=%d  rx=%lu tx=%lu  q_in[get=%lu put=%lu] q_out=%lu  ipc=%lu\n",
                    g, d, g_pkts_in, g_pkts_out,
                    g_q_in_get, g_q_in_put, g_q_out, g_ipc_reqs);
                last_good = g;
            }
            next_status = now + 30;
        }
    }

    fprintf(stderr, "[dht44:daemon] shutting down\n");
    periodic_save_nodes();
    if (!g_args.no_upnp) upnp_shutdown();
    for (int i = 0; i < MAX_IPC_CLIENTS; i++) client_close(i);
    if (g_listen_fd >= 0) close(g_listen_fd);
    ipc_cleanup();
    dht_wrap_uninit();
    sodium_memzero(g_token_secret, sizeof(g_token_secret));
    state_unlock(g_lock_fd);
    return 0;
}
