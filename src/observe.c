#define _POSIX_C_SOURCE 200809L
#include "observe.h"

#include <arpa/inet.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bencode.h"
#include "db.h"
#include "dht_wrap.h"
#include "redact.h"

#define TAG "[dht44:observe] "

static int              g_enabled = 0;
static observe_event_cb g_sink    = NULL;
static void            *g_sink_cl = NULL;

int  observe_enabled(void)            { return g_enabled; }
void observe_set_enabled(int on)      { g_enabled = on ? 1 : 0; }

void
observe_set_event_sink(observe_event_cb cb, void *closure)
{
    g_sink = cb;
    g_sink_cl = closure;
}

static void
emit(const char *topic, json_t *payload)
{
    if (!g_sink || !payload) { if (payload) json_decref(payload); return; }
    json_t *env = json_object();
    json_object_set_new(env, "topic", json_string(topic));
    json_object_set_new(env, "data",  payload);     /* steals ref */
    char *js = json_dumps(env, JSON_COMPACT);
    if (js) g_sink(topic, js, g_sink_cl);
    free(js);
    json_decref(env);
}

static void
peer_json(json_t *o, const struct sockaddr *peer)
{
    char ip[INET6_ADDRSTRLEN] = {0};
    int  port = 0;
    if (peer->sa_family == AF_INET) {
        const struct sockaddr_in *p = (const struct sockaddr_in *)peer;
        inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
        port = ntohs(p->sin_port);
    } else if (peer->sa_family == AF_INET6) {
        const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)peer;
        inet_ntop(AF_INET6, &p->sin6_addr, ip, sizeof(ip));
        port = ntohs(p->sin6_port);
    }
    char redacted[64];
    if (redact_ip(ip, redacted, sizeof(redacted)) == 0) {
        json_object_set_new(o, "ip", json_string(redacted));
    } else {
        json_object_set_new(o, "ip", json_string(ip));
    }
    json_object_set_new(o, "port", json_integer(port));
}

static char *
hex_dup(const uint8_t *bytes, size_t len)
{
    static const char H[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = H[bytes[i] >> 4];
        out[i*2+1] = H[bytes[i] & 0xf];
    }
    out[len*2] = 0;
    return out;
}

static void
set_hex(json_t *o, const char *k, const uint8_t *b, size_t n)
{
    if (!b || !n) { json_object_set_new(o, k, json_null()); return; }
    char *hex = hex_dup(b, n);
    if (hex) { json_object_set_new(o, k, json_string(hex)); free(hex); }
    else     { json_object_set_new(o, k, json_null()); }
}

/* Map query type: outer peek captures q only for 'q' messages. For responses
 * (y='r') we can't know the original query from the peek alone, so we label
 * them "r" with q=NULL. */
static const char *
y_str(const dht_wrap_peek *p)
{
    if (p->y_len != 1) return "?";
    switch (p->y[0]) {
        case 'q': return "q";
        case 'r': return "r";
        case 'e': return "e";
    }
    return "?";
}

static char *
dup_cstr(const uint8_t *b, size_t n)
{
    if (n > 64) n = 64;
    char *s = malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, b, n);
    s[n] = 0;
    return s;
}

/* Extract a 20-byte target/info_hash/id out of a freshly decoded args dict. */
static const uint8_t *
args_target(const bencode_value *a, size_t *len_out)
{
    if (!a || a->type != BENCODE_DICT) return NULL;
    static const char *keys[] = { "target", "info_hash" };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        const bencode_value *v = bencode_dict_get(a, keys[i]);
        if (v && v->type == BENCODE_STR && v->str.len == 20) {
            *len_out = 20;
            return v->str.bytes;
        }
    }
    return NULL;
}

static const uint8_t *
args_node_id(const bencode_value *a, size_t *len_out)
{
    if (!a || a->type != BENCODE_DICT) return NULL;
    const bencode_value *id = bencode_dict_get(a, "id");
    if (id && id->type == BENCODE_STR && id->str.len == 20) {
        *len_out = 20;
        return id->str.bytes;
    }
    return NULL;
}

/* ============================================================
 * observe_packet
 *
 * Fast path: only peek, don't full-decode. Record one queries row + touch the
 * peer row. Full decoding happens in observe_query_fields after the daemon's
 * on_inbound_query has already decoded the args dict for its own use.
 * ============================================================ */

void
observe_packet(int dir,
               const struct sockaddr *peer, socklen_t peerlen,
               const uint8_t *buf, size_t len,
               const dht_wrap_peek *peek)
{
    if (!g_enabled || !peer || !buf || !len) return;

    dht_wrap_peek local;
    if (!peek) {
        if (dht_wrap_peek_top(buf, len, &local) < 0) return;
        peek = &local;
    }
    int64_t now = time(NULL);
    const char *dirs = (dir == OBSERVE_OUT) ? "out" : "in";
    const char *y    = y_str(peek);
    char *q_copy = NULL;
    if (y[0] == 'q' && peek->q_len)
        q_copy = dup_cstr(peek->q, peek->q_len);

    /* Enrich: decode args for inbound BEP 5 queries (find_node, get_peers,
     * announce_peer, ping). BEP 44 get/put already flows through
     * observe_query_fields from cmd_daemon's handler. This lets us capture
     * node_id and info_hash / target from jech-handled traffic too. */
    const uint8_t *target_ptr = NULL;
    if (dir == OBSERVE_IN && y[0] == 'q' && q_copy) {
        bencode_arena *ar;
        bencode_value *root = bencode_parse(buf, len, &ar);
        if (root && root->type == BENCODE_DICT) {
            const bencode_value *a = bencode_dict_get(root, "a");
            if (a && a->type == BENCODE_DICT) {
                const bencode_value *id = bencode_dict_get(a, "id");
                if (id && id->type == BENCODE_STR && id->str.len == 20) {
                    db_upsert_peer(peer, peerlen, id->str.bytes, 1, NULL, 0, -1, -1, -1, 0);
                }
                const char *tkey = NULL;
                const char *src  = NULL;
                if (strcmp(q_copy, "find_node") == 0) {
                    tkey = "target"; src = "find_node";
                } else if (strcmp(q_copy, "get_peers") == 0) {
                    tkey = "info_hash"; src = "get_peers";
                } else if (strcmp(q_copy, "announce_peer") == 0) {
                    tkey = "info_hash"; src = "announce";
                } else if (strcmp(q_copy, "sample_infohashes") == 0) {
                    tkey = "target"; src = "bep51";
                }
                if (tkey) {
                    const bencode_value *tv = bencode_dict_get(a, tkey);
                    if (tv && tv->type == BENCODE_STR && tv->str.len == 20) {
                        db_upsert_infohash(tv->str.bytes, src);
                        target_ptr = tv->str.bytes;
                    }
                }
            }
        }
        if (root) bencode_free(ar);
    }

    db_insert_query(now, peer, peerlen, dirs, y, q_copy, target_ptr, (int)len);

    /* Peer presence row. Touches last_seen + bumps direction counter. */
    char peer_dir = (dir == OBSERVE_OUT) ? 'o' : 'i';
    db_upsert_peer(peer, peerlen, NULL, 0,
                   peek->v, peek->v_len,
                   peek->ro,
                   -1, -1, peer_dir);

    json_t *js = json_object();
    peer_json(js, peer);
    json_object_set_new(js, "ts",        json_integer(now));
    json_object_set_new(js, "direction", json_string(dirs));
    json_object_set_new(js, "y",         json_string(y));
    json_object_set_new(js, "q",         q_copy ? json_string(q_copy) : json_null());
    if (peek->v_len) set_hex(js, "v_string", peek->v, peek->v_len);
    else             json_object_set_new(js, "v_string", json_null());
    if (target_ptr) set_hex(js, "target", target_ptr, 20);
    else            json_object_set_new(js, "target", json_null());
    json_object_set_new(js, "raw_size",  json_integer((long long)len));
    emit("queries", js);

    free(q_copy);
}

void
observe_query_fields(const struct sockaddr *peer, socklen_t peerlen,
                     int is_put,
                     const bencode_value *a)
{
    if (!g_enabled || !peer || !a) return;

    size_t idlen = 0;
    const uint8_t *id = args_node_id(a, &idlen);
    if (id) {
        db_upsert_peer(peer, peerlen, id, 1, NULL, 0, -1, -1, -1, 0);
    }

    size_t tlen = 0;
    const uint8_t *target = args_target(a, &tlen);
    if (target) {
        /* Feed into infohashes table. We can't always tell whether this target
         * is an info_hash (BEP 5) or a BEP 44 target without more context,
         * so we tag by observed query class. */
        const char *src = is_put ? "bep44" : NULL;
        const bencode_value *ih = bencode_dict_get(a, "info_hash");
        if (ih && ih->type == BENCODE_STR && ih->str.len == 20) src = "get_peers";
        if (!src) {
            /* Generic get — most often BEP 44 in our daemon's traffic, but
             * could be anything. Tag as 'query' for ambiguous. */
            src = "query";
        }
        db_upsert_infohash(target, src);

        json_t *js = json_object();
        peer_json(js, peer);
        set_hex(js, "target", target, tlen);
        json_object_set_new(js, "source", json_string(src));
        json_object_set_new(js, "ts", json_integer(time(NULL)));
        emit("infohashes", js);
    }
}

void
observe_rtt(const struct sockaddr *peer, socklen_t peerlen, int rtt_ms)
{
    if (!g_enabled || !peer || rtt_ms < 0) return;
    db_upsert_peer(peer, peerlen, NULL, 0, NULL, 0, -1, -1, rtt_ms, 0);
}

void
observe_bep44_item(const uint8_t target[BEP44_TARGET_LEN],
                   int mutable_,
                   const uint8_t *pk, size_t pk_len,
                   const uint8_t *salt, size_t salt_len,
                   int64_t seq,
                   const uint8_t *sig, size_t sig_len,
                   const uint8_t *v, size_t v_len)
{
    if (!g_enabled || !target || !v || !v_len) return;
    db_upsert_bep44_item(target, mutable_,
                         pk, pk_len,
                         salt, salt_len,
                         seq,
                         sig, sig_len,
                         v, v_len);

    json_t *js = json_object();
    set_hex(js, "target", target, BEP44_TARGET_LEN);
    json_object_set_new(js, "mutable", json_integer(mutable_ ? 1 : 0));
    if (pk_len)   set_hex(js, "pk",   pk,   pk_len);   else json_object_set_new(js, "pk",   json_null());
    if (salt_len) set_hex(js, "salt", salt, salt_len); else json_object_set_new(js, "salt", json_null());
    if (sig_len)  set_hex(js, "sig",  sig,  sig_len);  else json_object_set_new(js, "sig",  json_null());
    json_object_set_new(js, "seq", json_integer(seq));
    set_hex(js, "v", v, v_len);
    json_object_set_new(js, "ts", json_integer(time(NULL)));
    emit("bep44", js);
}
