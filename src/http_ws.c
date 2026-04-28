#define _GNU_SOURCE
#include "http_ws.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <libwebsockets.h>
#include <limits.h>
#include <maxminddb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "classifier.h"
#include "db.h"
#include "dht_wrap.h"
#include "reputation.h"

#define TAG "[dht44:web] "

/* ============================================================
 * MaxMind GeoIP
 * ============================================================ */

static MMDB_s g_city;
static MMDB_s g_asn;
static int    g_city_ok = 0;
static int    g_asn_ok  = 0;

int
http_ws_set_geoip(const char *city_path, const char *asn_path)
{
    if (g_city_ok) { MMDB_close(&g_city); g_city_ok = 0; }
    if (g_asn_ok)  { MMDB_close(&g_asn);  g_asn_ok = 0;  }

    if (city_path && MMDB_open(city_path, MMDB_MODE_MMAP, &g_city) == MMDB_SUCCESS) {
        g_city_ok = 1;
        fprintf(stderr, TAG "geoip city db loaded: %s\n", city_path);
    } else if (city_path) {
        fprintf(stderr, TAG "geoip city open failed: %s\n", city_path);
    }
    if (asn_path && MMDB_open(asn_path, MMDB_MODE_MMAP, &g_asn) == MMDB_SUCCESS) {
        g_asn_ok = 1;
        fprintf(stderr, TAG "geoip asn db loaded: %s\n", asn_path);
    } else if (asn_path) {
        fprintf(stderr, TAG "geoip asn open failed: %s\n", asn_path);
    }
    return 0;
}

static void
lookup_double(MMDB_lookup_result_s *r, json_t *out, const char *dst, const char *a, const char *b)
{
    const char *path[3] = { a, b, NULL };
    MMDB_entry_data_s e;
    if (MMDB_aget_value(&r->entry, &e, path) == MMDB_SUCCESS && e.has_data
        && e.type == MMDB_DATA_TYPE_DOUBLE) {
        json_object_set_new(out, dst, json_real(e.double_value));
    }
}

static void
lookup_uint(MMDB_lookup_result_s *r, json_t *out, const char *dst, const char *a)
{
    const char *path[2] = { a, NULL };
    MMDB_entry_data_s e;
    if (MMDB_aget_value(&r->entry, &e, path) == MMDB_SUCCESS && e.has_data) {
        if (e.type == MMDB_DATA_TYPE_UINT32)
            json_object_set_new(out, dst, json_integer(e.uint32));
        else if (e.type == MMDB_DATA_TYPE_UINT16)
            json_object_set_new(out, dst, json_integer(e.uint16));
    }
}

/*
 * Parse an IP that may be a redacted CIDR form ("87.98.162.0/24",
 * "2001:16a2:7199::/48") or a plain IPv4/IPv6 string. Strips the
 * "/N" suffix if present, tries AF_INET first, falls back to AF_INET6.
 * Returns 1 on success and fills *ss + *ss_len, 0 on failure.
 *
 * Public via http_ws.h — also used by the deny refresh tick in
 * cmd_daemon.c.
 */
int
parse_ip_lenient(const char *ip, struct sockaddr_storage *ss, socklen_t *ss_len)
{
    if (!ip || !*ip) return 0;
    char buf[64];
    size_t n = strnlen(ip, sizeof(buf));
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, ip, n + 1);
    char *slash = strchr(buf, '/');
    if (slash) *slash = 0;

    memset(ss, 0, sizeof(*ss));
    struct sockaddr_in *sa4  = (struct sockaddr_in  *)ss;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ss;
    if (inet_pton(AF_INET, buf, &sa4->sin_addr) == 1) {
        sa4->sin_family = AF_INET;
        *ss_len = sizeof(*sa4);
        return 1;
    }
    if (inet_pton(AF_INET6, buf, &sa6->sin6_addr) == 1) {
        sa6->sin6_family = AF_INET6;
        *ss_len = sizeof(*sa6);
        return 1;
    }
    return 0;
}

static json_t *
geoip_lookup(const char *ip)
{
    if (!g_city_ok && !g_asn_ok) return NULL;
    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    if (!parse_ip_lenient(ip, &ss, &ss_len)) return NULL;
    struct sockaddr *sa = (struct sockaddr *)&ss;

    json_t *o = json_object();
    int gai = 0;
    if (g_city_ok) {
        MMDB_lookup_result_s r = MMDB_lookup_sockaddr(&g_city, sa, &gai);
        if (r.found_entry) {
            const char *p_iso[]  = { "country", "iso_code", NULL };
            const char *p_city[] = { "city", "names", "en", NULL };
            MMDB_entry_data_s e;
            if (MMDB_aget_value(&r.entry, &e, p_iso) == MMDB_SUCCESS && e.has_data
                && e.type == MMDB_DATA_TYPE_UTF8_STRING) {
                char buf[8] = {0};
                size_t l = e.data_size < 7 ? e.data_size : 7;
                memcpy(buf, e.utf8_string, l);
                json_object_set_new(o, "country", json_string(buf));
            }
            if (MMDB_aget_value(&r.entry, &e, p_city) == MMDB_SUCCESS && e.has_data
                && e.type == MMDB_DATA_TYPE_UTF8_STRING) {
                char buf[128] = {0};
                size_t l = e.data_size < sizeof(buf) - 1 ? e.data_size : sizeof(buf) - 1;
                memcpy(buf, e.utf8_string, l);
                json_object_set_new(o, "city", json_string(buf));
            }
            lookup_double(&r, o, "lat", "location", "latitude");
            lookup_double(&r, o, "lon", "location", "longitude");
        }
    }
    if (g_asn_ok) {
        MMDB_lookup_result_s r = MMDB_lookup_sockaddr(&g_asn, sa, &gai);
        if (r.found_entry) {
            lookup_uint(&r, o, "asn", "autonomous_system_number");
            MMDB_entry_data_s e;
            const char *p_org[] = { "autonomous_system_organization", NULL };
            if (MMDB_aget_value(&r.entry, &e, p_org) == MMDB_SUCCESS && e.has_data
                && e.type == MMDB_DATA_TYPE_UTF8_STRING) {
                char buf[256] = {0};
                size_t l = e.data_size < sizeof(buf) - 1 ? e.data_size : sizeof(buf) - 1;
                memcpy(buf, e.utf8_string, l);
                json_object_set_new(o, "asn_org", json_string(buf));
            }
        }
    }
    if (!json_object_size(o)) { json_decref(o); return NULL; }
    return o;
}

/* Small open-addressed table: ISO2 → count. We don't expect > 300 countries. */
#define COUNTRY_TABLE_SZ 512
struct country_bucket { char iso[3]; int64_t count; };

static int
aggregate_country_cb(const char *ip, void *closure)
{
    struct country_bucket *tbl = closure;
    if (!g_city_ok) return 0;
    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    if (!parse_ip_lenient(ip, &ss, &ss_len)) return 0;
    int gai = 0;
    MMDB_lookup_result_s r =
        MMDB_lookup_sockaddr(&g_city, (struct sockaddr *)&ss, &gai);
    if (!r.found_entry) return 0;
    MMDB_entry_data_s e;
    const char *p_iso[] = { "country", "iso_code", NULL };
    if (MMDB_aget_value(&r.entry, &e, p_iso) != MMDB_SUCCESS
        || !e.has_data || e.type != MMDB_DATA_TYPE_UTF8_STRING) return 0;
    char iso[3] = { 0 };
    size_t l = e.data_size < 2 ? e.data_size : 2;
    memcpy(iso, e.utf8_string, l);
    iso[l] = 0;

    /* Linear probe — tiny N, near-O(1) in practice. */
    unsigned h = ((unsigned)iso[0] * 31u + (unsigned)iso[1]) % COUNTRY_TABLE_SZ;
    for (unsigned i = 0; i < COUNTRY_TABLE_SZ; i++) {
        unsigned slot = (h + i) % COUNTRY_TABLE_SZ;
        if (tbl[slot].count == 0) {
            memcpy(tbl[slot].iso, iso, 3);
            tbl[slot].count = 1;
            return 0;
        }
        if (memcmp(tbl[slot].iso, iso, 2) == 0) {
            tbl[slot].count++;
            return 0;
        }
    }
    return 0;
}

static char *
country_stats_json(int limit)
{
    if (!g_city_ok) {
        return strdup("{\"clients\":[],\"total\":0,\"known\":0,\"unknown\":0,"
                      "\"note\":\"no geoip city db loaded\"}");
    }
    if (limit <= 0 || limit > 500) limit = 50;
    struct country_bucket *tbl = calloc(COUNTRY_TABLE_SZ, sizeof(*tbl));
    if (!tbl) return NULL;
    db_foreach_peer_ip(aggregate_country_cb, tbl);

    /* Collect non-empty buckets into an array and sort desc by count. */
    struct country_bucket tmp[COUNTRY_TABLE_SZ];
    int n = 0;
    for (unsigned i = 0; i < COUNTRY_TABLE_SZ; i++) {
        if (tbl[i].count > 0) tmp[n++] = tbl[i];
    }
    free(tbl);
    /* simple insertion sort is fine for n<300 */
    for (int i = 1; i < n; i++) {
        struct country_bucket v = tmp[i];
        int j = i - 1;
        while (j >= 0 && tmp[j].count < v.count) { tmp[j+1] = tmp[j]; j--; }
        tmp[j+1] = v;
    }

    int64_t known = 0;
    for (int i = 0; i < n; i++) known += tmp[i].count;
    int64_t total = db_count_peers();

    json_t *arr = json_array();
    int cap = n < limit ? n : limit;
    for (int i = 0; i < cap; i++) {
        json_t *o = json_object();
        json_object_set_new(o, "iso",   json_string(tmp[i].iso));
        json_object_set_new(o, "count", json_integer(tmp[i].count));
        json_array_append_new(arr, o);
    }
    json_t *env = json_object();
    json_object_set_new(env, "total",     json_integer(total));
    json_object_set_new(env, "known",     json_integer(known));
    json_object_set_new(env, "unknown",   json_integer(total - known));
    json_object_set_new(env, "countries", arr);
    char *js = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    return js;
}

/* ============================================================
 * Crawler / monitor / honeypot classifier — JSON adaptor.
 *
 * The scoring core lives in classifier.c (struct peer_signals →
 * struct classify_result) so the daemon-side deny refresh tick in
 * cmd_daemon.c can call the same logic directly. This function is
 * just the bridge from the per-peer json_t row to that core, plus
 * the reputation lookups that are too JSON-shaped for the core API.
 *
 * The legacy `likely_crawler: 0|1` field is preserved (= score >= 1)
 * so the graph view and any external scrapers keep working.
 * ============================================================ */

/* Mutates row: adds crawler_score / crawler_class / crawler_signals /
 * crawler_reason / likely_crawler / reputation. */
static void
classify_peer(json_t *row, json_t *geo)
{
    /* Pull raw fields off the row + geo into a peer_signals. */
    struct peer_signals sig = {0};
    sig.as_src       = json_integer_value(json_object_get(row, "as_src"));
    sig.as_dst       = json_integer_value(json_object_get(row, "as_dst"));
    sig.same_ip      = json_integer_value(json_object_get(row, "same_ip"));
    sig.queries_in   = json_integer_value(json_object_get(row, "queries_in"));
    sig.queries_out  = json_integer_value(json_object_get(row, "queries_out"));
    json_t *ro_v     = json_object_get(row, "ro");
    json_t *b42_v    = json_object_get(row, "bep42_ok");
    json_t *v_str    = json_object_get(row, "v_string");
    sig.ro           = json_is_integer(ro_v)  ? (int)json_integer_value(ro_v)  : -1;
    sig.bep42_ok     = json_is_integer(b42_v) ? (int)json_integer_value(b42_v) : -1;
    sig.has_v_string = (v_str && !json_is_null(v_str)) ? 1 : 0;
    sig.asn_org      = geo ? json_string_value(json_object_get(geo, "asn_org")) : NULL;

    /* Reputation: do the lookups once and emit the JSON `reputation`
     * object. Pass labels to the scoring core via peer_signals so it
     * applies the same rules without re-running the lookups. */
    json_t *rep_obj = NULL;
    const char *ip_str = json_string_value(json_object_get(row, "ip"));
    if (ip_str && *ip_str) {
        struct sockaddr_storage ss;
        socklen_t               ss_len = 0;
        const char             *rs = NULL, *rl = NULL;
        if (parse_ip_lenient(ip_str, &ss, &ss_len)
            && reputation_lookup((struct sockaddr *)&ss, &rs, &rl)
            && rs && rl) {
            rep_obj = json_object();
            json_t *e = json_object();
            json_object_set_new(e, "label", json_string(rl));
            json_object_set_new(rep_obj, rs, e);
            sig.rep_source = rs;
            sig.rep_label  = rl;
        }
        char *gn_json = db_select_reputation_json(ip_str);
        if (gn_json) {
            json_error_t je;
            json_t *gn = json_loads(gn_json, 0, &je);
            free(gn_json);
            if (gn && json_is_object(gn)) {
                const char *src;
                json_t     *entry;
                json_object_foreach(gn, src, entry) {
                    if (!rep_obj) rep_obj = json_object();
                    if (!json_object_get(rep_obj, src)) {
                        json_object_set(rep_obj, src, entry);
                    }
                    if (strcmp(src, "greynoise") == 0) {
                        const char *lbl = json_string_value(
                                              json_object_get(entry, "label"));
                        if (lbl && strncmp(lbl, "malicious", 9) == 0)
                            sig.gn_malicious = 1;
                        else if (lbl && strncmp(lbl, "benign", 6) == 0)
                            sig.gn_benign = 1;
                    }
                }
                json_decref(gn);
            } else if (gn) json_decref(gn);
        }
    }
    if (rep_obj) json_object_set_new(row, "reputation", rep_obj);

    /* Scoring + classification — single source of truth in classifier.c. */
    struct classify_result res;
    classify_compute(&sig, &res);

    /* Project result into the JSON row. */
    json_t *signals_arr = json_array();
    for (int i = 0; i < res.n_signals; i++) {
        json_array_append_new(signals_arr, json_string(res.signals[i]));
    }
    json_object_set_new(row, "crawler_score",   json_integer(res.score));
    json_object_set_new(row, "crawler_class",   json_string(res.cls));
    json_object_set_new(row, "crawler_signals", signals_arr);
    json_object_set_new(row, "crawler_reason",  json_string(res.reason));
    /* Legacy single-bit field — kept for graph view + external scrapers. */
    json_object_set_new(row, "likely_crawler",
                        json_integer(res.score >= 1 ? 1 : 0));
}

/* Wrap a JSON array of peer rows with geoip annotations + classifier output. */
static char *
peers_with_geoip(int limit, const char *order)
{
    char *plain = db_select_peers_json(limit, order);
    if (!plain) return NULL;
    json_error_t err;
    json_t *arr = json_loads(plain, 0, &err);
    free(plain);
    if (!arr || !json_is_array(arr)) { if (arr) json_decref(arr); return NULL; }
    size_t i;
    json_t *row;
    json_array_foreach(arr, i, row) {
        const char *ip = json_string_value(json_object_get(row, "ip"));
        json_t *geo = ip ? geoip_lookup(ip) : NULL;
        if (geo) json_object_set_new(row, "geo", geo);
        classify_peer(row, geo);
    }
    char *out = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    return out;
}

/* ============================================================
 * WebSocket session + broadcast
 * ============================================================ */

#define WS_RING_SLOTS 64    /* per-client ring for queued outbound messages */
#define WS_MAX_MSG    (16 * 1024)

struct ws_msg {
    unsigned char *buf;     /* LWS_PRE prepended */
    size_t         len;     /* payload len (excluding LWS_PRE) */
};

struct ws_session {
    struct ws_msg ring[WS_RING_SLOTS];
    int           head;     /* write index */
    int           tail;     /* read index */
    int           count;
};

static struct ws_session *g_sessions[64];
static struct lws       *g_sessions_wsi[64];
static int               g_session_count = 0;

static void
ws_register(struct ws_session *s, struct lws *wsi)
{
    for (int i = 0; i < (int)(sizeof(g_sessions)/sizeof(g_sessions[0])); i++) {
        if (!g_sessions[i]) {
            g_sessions[i] = s;
            g_sessions_wsi[i] = wsi;
            g_session_count++;
            return;
        }
    }
    /* table full — caller should close */
}

static void
ws_unregister(struct ws_session *s)
{
    for (int i = 0; i < (int)(sizeof(g_sessions)/sizeof(g_sessions[0])); i++) {
        if (g_sessions[i] == s) {
            g_sessions[i] = NULL;
            g_sessions_wsi[i] = NULL;
            g_session_count--;
            break;
        }
    }
    /* drain queue */
    for (int i = 0; i < WS_RING_SLOTS; i++) {
        free(s->ring[i].buf);
        s->ring[i].buf = NULL;
    }
    s->head = s->tail = s->count = 0;
}

static void
ws_enqueue(struct ws_session *s, struct lws *wsi, const char *payload, size_t n)
{
    if (s->count >= WS_RING_SLOTS) {
        /* backpressure: drop oldest */
        free(s->ring[s->tail].buf);
        s->ring[s->tail].buf = NULL;
        s->tail = (s->tail + 1) % WS_RING_SLOTS;
        s->count--;
    }
    unsigned char *buf = malloc(LWS_PRE + n);
    if (!buf) return;
    memcpy(buf + LWS_PRE, payload, n);
    s->ring[s->head].buf = buf;
    s->ring[s->head].len = n;
    s->head = (s->head + 1) % WS_RING_SLOTS;
    s->count++;
    lws_callback_on_writable(wsi);
}

/* ============================================================
 * HTTP router helpers
 * ============================================================ */

/* Query-string helper: find value of ?key=... in uri_args (NUL-separated).
 * libwebsockets gives you raw query string as one buffer. */
static const char *
qs_find(const char *qs, const char *key, char *buf, size_t cap)
{
    if (!qs) return NULL;
    size_t klen = strlen(key);
    const char *p = qs;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *end = strchr(v, '&');
            size_t n = end ? (size_t)(end - v) : strlen(v);
            if (n >= cap) n = cap - 1;
            memcpy(buf, v, n);
            buf[n] = 0;
            return buf;
        }
        const char *next = strchr(p, '&');
        if (!next) break;
        p = next + 1;
    }
    return NULL;
}

/* Pending HTTP body that didn't fit in a single lws_write. Per-wsi state
 * keyed via lws_set_opaque_user_data. The WRITEABLE callback drains it
 * across multiple iterations of the event loop so big JSON responses
 * (graph at limit=10000 can be ~1MB) don't get truncated when the kernel
 * send buffer fills mid-write. */
struct http_body {
    unsigned char *buf;     /* LWS_PRE + body */
    size_t         len;     /* total payload size */
    size_t         off;     /* bytes already accepted by lws */
};

static void
http_body_free(struct http_body *p)
{
    if (!p) return;
    free(p->buf);
    free(p);
}

/* Drain as much of `pending` as the socket will currently accept. Called
 * from the WRITEABLE handler. Returns 1 if the whole body has been sent
 * (caller should finalize the transaction), 0 if more remains, -1 on error.
 *
 * Chunk size matters: passing LWS_WRITE_HTTP_FINAL tells lws "this is the
 * last byte, you can close the transaction" — so only the LAST chunk uses
 * FINAL. Intermediate chunks use plain LWS_WRITE_HTTP. We cap each write
 * at 32 KB so the kernel buffer can drain between chunks instead of one
 * giant write returning a partial count. */
#define HTTP_CHUNK 32768
static int
http_body_drain(struct lws *wsi, struct http_body *p)
{
    while (p->off < p->len) {
        size_t remaining = p->len - p->off;
        size_t this_chunk = remaining > HTTP_CHUNK ? HTTP_CHUNK : remaining;
        enum lws_write_protocol kind =
            (this_chunk == remaining) ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;
        int rc = lws_write(wsi, p->buf + LWS_PRE + p->off,
                           this_chunk, kind);
        if (rc < 0) return -1;
        if (rc == 0) { lws_callback_on_writable(wsi); return 0; }
        p->off += rc;
        if ((size_t)rc < this_chunk) {
            /* Kernel buffer full; ask to be called back when it drains. */
            lws_callback_on_writable(wsi);
            return 0;
        }
    }
    return 1;
}

/* Build headers + start streaming `body`. Allocates the streaming buffer
 * and stashes it as the wsi's opaque user data; returns 0 even when the
 * write isn't fully drained — the WRITEABLE handler finishes it. */
static int
send_buffered_response(struct lws *wsi, int status, const char *ctype,
                       const char *body, size_t len, int with_cors)
{
    unsigned char buf[LWS_PRE + 1024];
    unsigned char *hp = &buf[LWS_PRE];
    unsigned char *end = &buf[sizeof(buf) - 1];

    if (lws_add_http_common_headers(wsi, (unsigned int)status,
                                    ctype, len, &hp, end)) return -1;
    if (with_cors && lws_add_http_header_by_name(wsi,
            (unsigned char *)"Access-Control-Allow-Origin:",
            (unsigned char *)"*", 1, &hp, end)) return -1;
    if (lws_finalize_write_http_header(wsi, &buf[LWS_PRE], &hp, end)) return -1;

    struct http_body *p = calloc(1, sizeof(*p));
    if (!p) return -1;
    p->buf = malloc(LWS_PRE + len);
    if (!p->buf) { free(p); return -1; }
    memcpy(p->buf + LWS_PRE, body, len);
    p->len = len;
    p->off = 0;

    /* Stash on wsi for the WRITEABLE callback. */
    lws_set_opaque_user_data(wsi, p);

    int rc = http_body_drain(wsi, p);
    if (rc < 0) { http_body_free(p); lws_set_opaque_user_data(wsi, NULL); return -1; }
    if (rc == 1) {
        http_body_free(p);
        lws_set_opaque_user_data(wsi, NULL);
        if (lws_http_transaction_completed(wsi)) return -1;
    }
    return 0;
}

static int
send_json_response(struct lws *wsi, const char *body)
{
    if (!body) body = "null";
    return send_buffered_response(wsi, HTTP_STATUS_OK,
                                  "application/json",
                                  body, strlen(body), /*cors=*/1);
}

static int
send_text_response(struct lws *wsi, int status, const char *ctype, const char *body)
{
    return send_buffered_response(wsi, status, ctype,
                                  body, strlen(body), /*cors=*/0);
}

/* ============================================================
 * Built-in index.html (served when --web-static not provided)
 * ============================================================ */

static const char BUILTIN_INDEX[] =
"<!doctype html><html><head><meta charset=\"utf-8\">"
"<title>dht44 crawler</title>"
"<style>body{font:13px monospace;background:#111;color:#ddd;margin:1em}"
"h1{color:#9cf}table{border-collapse:collapse;width:100%}"
"th,td{padding:3px 6px;border-bottom:1px solid #333;text-align:left}"
"th{color:#9cf;position:sticky;top:0;background:#111}"
"tr:hover{background:#1a1a1a}"
".tabs{margin-bottom:1em}.tab{cursor:pointer;padding:5px 10px;display:inline-block;"
"border:1px solid #333}.tab.active{background:#234;border-color:#9cf}"
".stats{font-size:18px;margin:1em 0}"
".stats span{color:#9cf;margin-right:1em}"
".live{color:#4f4}"
".hex{color:#888;font-size:11px}"
".geo{color:#fa0}"
"</style></head><body>"
"<h1>dht44 <span class=live id=live>●</span> <span id=rate style=color:#888></span></h1>"
"<div class=stats id=stats>…</div>"
"<div class=tabs>"
"<span class=tab data-t=peers>peers</span>"
"<span class=tab data-t=queries>queries</span>"
"<span class=tab data-t=infohashes>infohashes</span>"
"<span class=tab data-t=bep44>bep44 items</span>"
"</div><div id=pane></div>"
"<script>\n"
"const $=s=>document.querySelector(s);\n"
"let tab='peers', rows=[];\n"
"function renderStats(s){$('#stats').innerHTML=`<span>peers: ${s.peers}</span>`+\n"
" `<span>queries: ${s.queries}</span>`+\n"
" `<span>infohashes: ${s.infohashes}</span>`+\n"
" `<span>bep44: ${s.bep44_items}</span>`;\n"
" $('#rate').textContent=`${s.queries_per_min||0}/min`;}\n"
"function hex(s,n){return s?s.slice(0,n||20)+'…':'';}\n"
"function cols(){return {\n"
" peers:['ip','port','v_string','ro','rtt_ms','queries_in','queries_out','last_seen','geo'],\n"
" queries:['ts','direction','y','q','ip','port','target','raw_size'],\n"
" infohashes:['hash','source','times_queried','last_seen'],\n"
" bep44:['target','mutable','pk','seq','last_seen']\n"
"}[tab];}\n"
/* esc(): HTML-escape every untrusted string the embedded JS pours into
 * innerHTML below. Peer-controlled fields (v_string, asn_org, etc.)
 * arrive via the /api/peers, /api/queries, /api/bep44 endpoints;
 * without escaping, a malicious DHT peer announcing a hostile v-string
 * would inject script into anyone using this fallback dashboard. JSON
 * values for the dashboard are produced by the daemon itself today,
 * but defense in depth keeps the surface closed even if any /api
 * endpoint gains a relayed field later. */
"function esc(s){return String(s==null?'':s).replace(/[&<>\"\\\\']/g,"
"  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;','\\\\'':'&#39;'}[c]));}\n"
"function cell(r,k){const v=r[k];\n"
" if(v==null)return '';\n"
" if(k==='geo'&&typeof v==='object')return `<span class=geo>${esc(v.country||'')} ${esc(v.city||'')} AS${esc(v.asn||'')}</span>`;\n"
" if(['target','hash','pk','node_id','v_string'].includes(k))return `<span class=hex>${esc(hex(v,16))}</span>`;\n"
" if(k==='last_seen'||k==='first_seen'||k==='ts')return esc(new Date(v*1000).toLocaleTimeString());\n"
" return esc(v);}\n"
"function render(){let c=cols();let h=c.map(k=>`<th>${esc(k)}</th>`).join('');\n"
" let body=rows.slice(0,500).map(r=>'<tr>'+c.map(k=>`<td>${cell(r,k)}</td>`).join('')+'</tr>').join('');\n"
" $('#pane').innerHTML=`<table><thead><tr>${h}</tr></thead><tbody>${body}</tbody></table>`;}\n"
"async function load(){let r=await fetch('/api/'+tab+'?limit=500');rows=await r.json();render();}\n"
"function switchTab(t){tab=t;document.querySelectorAll('.tab').forEach(el=>el.classList.toggle('active',el.dataset.t===t));load();}\n"
"document.querySelectorAll('.tab').forEach(el=>el.onclick=()=>switchTab(el.dataset.t));\n"
"switchTab('peers');\n"
"function connect(){let ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/stream','dht44-stream');\n"
" ws.onopen=()=>{$('#live').style.color='#4f4'};\n"
" ws.onclose=()=>{$('#live').style.color='#f44';setTimeout(connect,2000)};\n"
" ws.onmessage=e=>{try{let m=JSON.parse(e.data);\n"
"   if(m.topic==='stats')renderStats(m.data);\n"
"   else if(m.topic===tab){rows.unshift(m.data);if(rows.length>1000)rows.length=1000;render();}\n"
"  }catch(x){}};}\n"
"connect();\n"
"</script></body></html>\n";

/* ============================================================
 * Live snapshot for SEO crawlers (HTML, not JSON)
 *
 * Returns a small chunk of HTML — top-line counts + top countries +
 * top clients — meant to be inlined into the SPA's <noscript> block
 * via nginx Server-Side Includes (SSI). Crawlers that don't render
 * JavaScript (Bingbot, DuckDuckBot, AI scrapers, archive crawlers)
 * see real numbers instead of an empty SPA shell. JS-enabled clients
 * never see this — the host noscript block hides it.
 * ============================================================ */

#define APPEND_HTML(...) do { \
    int _n = snprintf(buf + len, cap - len, __VA_ARGS__); \
    if (_n < 0) break; \
    if ((size_t)_n >= cap - len) { \
        while ((size_t)_n >= cap - len) cap *= 2; \
        char *_nb = realloc(buf, cap); \
        if (!_nb) break; \
        buf = _nb; \
        _n = snprintf(buf + len, cap - len, __VA_ARGS__); \
    } \
    len += (size_t)_n; \
} while (0)

static char *
snapshot_html(void)
{
    char *stats_json   = db_select_stats_json();
    char *country_json = country_stats_json(15);
    char *client_json  = db_select_client_stats_json(12);

    json_error_t err;
    json_t *jstats   = stats_json   ? json_loads(stats_json,   0, &err) : NULL;
    json_t *jcountry = country_json ? json_loads(country_json, 0, &err) : NULL;
    json_t *jclient  = client_json  ? json_loads(client_json,  0, &err) : NULL;
    free(stats_json); free(country_json); free(client_json);

    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) goto cleanup;

    APPEND_HTML("<section class=\"snapshot\">\n");

    if (jstats) {
        int64_t peers = json_integer_value(json_object_get(jstats, "peers"));
        int64_t v4    = json_integer_value(json_object_get(jstats, "peers_v4"));
        int64_t v6    = json_integer_value(json_object_get(jstats, "peers_v6"));
        int64_t qrs   = json_integer_value(json_object_get(jstats, "queries"));
        int64_t ihs   = json_integer_value(json_object_get(jstats, "infohashes"));
        int64_t qpm   = json_integer_value(json_object_get(jstats, "queries_per_min"));
        int64_t first = json_integer_value(json_object_get(jstats, "db_first_seen"));
        int64_t now   = (int64_t)time(NULL);
        int64_t up    = (first > 0) ? now - first : 0;

        APPEND_HTML("<h3>Live snapshot</h3>\n<dl>\n");
        APPEND_HTML("  <dt>peers</dt><dd>%lld observed (v4 %lld &middot; v6 %lld)</dd>\n",
                    (long long)peers, (long long)v4, (long long)v6);
        APPEND_HTML("  <dt>queries</dt><dd>%lld total &middot; %lld/min</dd>\n",
                    (long long)qrs, (long long)qpm);
        APPEND_HTML("  <dt>infohashes</dt><dd>%lld</dd>\n", (long long)ihs);
        if (up > 0) {
            int dy = (int)(up / 86400);
            int hr = (int)((up % 86400) / 3600);
            int mn = (int)((up % 3600) / 60);
            if (dy)      APPEND_HTML("  <dt>uptime</dt><dd>%dd %dh</dd>\n", dy, hr);
            else if (hr) APPEND_HTML("  <dt>uptime</dt><dd>%dh %dm</dd>\n", hr, mn);
            else         APPEND_HTML("  <dt>uptime</dt><dd>%dm</dd>\n", mn);
        }
        APPEND_HTML("</dl>\n");
    }

    if (jcountry) {
        json_t *arr = json_object_get(jcountry, "countries");
        if (arr && json_is_array(arr) && json_array_size(arr) > 0) {
            APPEND_HTML("<h3>Top peer countries</h3>\n<ul>\n");
            size_t i;
            json_t *o;
            json_array_foreach(arr, i, o) {
                if (i >= 15) break;
                const char *iso = json_string_value(json_object_get(o, "iso"));
                int64_t cnt = json_integer_value(json_object_get(o, "count"));
                if (iso) APPEND_HTML("  <li>%s &middot; %lld</li>\n",
                                     iso, (long long)cnt);
            }
            APPEND_HTML("</ul>\n");
        }
    }

    if (jclient) {
        json_t *arr = json_object_get(jclient, "clients");
        if (arr && json_is_array(arr) && json_array_size(arr) > 0) {
            APPEND_HTML("<h3>Top BitTorrent clients (BEP 20 v-string prefixes)</h3>\n<ul>\n");
            size_t i;
            json_t *o;
            json_array_foreach(arr, i, o) {
                if (i >= 12) break;
                const char *vs = json_string_value(json_object_get(o, "v_string"));
                int64_t cnt = json_integer_value(json_object_get(o, "count"));
                if (vs) APPEND_HTML("  <li><code>%s</code> &middot; %lld</li>\n",
                                    vs, (long long)cnt);
            }
            APPEND_HTML("</ul>\n");
        }
    }

    APPEND_HTML("</section>\n");

cleanup:
    if (jstats)   json_decref(jstats);
    if (jcountry) json_decref(jcountry);
    if (jclient)  json_decref(jclient);
    return buf;
}

#undef APPEND_HTML

/* ============================================================
 * Context + protocols
 * ============================================================ */

static struct lws_context *g_ctx = NULL;
static char                g_static_dir[512]      = "";
/* Canonicalized form of g_static_dir (resolved once at init via realpath).
 * Used in dispatch_http to verify that the resolved path of any served
 * static asset stays inside the configured static dir, even after symlink
 * resolution and `..`-handling. Trailing '/' is appended at init so the
 * containment check is a clean prefix match without partial-name false
 * positives (e.g. "/var/www/dht44.com" vs "/var/www/dht44.com.bak"). */
static char                g_static_dir_real[512] = "";
static size_t              g_static_dir_real_len  = 0;

static int
dispatch_http(struct lws *wsi)
{
    char uri[512];
    int  uri_len = lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);
    if (uri_len <= 0) return lws_return_http_status(wsi, 400, NULL);

    /* libwebsockets gives path + query string in SEPARATE tokens. */
    char qsbuf[512];
    int  qs_len = lws_hdr_copy(wsi, qsbuf, sizeof(qsbuf),
                               WSI_TOKEN_HTTP_URI_ARGS);
    char *qs = qs_len > 0 ? qsbuf : NULL;

    /* Routes */
    if (strcmp(uri, "/") == 0) {
        /* Serve static if configured, else built-in index */
        if (g_static_dir[0]) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/index.html", g_static_dir);
            if (lws_serve_http_file(wsi, path, "text/html", NULL, 0) < 0)
                return -1;
            return 0;
        }
        return send_text_response(wsi, HTTP_STATUS_OK, "text/html; charset=utf-8",
                                  BUILTIN_INDEX);
    }

    /* Static assets from configured dir, e.g. /main.js, /main.css.
     *
     * Defense in depth against path traversal. Three layers:
     *   1. The substring check rejects the canonical form `..` in
     *      the URI (libwebsockets URL-decodes percent-encoding before
     *      handing us WSI_TOKEN_GET_URI, so `%2e%2e` is also caught).
     *   2. realpath() resolves symlinks and `.`/`..` components in the
     *      assembled candidate path.
     *   3. We require the resolved path to fall under the canonicalized
     *      static dir (g_static_dir_real, with trailing '/' so a
     *      partial-prefix overlap with a sibling directory can't leak).
     * Any failure → 404, never partial. */
    if (g_static_dir[0] && uri[0] == '/' && strstr(uri, "..") == NULL) {
        char path[1024];
        snprintf(path, sizeof(path), "%s%s", g_static_dir, uri);
        char resolved[PATH_MAX];
        if (g_static_dir_real_len > 0 && realpath(path, resolved) != NULL
            && strncmp(resolved, g_static_dir_real, g_static_dir_real_len) != 0) {
            /* resolved exists but escaped the static dir → refuse. */
            return lws_return_http_status(wsi, 404, NULL);
        }
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            const char *ct = "application/octet-stream";
            const char *dot = strrchr(uri, '.');
            if (dot) {
                if (strcmp(dot, ".html") == 0) ct = "text/html; charset=utf-8";
                else if (strcmp(dot, ".js")   == 0) ct = "application/javascript";
                else if (strcmp(dot, ".css")  == 0) ct = "text/css";
                else if (strcmp(dot, ".json") == 0) ct = "application/json";
                else if (strcmp(dot, ".svg")  == 0) ct = "image/svg+xml";
                else if (strcmp(dot, ".png")  == 0) ct = "image/png";
                else if (strcmp(dot, ".woff2")== 0) ct = "font/woff2";
            }
            if (lws_serve_http_file(wsi, path, ct, NULL, 0) < 0) return -1;
            return 0;
        }
    }

    char numbuf[32];
    int limit = 500;
    if (qs_find(qs, "limit", numbuf, sizeof(numbuf))) limit = atoi(numbuf);

    if (strcmp(uri, "/api/peers") == 0) {
        char order[32] = "";
        qs_find(qs, "order", order, sizeof(order));
        char *body = peers_with_geoip(limit, order[0] ? order : NULL);
        int rc = send_json_response(wsi, body ? body : "[]");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/queries") == 0) {
        int64_t since = 0;
        if (qs_find(qs, "since", numbuf, sizeof(numbuf))) since = atoll(numbuf);
        char *body = db_select_queries_json(since, limit);
        int rc = send_json_response(wsi, body ? body : "[]");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/infohashes") == 0) {
        char *body = db_select_infohashes_json(limit);
        int rc = send_json_response(wsi, body ? body : "[]");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/bep44") == 0) {
        char *body = db_select_bep44_json(limit);
        int rc = send_json_response(wsi, body ? body : "[]");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/stats") == 0) {
        char *body = db_select_stats_json();
        int rc = send_json_response(wsi, body ? body : "{}");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/client-stats") == 0) {
        char *body = db_select_client_stats_json(limit);
        int rc = send_json_response(wsi, body ? body : "{}");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/infohash-sources") == 0) {
        char *body = db_select_infohash_sources_json();
        int rc = send_json_response(wsi, body ? body : "{}");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/country-stats") == 0) {
        char *body = country_stats_json(limit);
        int rc = send_json_response(wsi, body ? body : "{}");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/graph") == 0) {
        char *body = db_select_graph_json(limit);
        /* Enrich each node with the same geo + classifier the Peers tab gets,
         * so the graph view's color/click/filter UI can use one vocabulary. */
        if (body) {
            json_error_t err;
            json_t *env = json_loads(body, 0, &err);
            free(body);
            body = NULL;
            if (env) {
                json_t *nodes = json_object_get(env, "nodes");
                size_t i; json_t *n;
                json_array_foreach(nodes, i, n) {
                    const char *ip = json_string_value(json_object_get(n, "ip"));
                    json_t *geo = ip ? geoip_lookup(ip) : NULL;
                    if (geo) {
                        /* Mirror the legacy "country" top-level key that the
                         * graph endpoint used to emit, so older frontends keep
                         * working alongside the richer `geo` object. */
                        const char *c = json_string_value(json_object_get(geo, "country"));
                        if (c) json_object_set_new(n, "country", json_string(c));
                        json_object_set_new(n, "geo", geo);
                    }
                    classify_peer(n, geo);
                }
                body = json_dumps(env, JSON_COMPACT);
                json_decref(env);
            }
        }
        int rc = send_json_response(wsi, body ? body : "{\"nodes\":[],\"links\":[]}");
        free(body);
        return rc;
    }
    if (strcmp(uri, "/api/node-id") == 0) {
        const uint8_t *id = dht_wrap_node_id();
        char hex[41];
        if (id) {
            for (int i = 0; i < 20; i++)
                snprintf(&hex[i * 2], 3, "%02x", id[i]);
        } else {
            hex[0] = 0;
        }
        char body[80];
        snprintf(body, sizeof(body), "{\"node_id\":\"%s\"}", hex);
        return send_json_response(wsi, body);
    }
    if (strcmp(uri, "/api/snapshot.html") == 0) {
        char *body = snapshot_html();
        int rc = send_text_response(wsi, HTTP_STATUS_OK,
                                    "text/html; charset=utf-8",
                                    body ? body : "<!-- snapshot unavailable -->");
        free(body);
        return rc;
    }

    return lws_return_http_status(wsi, 404, NULL);
}

static int
http_callback(struct lws *wsi, enum lws_callback_reasons reason,
              void *user, void *in, size_t len)
{
    (void)user; (void)in; (void)len;
    if (reason == LWS_CALLBACK_HTTP) {
        if (dispatch_http(wsi) < 0) return -1;
        return 0;
    }
    if (reason == LWS_CALLBACK_HTTP_WRITEABLE) {
        struct http_body *p = (struct http_body *)lws_get_opaque_user_data(wsi);
        if (!p) return 0;     /* nothing to do — must be a static-file write */
        int rc = http_body_drain(wsi, p);
        if (rc < 0) {
            http_body_free(p);
            lws_set_opaque_user_data(wsi, NULL);
            return -1;
        }
        if (rc == 1) {
            http_body_free(p);
            lws_set_opaque_user_data(wsi, NULL);
            if (lws_http_transaction_completed(wsi)) return -1;
        }
        return 0;
    }
    if (reason == LWS_CALLBACK_CLOSED_HTTP) {
        struct http_body *p = (struct http_body *)lws_get_opaque_user_data(wsi);
        if (p) {
            http_body_free(p);
            lws_set_opaque_user_data(wsi, NULL);
        }
        /* fall through to dummy for any other cleanup */
    }
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
ws_callback(struct lws *wsi, enum lws_callback_reasons reason,
            void *user, void *in, size_t len)
{
    struct ws_session *s = user;
    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        memset(s, 0, sizeof(*s));
        ws_register(s, wsi);
        fprintf(stderr, TAG "ws connect (%d clients)\n", g_session_count);
        break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
        if (s->count > 0) {
            struct ws_msg *m = &s->ring[s->tail];
            int n = lws_write(wsi, m->buf + LWS_PRE, m->len, LWS_WRITE_TEXT);
            free(m->buf);
            m->buf = NULL;
            s->tail = (s->tail + 1) % WS_RING_SLOTS;
            s->count--;
            if (n < 0) return -1;
            if (s->count > 0) lws_callback_on_writable(wsi);
        }
        break;

    case LWS_CALLBACK_RECEIVE:
        /* ignore inbound — client has nothing to say that we act on */
        (void)in; (void)len;
        break;

    case LWS_CALLBACK_CLOSED:
        ws_unregister(s);
        fprintf(stderr, TAG "ws close (%d clients)\n", g_session_count);
        break;

    default:
        break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "http",         http_callback, 0,                         0, 0, NULL, 0 },
    { "dht44-stream", ws_callback,   sizeof(struct ws_session), WS_MAX_MSG, 0, NULL, 0 },
    LWS_PROTOCOL_LIST_TERM
};

/* ============================================================
 * Public API
 * ============================================================ */

int
http_ws_init(uint16_t port, const char *static_dir)
{
    if (g_ctx) return 0;
    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = port;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;
    info.iface = "lo";     /* default: localhost only */
    /* Bigger per-thread service buffer so big HTTP responses don't get
     * implicitly capped at lws's default ~1MB internal ceiling. */
    info.pt_serv_buf_size = 4 * 1024 * 1024;

    /* Allow binding to any interface by setting iface=NULL via env var, for users
     * who want to expose the dashboard on LAN at their own risk. */
    if (getenv("DHT44_WEB_BIND_ALL")) info.iface = NULL;

    g_ctx = lws_create_context(&info);
    if (!g_ctx) {
        fprintf(stderr, TAG "lws_create_context failed on port %u\n", port);
        return -1;
    }
    if (static_dir && *static_dir) {
        snprintf(g_static_dir, sizeof(g_static_dir), "%s", static_dir);
        /* Canonicalize once at init so we don't pay realpath() cost per
         * request and so the prefix-match below is unambiguous. The
         * trailing '/' guards against directory-name partial overlap. */
        char canon[PATH_MAX];
        if (realpath(static_dir, canon) != NULL) {
            int n = snprintf(g_static_dir_real, sizeof(g_static_dir_real),
                             "%s/", canon);
            if (n > 0 && (size_t)n < sizeof(g_static_dir_real)) {
                g_static_dir_real_len = (size_t)n;
            } else {
                fprintf(stderr, TAG "warn: static dir path too long for canonicalization\n");
                g_static_dir_real[0] = 0;
            }
        } else {
            fprintf(stderr, TAG "warn: realpath(%s) failed: %s\n",
                    static_dir, strerror(errno));
        }
    }
    fprintf(stderr, TAG "listening on %s:%u%s\n",
            info.iface ? info.iface : "*", port,
            static_dir && *static_dir ? " (static dir on)" : " (built-in UI)");
    return 0;
}

void
http_ws_uninit(void)
{
    if (g_ctx) { lws_context_destroy(g_ctx); g_ctx = NULL; }
    if (g_city_ok) { MMDB_close(&g_city); g_city_ok = 0; }
    if (g_asn_ok)  { MMDB_close(&g_asn);  g_asn_ok = 0;  }
}

void
http_ws_service(int timeout_ms)
{
    if (g_ctx) lws_service(g_ctx, timeout_ms);
}

void
http_ws_publish(const char *topic, const char *json_str)
{
    (void)topic;   /* topic already embedded in JSON envelope by observe */
    if (!g_ctx || !json_str) return;
    size_t n = strlen(json_str);
    if (n > WS_MAX_MSG) return;
    for (int i = 0; i < (int)(sizeof(g_sessions)/sizeof(g_sessions[0])); i++) {
        if (g_sessions[i] && g_sessions_wsi[i]) {
            ws_enqueue(g_sessions[i], g_sessions_wsi[i], json_str, n);
        }
    }
}

void
http_ws_heartbeat(void)
{
    if (!g_ctx || g_session_count == 0) return;
    char *stats = db_select_stats_json();
    if (!stats) return;
    /* Wrap in envelope */
    char *env = NULL;
    if (asprintf(&env, "{\"topic\":\"stats\",\"data\":%s}", stats) < 0) env = NULL;
    free(stats);
    if (env) { http_ws_publish("stats", env); free(env); }
}
