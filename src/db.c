#define _POSIX_C_SOURCE 200809L
#include "db.h"

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *g_db            = NULL;
static int      g_tx_open       = 0;
static time_t   g_tx_opened_at  = 0;

static sqlite3_stmt *g_ins_peer       = NULL;
static sqlite3_stmt *g_upd_peer_count = NULL;
static sqlite3_stmt *g_ins_query      = NULL;
static sqlite3_stmt *g_ins_infohash   = NULL;
static sqlite3_stmt *g_ins_bep44      = NULL;
static sqlite3_stmt *g_ins_edge       = NULL;

#define TAG "[dht44:db] "

static void
log_err(const char *where)
{
    fprintf(stderr, TAG "%s: %s\n", where,
            g_db ? sqlite3_errmsg(g_db) : "no db");
}

static int
exec_noret(const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, TAG "exec: %s (sql: %s)\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int
prepare_all(void)
{
    static const char *S_INS_PEER =
        "INSERT INTO peers"
        " (ip,port,node_id,v_string,ro,bep42_ok,first_seen,last_seen,"
        "  rtt_ms_ewma,queries_in,queries_out)"
        " VALUES(?,?,?,?,?,?,?,?,?,0,0)"
        " ON CONFLICT(ip,port) DO UPDATE SET"
        "   node_id  = COALESCE(excluded.node_id,  node_id),"
        "   v_string = COALESCE(excluded.v_string, v_string),"
        "   ro       = COALESCE(excluded.ro,       ro),"
        "   bep42_ok = COALESCE(excluded.bep42_ok, bep42_ok),"
        "   last_seen = excluded.last_seen,"
        "   rtt_ms_ewma = CASE WHEN excluded.rtt_ms_ewma IS NULL THEN rtt_ms_ewma"
        "                 WHEN rtt_ms_ewma IS NULL THEN excluded.rtt_ms_ewma"
        "                 ELSE (rtt_ms_ewma*3 + excluded.rtt_ms_ewma)/4 END";
    static const char *S_UPD_PEER_COUNT =
        "UPDATE peers SET"
        "  queries_in  = queries_in  + CASE WHEN ?='i' THEN 1 ELSE 0 END,"
        "  queries_out = queries_out + CASE WHEN ?='o' THEN 1 ELSE 0 END,"
        "  last_seen   = ?"
        " WHERE ip=? AND port=?";
    static const char *S_INS_QUERY =
        "INSERT INTO queries(ts,ip,port,direction,y,q,target,raw_size)"
        " VALUES(?,?,?,?,?,?,?,?)";
    static const char *S_INS_INFOHASH =
        "INSERT INTO infohashes(hash,first_seen,last_seen,times_queried,source)"
        " VALUES(?,?,?,1,?)"
        " ON CONFLICT(hash) DO UPDATE SET"
        "   last_seen     = excluded.last_seen,"
        "   times_queried = times_queried + 1,"
        "   source        = COALESCE(source, excluded.source)";
    static const char *S_INS_BEP44 =
        "INSERT INTO bep44_items"
        " (target,mutable,pk,salt,seq,sig,v,first_seen,last_seen)"
        " VALUES(?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(target) DO UPDATE SET"
        "   mutable   = excluded.mutable,"
        "   pk        = COALESCE(excluded.pk, pk),"
        "   salt      = COALESCE(excluded.salt, salt),"
        "   seq       = excluded.seq,"
        "   sig       = COALESCE(excluded.sig, sig),"
        "   v         = excluded.v,"
        "   last_seen = excluded.last_seen";
    static const char *S_INS_EDGE =
        "INSERT INTO edges(src_ip,src_port,dst_ip,dst_port,last_seen)"
        " VALUES(?,?,?,?,?)"
        " ON CONFLICT(src_ip,src_port,dst_ip,dst_port) DO UPDATE SET"
        "   last_seen = excluded.last_seen";

    struct { sqlite3_stmt **slot; const char *sql; } items[] = {
        { &g_ins_peer,       S_INS_PEER },
        { &g_upd_peer_count, S_UPD_PEER_COUNT },
        { &g_ins_query,      S_INS_QUERY },
        { &g_ins_infohash,   S_INS_INFOHASH },
        { &g_ins_bep44,      S_INS_BEP44 },
        { &g_ins_edge,       S_INS_EDGE },
    };
    for (size_t i = 0; i < sizeof(items)/sizeof(items[0]); i++) {
        if (sqlite3_prepare_v2(g_db, items[i].sql, -1, items[i].slot, NULL)
                != SQLITE_OK) {
            log_err("prepare");
            return -1;
        }
    }
    return 0;
}

int
db_open(const char *path)
{
    if (g_db) return 0;
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        log_err("open");
        return -1;
    }
    if (exec_noret("PRAGMA journal_mode = WAL") < 0) return -1;
    if (exec_noret("PRAGMA synchronous  = NORMAL") < 0) return -1;
    if (exec_noret("PRAGMA temp_store   = MEMORY") < 0) return -1;
    if (exec_noret("PRAGMA busy_timeout = 2000") < 0) return -1;

    static const char *SCHEMA =
        "CREATE TABLE IF NOT EXISTS peers ("
        "  ip TEXT NOT NULL, port INTEGER NOT NULL,"
        "  node_id BLOB, v_string BLOB,"
        "  ro INTEGER, bep42_ok INTEGER,"
        "  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,"
        "  rtt_ms_ewma INTEGER,"
        "  queries_in  INTEGER NOT NULL DEFAULT 0,"
        "  queries_out INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(ip,port));"
        "CREATE INDEX IF NOT EXISTS peers_last ON peers(last_seen);"
        "CREATE TABLE IF NOT EXISTS queries ("
        "  ts INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL,"
        "  direction TEXT NOT NULL, y TEXT NOT NULL, q TEXT,"
        "  target BLOB, raw_size INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS queries_ts     ON queries(ts);"
        "CREATE INDEX IF NOT EXISTS queries_target ON queries(target);"
        "CREATE TABLE IF NOT EXISTS infohashes ("
        "  hash BLOB PRIMARY KEY, first_seen INTEGER NOT NULL,"
        "  last_seen INTEGER NOT NULL,"
        "  times_queried INTEGER NOT NULL DEFAULT 1, source TEXT);"
        "CREATE TABLE IF NOT EXISTS bep44_items ("
        "  target BLOB PRIMARY KEY, mutable INTEGER NOT NULL,"
        "  pk BLOB, salt BLOB, seq INTEGER, sig BLOB, v BLOB NOT NULL,"
        "  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS edges ("
        "  src_ip TEXT NOT NULL, src_port INTEGER NOT NULL,"
        "  dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL,"
        "  last_seen INTEGER NOT NULL,"
        "  PRIMARY KEY(src_ip,src_port,dst_ip,dst_port));"
        "CREATE INDEX IF NOT EXISTS edges_src ON edges(src_ip, src_port);"
        "CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst_ip, dst_port);";
    if (exec_noret(SCHEMA) < 0) return -1;
    if (prepare_all() < 0) return -1;
    fprintf(stderr, TAG "opened %s\n", path);
    return 0;
}

void
db_close(void)
{
    if (!g_db) return;
    db_flush();
    sqlite3_finalize(g_ins_peer);        g_ins_peer = NULL;
    sqlite3_finalize(g_upd_peer_count);  g_upd_peer_count = NULL;
    sqlite3_finalize(g_ins_query);       g_ins_query = NULL;
    sqlite3_finalize(g_ins_infohash);    g_ins_infohash = NULL;
    sqlite3_finalize(g_ins_bep44);       g_ins_bep44 = NULL;
    sqlite3_finalize(g_ins_edge);        g_ins_edge = NULL;
    sqlite3_close(g_db);                 g_db = NULL;
}

static void
tx_begin_if_needed(void)
{
    if (!g_db || g_tx_open) return;
    if (exec_noret("BEGIN") == 0) {
        g_tx_open = 1;
        g_tx_opened_at = time(NULL);
    }
}

void
db_flush(void)
{
    if (!g_db || !g_tx_open) return;
    if (exec_noret("COMMIT") < 0) {
        exec_noret("ROLLBACK");
    }
    g_tx_open = 0;
}

/* ============================================================
 * Writes
 * ============================================================ */

static void
peer_key(const struct sockaddr_in *p, char *ip_out, size_t ip_cap, int *port_out)
{
    inet_ntop(AF_INET, &p->sin_addr, ip_out, ip_cap);
    *port_out = ntohs(p->sin_port);
}

void
db_upsert_peer(const struct sockaddr_in *peer,
               const uint8_t node_id[BEP44_NODE_ID_LEN], int has_node_id,
               const uint8_t *v_string, size_t v_len,
               int ro, int bep42_ok, int rtt_ms, char direction)
{
    if (!g_db || !peer) return;
    tx_begin_if_needed();

    char ip[INET_ADDRSTRLEN];
    int  port;
    peer_key(peer, ip, sizeof(ip), &port);
    int64_t now = time(NULL);

    sqlite3_stmt *s = g_ins_peer;
    sqlite3_reset(s);
    sqlite3_bind_text  (s, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int   (s, 2, port);
    if (has_node_id) sqlite3_bind_blob(s, 3, node_id, BEP44_NODE_ID_LEN, SQLITE_TRANSIENT);
    else             sqlite3_bind_null(s, 3);
    if (v_string && v_len) sqlite3_bind_blob(s, 4, v_string, (int)v_len, SQLITE_TRANSIENT);
    else                   sqlite3_bind_null(s, 4);
    if (ro >= 0)        sqlite3_bind_int(s, 5, ro ? 1 : 0);
    else                sqlite3_bind_null(s, 5);
    if (bep42_ok >= 0)  sqlite3_bind_int(s, 6, bep42_ok ? 1 : 0);
    else                sqlite3_bind_null(s, 6);
    sqlite3_bind_int64 (s, 7, now);           /* first_seen */
    sqlite3_bind_int64 (s, 8, now);           /* last_seen  */
    if (rtt_ms >= 0)    sqlite3_bind_int(s, 9, rtt_ms);
    else                sqlite3_bind_null(s, 9);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("upsert peer");

    if (direction == 'i' || direction == 'o') {
        sqlite3_stmt *u = g_upd_peer_count;
        sqlite3_reset(u);
        char d[2] = { direction, 0 };
        sqlite3_bind_text (u, 1, d, 1, SQLITE_TRANSIENT);
        sqlite3_bind_text (u, 2, d, 1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(u, 3, now);
        sqlite3_bind_text (u, 4, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (u, 5, port);
        if (sqlite3_step(u) != SQLITE_DONE) log_err("bump peer count");
    }
}

void
db_insert_query(int64_t ts,
                const struct sockaddr_in *peer,
                const char *direction,
                const char *y,
                const char *q,
                const uint8_t *target,
                int raw_size)
{
    if (!g_db || !peer) return;
    tx_begin_if_needed();

    char ip[INET_ADDRSTRLEN];
    int  port;
    peer_key(peer, ip, sizeof(ip), &port);

    sqlite3_stmt *s = g_ins_query;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, ts);
    sqlite3_bind_text (s, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 3, port);
    sqlite3_bind_text (s, 4, direction, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s, 5, y, -1, SQLITE_TRANSIENT);
    if (q) sqlite3_bind_text(s, 6, q, -1, SQLITE_TRANSIENT);
    else   sqlite3_bind_null(s, 6);
    if (target) sqlite3_bind_blob(s, 7, target, BEP44_TARGET_LEN, SQLITE_TRANSIENT);
    else        sqlite3_bind_null(s, 7);
    sqlite3_bind_int (s, 8, raw_size);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("insert query");
}

void
db_upsert_infohash(const uint8_t hash[BEP44_TARGET_LEN], const char *source)
{
    if (!g_db || !hash) return;
    tx_begin_if_needed();
    int64_t now = time(NULL);
    sqlite3_stmt *s = g_ins_infohash;
    sqlite3_reset(s);
    sqlite3_bind_blob (s, 1, hash, BEP44_TARGET_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 2, now);
    sqlite3_bind_int64(s, 3, now);
    if (source) sqlite3_bind_text(s, 4, source, -1, SQLITE_TRANSIENT);
    else        sqlite3_bind_null(s, 4);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("upsert infohash");
}

void
db_upsert_bep44_item(const uint8_t target[BEP44_TARGET_LEN],
                     int mutable_,
                     const uint8_t *pk, size_t pk_len,
                     const uint8_t *salt, size_t salt_len,
                     int64_t seq,
                     const uint8_t *sig, size_t sig_len,
                     const uint8_t *v, size_t v_len)
{
    if (!g_db || !target || !v || !v_len) return;
    tx_begin_if_needed();
    int64_t now = time(NULL);
    sqlite3_stmt *s = g_ins_bep44;
    sqlite3_reset(s);
    sqlite3_bind_blob (s, 1, target, BEP44_TARGET_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 2, mutable_ ? 1 : 0);
    if (pk && pk_len)     sqlite3_bind_blob(s, 3, pk, (int)pk_len, SQLITE_TRANSIENT);
    else                  sqlite3_bind_null(s, 3);
    if (salt && salt_len) sqlite3_bind_blob(s, 4, salt, (int)salt_len, SQLITE_TRANSIENT);
    else                  sqlite3_bind_null(s, 4);
    sqlite3_bind_int64(s, 5, seq);
    if (sig && sig_len)   sqlite3_bind_blob(s, 6, sig, (int)sig_len, SQLITE_TRANSIENT);
    else                  sqlite3_bind_null(s, 6);
    sqlite3_bind_blob (s, 7, v, (int)v_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 8, now);
    sqlite3_bind_int64(s, 9, now);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("upsert bep44 item");
}

/* ============================================================
 * Reads (JSON output)
 * ============================================================ */

static void
json_set_blob_hex(json_t *obj, const char *key, const void *bytes, int len)
{
    if (!bytes || len <= 0) { json_object_set_new(obj, key, json_null()); return; }
    const uint8_t *b = bytes;
    char *hex = malloc((size_t)len * 2 + 1);
    if (!hex) { json_object_set_new(obj, key, json_null()); return; }
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex[i*2]   = H[b[i] >> 4];
        hex[i*2+1] = H[b[i] & 0xf];
    }
    hex[len*2] = 0;
    json_object_set_new(obj, key, json_string(hex));
    free(hex);
}

static char *
run_select(const char *sql,
           void (*bind)(sqlite3_stmt *s, void *ctx),
           json_t *(*row)(sqlite3_stmt *s, void *ctx),
           void *ctx)
{
    if (!g_db) return NULL;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) {
        log_err("prepare select"); return NULL;
    }
    if (bind) bind(s, ctx);
    json_t *arr = json_array();
    while (sqlite3_step(s) == SQLITE_ROW) {
        json_t *r = row(s, ctx);
        if (r) json_array_append_new(arr, r);
    }
    sqlite3_finalize(s);
    char *js = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    return js;
}

static json_t *
row_peer(sqlite3_stmt *s, void *ctx)
{
    (void)ctx;
    json_t *o = json_object();
    json_object_set_new(o, "ip",   json_string((const char *)sqlite3_column_text(s, 0)));
    json_object_set_new(o, "port", json_integer(sqlite3_column_int(s, 1)));
    json_set_blob_hex(o, "node_id",  sqlite3_column_blob(s, 2), sqlite3_column_bytes(s, 2));
    json_set_blob_hex(o, "v_string", sqlite3_column_blob(s, 3), sqlite3_column_bytes(s, 3));
    json_object_set_new(o, "ro",         sqlite3_column_type(s, 4) == SQLITE_NULL ? json_null() : json_integer(sqlite3_column_int(s, 4)));
    json_object_set_new(o, "bep42_ok",   sqlite3_column_type(s, 5) == SQLITE_NULL ? json_null() : json_integer(sqlite3_column_int(s, 5)));
    json_object_set_new(o, "first_seen", json_integer(sqlite3_column_int64(s, 6)));
    json_object_set_new(o, "last_seen",  json_integer(sqlite3_column_int64(s, 7)));
    json_object_set_new(o, "rtt_ms",     sqlite3_column_type(s, 8) == SQLITE_NULL ? json_null() : json_integer(sqlite3_column_int(s, 8)));
    json_object_set_new(o, "queries_in",  json_integer(sqlite3_column_int64(s, 9)));
    json_object_set_new(o, "queries_out", json_integer(sqlite3_column_int64(s, 10)));
    /* Edge-count extras (columns 11-13) only present when the query JOINed
     * against edges. Extract defensively so row_peer remains reusable. */
    int cols = sqlite3_column_count(s);
    int64_t as_src = cols > 11 ? sqlite3_column_int64(s, 11) : 0;
    int64_t as_dst = cols > 12 ? sqlite3_column_int64(s, 12) : 0;
    int64_t same_ip = cols > 13 ? sqlite3_column_int64(s, 13) : 0;
    json_object_set_new(o, "as_src",       json_integer(as_src));
    json_object_set_new(o, "as_dst",       json_integer(as_dst));
    json_object_set_new(o, "same_ip",      json_integer(same_ip));
    int crawler = (as_dst == 0 && as_src >= 50) || same_ip >= 3;
    json_object_set_new(o, "likely_crawler", json_integer(crawler ? 1 : 0));
    return o;
}

static json_t *
row_query(sqlite3_stmt *s, void *ctx)
{
    (void)ctx;
    json_t *o = json_object();
    json_object_set_new(o, "ts",        json_integer(sqlite3_column_int64(s, 0)));
    json_object_set_new(o, "ip",        json_string((const char *)sqlite3_column_text(s, 1)));
    json_object_set_new(o, "port",      json_integer(sqlite3_column_int(s, 2)));
    json_object_set_new(o, "direction", json_string((const char *)sqlite3_column_text(s, 3)));
    json_object_set_new(o, "y",         json_string((const char *)sqlite3_column_text(s, 4)));
    json_object_set_new(o, "q",         sqlite3_column_type(s, 5) == SQLITE_NULL ? json_null() : json_string((const char *)sqlite3_column_text(s, 5)));
    json_set_blob_hex(o, "target", sqlite3_column_blob(s, 6), sqlite3_column_bytes(s, 6));
    json_object_set_new(o, "raw_size",  json_integer(sqlite3_column_int(s, 7)));
    return o;
}

static json_t *
row_infohash(sqlite3_stmt *s, void *ctx)
{
    (void)ctx;
    json_t *o = json_object();
    json_set_blob_hex(o, "hash", sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0));
    json_object_set_new(o, "first_seen",    json_integer(sqlite3_column_int64(s, 1)));
    json_object_set_new(o, "last_seen",     json_integer(sqlite3_column_int64(s, 2)));
    json_object_set_new(o, "times_queried", json_integer(sqlite3_column_int64(s, 3)));
    json_object_set_new(o, "source",        sqlite3_column_type(s, 4) == SQLITE_NULL ? json_null() : json_string((const char *)sqlite3_column_text(s, 4)));
    return o;
}

static json_t *
row_bep44(sqlite3_stmt *s, void *ctx)
{
    (void)ctx;
    json_t *o = json_object();
    json_set_blob_hex(o, "target", sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0));
    json_object_set_new(o, "mutable", json_integer(sqlite3_column_int(s, 1)));
    json_set_blob_hex(o, "pk",   sqlite3_column_blob(s, 2), sqlite3_column_bytes(s, 2));
    json_set_blob_hex(o, "salt", sqlite3_column_blob(s, 3), sqlite3_column_bytes(s, 3));
    json_object_set_new(o, "seq",        json_integer(sqlite3_column_int64(s, 4)));
    json_set_blob_hex(o, "sig", sqlite3_column_blob(s, 5), sqlite3_column_bytes(s, 5));
    json_set_blob_hex(o, "v",   sqlite3_column_blob(s, 6), sqlite3_column_bytes(s, 6));
    json_object_set_new(o, "first_seen", json_integer(sqlite3_column_int64(s, 7)));
    json_object_set_new(o, "last_seen",  json_integer(sqlite3_column_int64(s, 8)));
    return o;
}

struct limit_ctx { int limit; };
static void bind_limit(sqlite3_stmt *s, void *c) {
    sqlite3_bind_int(s, 1, ((struct limit_ctx *)c)->limit);
}

char *
db_select_peers_json(int limit, const char *order)
{
    if (limit <= 0 || limit > 5000) limit = 500;
    const char *ord = "last_seen DESC";
    if (order && strcmp(order, "first_seen") == 0) ord = "first_seen DESC";
    if (order && strcmp(order, "rtt")       == 0) ord = "rtt_ms_ewma ASC";
    if (order && strcmp(order, "queries")   == 0) ord = "(queries_in+queries_out) DESC";

    /* Left-join the peer row against per-peer edge counts (as_src / as_dst)
     * and a per-IP port-count. These drive the "likely crawler" heuristic on
     * the UI:   as_dst == 0 && as_src >= 50          → never in anyone's
     *                                                  routing table despite
     *                                                  answering us a lot
     *          same_ip_count >= 3                    → many source ports from
     *                                                  the same host
     */
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "WITH src AS (SELECT src_ip ip, src_port port, COUNT(*) c FROM edges GROUP BY 1,2),"
        "     dst AS (SELECT dst_ip ip, dst_port port, COUNT(*) c FROM edges GROUP BY 1,2),"
        "     ipc AS (SELECT ip,               COUNT(*) c FROM peers GROUP BY 1)"
        " SELECT p.ip, p.port, p.node_id, p.v_string, p.ro, p.bep42_ok,"
        "        p.first_seen, p.last_seen, p.rtt_ms_ewma,"
        "        p.queries_in, p.queries_out,"
        "        COALESCE(s.c,0) AS as_src, COALESCE(d.c,0) AS as_dst,"
        "        COALESCE(ipc.c,0) AS same_ip"
        "   FROM peers p"
        "   LEFT JOIN src  s ON s.ip=p.ip  AND s.port=p.port"
        "   LEFT JOIN dst  d ON d.ip=p.ip  AND d.port=p.port"
        "   LEFT JOIN ipc  ON ipc.ip=p.ip"
        "  ORDER BY %s LIMIT ?", ord);
    struct limit_ctx c = { limit };
    return run_select(sql, bind_limit, row_peer, &c);
}

struct qctx { int64_t since; int limit; };
static void bind_qctx(sqlite3_stmt *s, void *c) {
    struct qctx *q = c;
    sqlite3_bind_int64(s, 1, q->since);
    sqlite3_bind_int  (s, 2, q->limit);
}

char *
db_select_queries_json(int64_t since_ts, int limit)
{
    if (limit <= 0 || limit > 5000) limit = 500;
    struct qctx c = { since_ts, limit };
    return run_select(
        "SELECT ts,ip,port,direction,y,q,target,raw_size"
        " FROM queries WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
        bind_qctx, row_query, &c);
}

char *
db_select_infohashes_json(int limit)
{
    if (limit <= 0 || limit > 5000) limit = 500;
    struct limit_ctx c = { limit };
    return run_select(
        "SELECT hash,first_seen,last_seen,times_queried,source"
        " FROM infohashes ORDER BY last_seen DESC LIMIT ?",
        bind_limit, row_infohash, &c);
}

char *
db_select_bep44_json(int limit)
{
    if (limit <= 0 || limit > 5000) limit = 500;
    struct limit_ctx c = { limit };
    return run_select(
        "SELECT target,mutable,pk,salt,seq,sig,v,first_seen,last_seen"
        " FROM bep44_items ORDER BY last_seen DESC LIMIT ?",
        bind_limit, row_bep44, &c);
}

static int64_t
scalar_i64(const char *sql)
{
    if (!g_db) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) return 0;
    int64_t n = 0;
    if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

int64_t db_count_peers(void)      { return scalar_i64("SELECT COUNT(*) FROM peers"); }
int64_t db_count_queries(void)    { return scalar_i64("SELECT COUNT(*) FROM queries"); }
int64_t db_count_infohashes(void) { return scalar_i64("SELECT COUNT(*) FROM infohashes"); }
int64_t db_count_bep44(void)      { return scalar_i64("SELECT COUNT(*) FROM bep44_items"); }

/* Pull the top-N peers by edge degree and the subgraph of edges between them.
 * Response shape: { nodes: [...], links: [...] }. Node metadata (country is
 * NOT included here — GeoIP resolution happens in http_ws.c where the mmdb
 * handle lives). */
char *
db_select_graph_json(int limit)
{
    if (!g_db) return NULL;
    if (limit <= 0) limit = 300;
    if (limit > 1500) limit = 1500;

    /* Top-N peers by degree: count appearances as src OR dst in edges.
     * Use a CTE to express the union count, then a final LIMIT. */
    sqlite3_stmt *s = NULL;
    const char *sql_top =
        "WITH src AS (SELECT src_ip ip, src_port port, COUNT(*) c FROM edges GROUP BY 1,2),"
        "     dst AS (SELECT dst_ip ip, dst_port port, COUNT(*) c FROM edges GROUP BY 1,2),"
        "     ipc AS (SELECT ip, COUNT(*) c FROM peers GROUP BY 1),"
        "     all_nodes AS ("
        "       SELECT ip, port FROM src"
        "       UNION"
        "       SELECT ip, port FROM dst)"
        " SELECT a.ip, a.port,"
        "        COALESCE(src.c,0) + COALESCE(dst.c,0) AS deg,"
        "        p.v_string,"
        "        COALESCE(src.c,0) AS as_src,"
        "        COALESCE(dst.c,0) AS as_dst,"
        "        COALESCE(ipc.c,0) AS same_ip"
        "   FROM all_nodes a"
        "   LEFT JOIN src  ON src.ip=a.ip  AND src.port=a.port"
        "   LEFT JOIN dst  ON dst.ip=a.ip  AND dst.port=a.port"
        "   LEFT JOIN peers p ON p.ip=a.ip AND p.port=a.port"
        "   LEFT JOIN ipc  ON ipc.ip=a.ip"
        "  ORDER BY deg DESC LIMIT ?";
    if (sqlite3_prepare_v2(g_db, sql_top, -1, &s, NULL) != SQLITE_OK) {
        log_err("prepare graph-top"); return NULL;
    }
    sqlite3_bind_int(s, 1, limit);

    json_t *nodes = json_array();
    /* collect a set of (ip, port) for subsequent edge filter */
    typedef struct { char ip[INET_ADDRSTRLEN]; int port; } nk;
    nk *set = calloc((size_t)limit, sizeof(*set));
    int set_n = 0;
    while (set && sqlite3_step(s) == SQLITE_ROW) {
        const char *ip = (const char *)sqlite3_column_text(s, 0);
        int port       = sqlite3_column_int(s, 1);
        int deg        = sqlite3_column_int(s, 2);
        const void *v  = sqlite3_column_blob(s, 3);
        int v_len      = sqlite3_column_bytes(s, 3);
        int64_t as_src  = sqlite3_column_int64(s, 4);
        int64_t as_dst  = sqlite3_column_int64(s, 5);
        int64_t same_ip = sqlite3_column_int64(s, 6);

        char id[INET_ADDRSTRLEN + 8];
        snprintf(id, sizeof(id), "%s:%d", ip, port);

        json_t *o = json_object();
        json_object_set_new(o, "id",   json_string(id));
        json_object_set_new(o, "ip",   json_string(ip));
        json_object_set_new(o, "port", json_integer(port));
        json_object_set_new(o, "deg",  json_integer(deg));
        json_set_blob_hex(o, "v_string", v, v_len);
        json_object_set_new(o, "as_src",  json_integer(as_src));
        json_object_set_new(o, "as_dst",  json_integer(as_dst));
        json_object_set_new(o, "same_ip", json_integer(same_ip));
        int crawler = (as_dst == 0 && as_src >= 50) || same_ip >= 3;
        json_object_set_new(o, "likely_crawler", json_integer(crawler ? 1 : 0));
        json_array_append_new(nodes, o);

        if (set_n < limit) {
            snprintf(set[set_n].ip, sizeof(set[set_n].ip), "%s", ip);
            set[set_n].port = port;
            set_n++;
        }
    }
    sqlite3_finalize(s);

    /* Fetch edges among the set. Simpler and still fast at this scale: pull
     * all edges and filter in-process via a small open-hash lookup. */
    json_t *links = json_array();
    sqlite3_stmt *e = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT src_ip,src_port,dst_ip,dst_port FROM edges",
            -1, &e, NULL) == SQLITE_OK) {

        /* build a sorted search index for O(log n) endpoint membership */
        int (*find)(const char *ip, int port, nk *tbl, int n) =
            NULL; (void)find;

        while (set && sqlite3_step(e) == SQLITE_ROW) {
            const char *sip = (const char *)sqlite3_column_text(e, 0);
            int sport = sqlite3_column_int(e, 1);
            const char *dip = (const char *)sqlite3_column_text(e, 2);
            int dport = sqlite3_column_int(e, 3);

            int sok = 0, dok = 0;
            for (int i = 0; i < set_n; i++) {
                if (!sok && set[i].port == sport && strcmp(set[i].ip, sip)==0) sok = 1;
                if (!dok && set[i].port == dport && strcmp(set[i].ip, dip)==0) dok = 1;
                if (sok && dok) break;
            }
            if (sok && dok) {
                char sbuf[INET_ADDRSTRLEN+8], dbuf[INET_ADDRSTRLEN+8];
                snprintf(sbuf, sizeof(sbuf), "%s:%d", sip, sport);
                snprintf(dbuf, sizeof(dbuf), "%s:%d", dip, dport);
                json_t *lo = json_object();
                json_object_set_new(lo, "src", json_string(sbuf));
                json_object_set_new(lo, "dst", json_string(dbuf));
                json_array_append_new(links, lo);
            }
        }
        sqlite3_finalize(e);
    }
    free(set);

    json_t *env = json_object();
    json_object_set_new(env, "nodes", nodes);
    json_object_set_new(env, "links", links);
    char *js = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    return js;
}

char *
db_select_client_stats_json(int limit)
{
    if (!g_db) return NULL;
    if (limit <= 0 || limit > 500) limit = 50;

    /* Count rows: known (non-null v_string), unknown (null), total. */
    int64_t total   = db_count_peers();
    int64_t unknown = scalar_i64(
        "SELECT COUNT(*) FROM peers WHERE v_string IS NULL");

    sqlite3_stmt *s = NULL;
    const char *sql =
        "SELECT v_string, COUNT(*) c FROM peers"
        " WHERE v_string IS NOT NULL"
        " GROUP BY v_string ORDER BY c DESC LIMIT ?";
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) {
        log_err("prepare client-stats"); return NULL;
    }
    sqlite3_bind_int(s, 1, limit);

    json_t *arr = json_array();
    while (sqlite3_step(s) == SQLITE_ROW) {
        json_t *o = json_object();
        json_set_blob_hex(o, "v_string",
                          sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0));
        json_object_set_new(o, "count", json_integer(sqlite3_column_int64(s, 1)));
        json_array_append_new(arr, o);
    }
    sqlite3_finalize(s);

    json_t *env = json_object();
    json_object_set_new(env, "total",     json_integer(total));
    json_object_set_new(env, "known",     json_integer(total - unknown));
    json_object_set_new(env, "unknown",   json_integer(unknown));
    json_object_set_new(env, "clients",   arr);
    char *js = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    return js;
}

void
db_upsert_edge(const struct sockaddr_in *src, const struct sockaddr_in *dst)
{
    if (!g_db || !src || !dst) return;
    tx_begin_if_needed();

    char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
    int  sport, dport;
    peer_key(src, sip, sizeof(sip), &sport);
    peer_key(dst, dip, sizeof(dip), &dport);

    sqlite3_stmt *s = g_ins_edge;
    sqlite3_reset(s);
    sqlite3_bind_text (s, 1, sip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 2, sport);
    sqlite3_bind_text (s, 3, dip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 4, dport);
    sqlite3_bind_int64(s, 5, (int64_t)time(NULL));
    if (sqlite3_step(s) != SQLITE_DONE) log_err("upsert edge");
}

int
db_foreach_peer_ip(int (*cb)(const char *ip, void *closure), void *closure)
{
    if (!g_db || !cb) return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db, "SELECT ip FROM peers", -1, &s, NULL)
            != SQLITE_OK) {
        log_err("prepare foreach_peer_ip"); return -1;
    }
    int stop = 0;
    while (!stop && sqlite3_step(s) == SQLITE_ROW) {
        const char *ip = (const char *)sqlite3_column_text(s, 0);
        if (ip && cb(ip, closure) != 0) stop = 1;
    }
    sqlite3_finalize(s);
    return 0;
}

char *
db_select_stats_json(void)
{
    if (!g_db) return NULL;
    json_t *o = json_object();
    int64_t now = time(NULL);
    json_object_set_new(o, "ts",          json_integer(now));
    json_object_set_new(o, "peers",       json_integer(db_count_peers()));
    json_object_set_new(o, "queries",     json_integer(db_count_queries()));
    json_object_set_new(o, "infohashes",  json_integer(db_count_infohashes()));
    json_object_set_new(o, "bep44_items", json_integer(db_count_bep44()));
    /* rates: rows in last 60s */
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT COUNT(*) FROM queries WHERE ts >= %lld", (long long)(now - 60));
    json_object_set_new(o, "queries_per_min", json_integer(scalar_i64(sql)));
    char *js = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    return js;
}
