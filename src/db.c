#define _POSIX_C_SOURCE 200809L
#include "db.h"

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "redact.h"

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

    /* Additive migrations: add columns if missing. SQLite raises
     * "duplicate column name" if already present, which we suppress. */
    static const char *MIGRATIONS[] = {
        "ALTER TABLE peers ADD COLUMN supports_bep51 INTEGER",
        "ALTER TABLE peers ADD COLUMN last_pinged   INTEGER",
        "CREATE INDEX IF NOT EXISTS peers_pinged ON peers(last_pinged)",
        NULL,
    };
    for (int i = 0; MIGRATIONS[i]; i++) {
        char *merr = NULL;
        int mrc = sqlite3_exec(g_db, MIGRATIONS[i], NULL, NULL, &merr);
        if (mrc != SQLITE_OK && mrc != SQLITE_ERROR) {     /* ERROR = dup col */
            fprintf(stderr, TAG "migration note: %s\n", merr ? merr : "?");
        }
        sqlite3_free(merr);
    }

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

/* Accept both v4 and v6 peers; format ip as text in ip_out, port as host order. */
static int
peer_key(const struct sockaddr *sa, char *ip_out, size_t ip_cap, int *port_out)
{
    if (!sa) return -1;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *p = (const struct sockaddr_in *)sa;
        if (!inet_ntop(AF_INET, &p->sin_addr, ip_out, ip_cap)) return -1;
        *port_out = ntohs(p->sin_port);
        return 0;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)sa;
        if (!inet_ntop(AF_INET6, &p->sin6_addr, ip_out, ip_cap)) return -1;
        *port_out = ntohs(p->sin6_port);
        return 0;
    }
    return -1;
}

void
db_upsert_peer(const struct sockaddr *peer, socklen_t peerlen,
               const uint8_t node_id[BEP44_NODE_ID_LEN], int has_node_id,
               const uint8_t *v_string, size_t v_len,
               int ro, int bep42_ok, int rtt_ms, char direction)
{
    (void)peerlen;
    if (!g_db || !peer) return;
    tx_begin_if_needed();

    char ip[INET6_ADDRSTRLEN];
    int  port;
    if (peer_key(peer, ip, sizeof(ip), &port) < 0) return;
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
                const struct sockaddr *peer, socklen_t peerlen,
                const char *direction,
                const char *y,
                const char *q,
                const uint8_t *target,
                int raw_size)
{
    (void)peerlen;
    if (!g_db || !peer) return;
    tx_begin_if_needed();

    char ip[INET6_ADDRSTRLEN];
    int  port;
    if (peer_key(peer, ip, sizeof(ip), &port) < 0) return;

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
    const char *ip_raw = (const char *)sqlite3_column_text(s, 0);
    char ip_red[64];
    if (ip_raw && redact_ip(ip_raw, ip_red, sizeof(ip_red)) == 0) {
        json_object_set_new(o, "ip", json_string(ip_red));
    } else {
        json_object_set_new(o, "ip", json_string(ip_raw ? ip_raw : ""));
    }
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
    /* Edge-count extras (columns 11-13) and optional supports_bep51 (col 14)
     * only present when the query includes them. Extract defensively so
     * row_peer remains reusable. */
    int cols = sqlite3_column_count(s);
    int64_t as_src = cols > 11 ? sqlite3_column_int64(s, 11) : 0;
    int64_t as_dst = cols > 12 ? sqlite3_column_int64(s, 12) : 0;
    int64_t same_ip = cols > 13 ? sqlite3_column_int64(s, 13) : 0;
    json_object_set_new(o, "as_src",       json_integer(as_src));
    json_object_set_new(o, "as_dst",       json_integer(as_dst));
    json_object_set_new(o, "same_ip",      json_integer(same_ip));
    /* crawler classification is layered on by http_ws.c's classify_peer
     * (which has access to ASN org from GeoIP); raw db rows omit it. */
    if (cols > 14 && sqlite3_column_type(s, 14) != SQLITE_NULL) {
        json_object_set_new(o, "supports_bep51",
                            json_integer(sqlite3_column_int(s, 14) ? 1 : 0));
    } else {
        json_object_set_new(o, "supports_bep51", json_null());
    }
    return o;
}

static json_t *
row_query(sqlite3_stmt *s, void *ctx)
{
    (void)ctx;
    json_t *o = json_object();
    json_object_set_new(o, "ts",        json_integer(sqlite3_column_int64(s, 0)));
    {
        const char *ip_raw = (const char *)sqlite3_column_text(s, 1);
        char ip_red[64];
        if (ip_raw && redact_ip(ip_raw, ip_red, sizeof(ip_red)) == 0) {
            json_object_set_new(o, "ip", json_string(ip_red));
        } else {
            json_object_set_new(o, "ip", json_string(ip_raw ? ip_raw : ""));
        }
    }
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
    /* SQLi safety: `ord` is selected from a closed-set allowlist of
     * literal strings. The user-supplied `order` query parameter only
     * drives an `strcmp` match against fixed values; an unmatched value
     * leaves the default in place. NEVER substitute `order` directly
     * into the SQL via %s — `ord` must always be one of the literals
     * below. The actual LIMIT goes through sqlite3_bind_int (`?`). */
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
        "        COALESCE(ipc.c,0) AS same_ip,"
        "        p.supports_bep51"
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

int64_t
db_count_peers_since(int64_t since_ts)
{
    if (!g_db) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COUNT(*) FROM peers WHERE last_seen >= ?",
            -1, &s, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(s, 1, since_ts);
    int64_t n = 0;
    if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* Fill `out` with up to `max` (ip,port) entries whose last_pinged is NULL or
 * older than `older_than_ts`, oldest first. Returns the number filled. */
int
db_select_liveness_candidates(int max, int64_t older_than_ts,
                              struct sockaddr_storage *out, int *out_lens)
{
    if (!g_db || !out || !out_lens || max <= 0) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT ip,port FROM peers"
            " WHERE last_pinged IS NULL OR last_pinged < ?"
            " ORDER BY last_pinged IS NULL DESC, last_pinged ASC"
            " LIMIT ?", -1, &s, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(s, 1, older_than_ts);
    sqlite3_bind_int  (s, 2, max);
    int n = 0;
    while (sqlite3_step(s) == SQLITE_ROW && n < max) {
        const char *ip = (const char *)sqlite3_column_text(s, 0);
        int port = sqlite3_column_int(s, 1);
        if (!ip) continue;
        struct sockaddr_in6 sin6 = {0};
        struct sockaddr_in  sin4 = {0};
        if (inet_pton(AF_INET, ip, &sin4.sin_addr) == 1) {
            sin4.sin_family = AF_INET;
            sin4.sin_port = htons((uint16_t)port);
            memcpy(&out[n], &sin4, sizeof(sin4));
            out_lens[n] = sizeof(sin4);
            n++;
        } else if (inet_pton(AF_INET6, ip, &sin6.sin6_addr) == 1) {
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = htons((uint16_t)port);
            memcpy(&out[n], &sin6, sizeof(sin6));
            out_lens[n] = sizeof(sin6);
            n++;
        }
    }
    sqlite3_finalize(s);
    return n;
}

void
db_mark_pinged(const struct sockaddr *peer, socklen_t peerlen, int64_t ts)
{
    (void)peerlen;
    if (!g_db || !peer) return;
    char ip[INET6_ADDRSTRLEN];
    int  port;
    if (peer_key(peer, ip, sizeof(ip), &port) < 0) return;
    tx_begin_if_needed();
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "UPDATE peers SET last_pinged=? WHERE ip=? AND port=?",
            -1, &s, NULL) != SQLITE_OK) return;
    sqlite3_bind_int64(s, 1, ts);
    sqlite3_bind_text (s, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 3, port);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("mark pinged");
    sqlite3_finalize(s);
}

/* Permanently delete peers whose last_seen is older than `older_than_ts`.
 * Edges referencing pruned peers stay in the edges table (cheap; queried
 * defensively elsewhere). Returns the number deleted. */
int
db_prune_peers_older_than(int64_t older_than_ts)
{
    if (!g_db) return 0;
    tx_begin_if_needed();
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "DELETE FROM peers WHERE last_seen < ?", -1, &s, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(s, 1, older_than_ts);
    int rc = sqlite3_step(s);
    int n = (rc == SQLITE_DONE) ? sqlite3_changes(g_db) : 0;
    sqlite3_finalize(s);
    return n;
}

/* Open-addressing hash index from "ip:port" string → candidate index.
 *
 * The graph builder used to do a linear scan over `cand_n` candidates for
 * every edge in the table — at 885 k edges × 15 k candidates that is many
 * billions of strcmp ops and dominated the request time. With a hash lookup
 * each edge resolves in O(1) and the dominant cost falls back to the SQL
 * pass that emits the candidate set. */
typedef struct {
    int     *slots;     /* -1 sentinel = empty; >=0 = index into cands[] */
    uint32_t cap_mask;  /* power-of-two minus one */
    /* parallel arrays sized cand_n: precomputed key + hash to avoid
     * re-snprintf'ing on every probe step */
    char    (*keys)[INET_ADDRSTRLEN + 8];
    uint8_t  *key_lens;
    uint32_t *hashes;
} cand_index;

static uint32_t
fnv1a(const char *p, int len)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= (unsigned char)p[i];
        h *= 16777619u;
    }
    return h;
}

static int
cand_index_build(cand_index *ix, int n,
                 const char (*ips)[INET_ADDRSTRLEN], const int *ports)
{
    memset(ix, 0, sizeof(*ix));
    if (n <= 0) return 0;
    /* 50% target load */
    uint32_t cap = 16;
    while (cap < (uint32_t)n * 2) cap <<= 1;
    ix->slots    = malloc((size_t)cap * sizeof(int));
    ix->keys     = malloc((size_t)n * sizeof(*ix->keys));
    ix->key_lens = malloc((size_t)n);
    ix->hashes   = malloc((size_t)n * sizeof(uint32_t));
    if (!ix->slots || !ix->keys || !ix->key_lens || !ix->hashes) {
        free(ix->slots); free(ix->keys); free(ix->key_lens); free(ix->hashes);
        memset(ix, 0, sizeof(*ix));
        return -1;
    }
    ix->cap_mask = cap - 1;
    for (uint32_t s = 0; s < cap; s++) ix->slots[s] = -1;
    for (int i = 0; i < n; i++) {
        int kl = snprintf(ix->keys[i], sizeof(ix->keys[i]),
                          "%s:%d", ips[i], ports[i]);
        ix->key_lens[i] = (uint8_t)(kl > 255 ? 255 : kl);
        ix->hashes[i]   = fnv1a(ix->keys[i], kl);
        uint32_t slot = ix->hashes[i] & ix->cap_mask;
        while (ix->slots[slot] != -1) slot = (slot + 1) & ix->cap_mask;
        ix->slots[slot] = i;
    }
    return 0;
}

static void
cand_index_free(cand_index *ix)
{
    free(ix->slots); free(ix->keys); free(ix->key_lens); free(ix->hashes);
    memset(ix, 0, sizeof(*ix));
}

static int
cand_index_lookup(const cand_index *ix, const char *ip, int port)
{
    if (!ix->slots || !ip) return -1;
    char     key[INET_ADDRSTRLEN + 8];
    int      kl = snprintf(key, sizeof(key), "%s:%d", ip, port);
    uint32_t h  = fnv1a(key, kl);
    uint32_t slot = h & ix->cap_mask;
    for (;;) {
        int idx = ix->slots[slot];
        if (idx < 0) return -1;
        if (ix->hashes[idx] == h
            && ix->key_lens[idx] == (uint8_t)kl
            && memcmp(ix->keys[idx], key, (size_t)kl) == 0) return idx;
        slot = (slot + 1) & ix->cap_mask;
    }
}

/* Pull the top-N peers by edge degree and the subgraph of edges between them.
 * Response shape: { nodes: [...], links: [...] }. Node metadata (country is
 * NOT included here — GeoIP resolution happens in http_ws.c where the mmdb
 * handle lives). */
char *
db_select_graph_json(int limit)
{
    if (!g_db) return NULL;
    if (limit <= 0) limit = 300;
    if (limit > 25000) limit = 25000;

    /*
     * Two-pass picker:
     *
     * Pass 1 — pull a CANDIDATE set (3× the requested limit, capped at
     *   10k) with the cheap "overall edge degree" ranking.
     * Pass 2 — for each candidate count its INTERNAL degree (edges where
     *   both endpoints are in the candidate set), then take the top-N
     *   by that internal degree.
     *
     * Result: every node we return has at least one visible edge to
     * another returned node, and the most "internally connected" peers
     * make the cut. No orphan periphery bubbles, no separate filter pass.
     */
    int cand_limit = limit * 3;
    if (cand_limit > 50000) cand_limit = 50000;

    typedef struct {
        char    ip[INET_ADDRSTRLEN];
        int     port;
        int     overall_deg;
        int     internal_deg;
        int     keep;            /* set if this candidate makes the final cut */
        const void *v;            /* pointer into the row's blob — copied later */
        int     v_len;
        const void *node_id;      /* 20-byte blob copied here from peers row */
        int     node_id_len;
        int64_t as_src, as_dst, same_ip;
        int64_t first_seen, last_seen;
        int64_t queries_in, queries_out;
        int     ro;               /* -1 = NULL */
        int     bep42_ok;         /* -1 = NULL */
        int     rtt_ms_ewma;      /* -1 = NULL */
        int     supports_bep51;   /* -1 = NULL */
        json_t *node_json;        /* allocated lazily on keep */
    } cand_t;

    cand_t *cands = calloc((size_t)cand_limit, sizeof(*cands));
    if (!cands) return NULL;
    int cand_n = 0;

    /* --- Pass 1: candidate set by overall degree ------------------- */
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
        "        COALESCE(ipc.c,0) AS same_ip,"
        "        p.node_id, p.first_seen, p.last_seen,"
        "        p.queries_in, p.queries_out,"
        "        p.ro, p.bep42_ok, p.rtt_ms_ewma, p.supports_bep51"
        "   FROM all_nodes a"
        "   LEFT JOIN src  ON src.ip=a.ip  AND src.port=a.port"
        "   LEFT JOIN dst  ON dst.ip=a.ip  AND dst.port=a.port"
        "   LEFT JOIN peers p ON p.ip=a.ip AND p.port=a.port"
        "   LEFT JOIN ipc  ON ipc.ip=a.ip"
        "  ORDER BY deg DESC LIMIT ?";
    if (sqlite3_prepare_v2(g_db, sql_top, -1, &s, NULL) != SQLITE_OK) {
        log_err("prepare graph-top"); free(cands); return NULL;
    }
    sqlite3_bind_int(s, 1, cand_limit);
    while (cand_n < cand_limit && sqlite3_step(s) == SQLITE_ROW) {
        cand_t *c = &cands[cand_n++];
        snprintf(c->ip, sizeof(c->ip), "%s",
                 (const char *)sqlite3_column_text(s, 0));
        c->port        = sqlite3_column_int(s, 1);
        c->overall_deg = sqlite3_column_int(s, 2);
        /* sqlite3_column_blob pointers are valid only until the next step,
         * so copy the v_string into our own buffer. */
        const void *vb = sqlite3_column_blob(s, 3);
        int vbl = sqlite3_column_bytes(s, 3);
        if (vb && vbl > 0) {
            void *copy = malloc((size_t)vbl);
            if (copy) { memcpy(copy, vb, (size_t)vbl); c->v = copy; c->v_len = vbl; }
        }
        c->as_src  = sqlite3_column_int64(s, 4);
        c->as_dst  = sqlite3_column_int64(s, 5);
        c->same_ip = sqlite3_column_int64(s, 6);
        const void *nid = sqlite3_column_blob(s, 7);
        int nidl = sqlite3_column_bytes(s, 7);
        if (nid && nidl > 0) {
            void *copy = malloc((size_t)nidl);
            if (copy) { memcpy(copy, nid, (size_t)nidl); c->node_id = copy; c->node_id_len = nidl; }
        }
        c->first_seen     = sqlite3_column_int64(s, 8);
        c->last_seen      = sqlite3_column_int64(s, 9);
        c->queries_in     = sqlite3_column_int64(s, 10);
        c->queries_out    = sqlite3_column_int64(s, 11);
        c->ro             = (sqlite3_column_type(s, 12) == SQLITE_NULL) ? -1 : sqlite3_column_int(s, 12);
        c->bep42_ok       = (sqlite3_column_type(s, 13) == SQLITE_NULL) ? -1 : sqlite3_column_int(s, 13);
        c->rtt_ms_ewma    = (sqlite3_column_type(s, 14) == SQLITE_NULL) ? -1 : sqlite3_column_int(s, 14);
        c->supports_bep51 = (sqlite3_column_type(s, 15) == SQLITE_NULL) ? -1 : sqlite3_column_int(s, 15);
    }
    sqlite3_finalize(s);

    /* --- Pass 2: count internal-degree by walking edges ----------- */
    /* Build a hash index over the candidate set. Without this, looking up
     * each edge's endpoint becomes a linear scan over cand_n — at 800 k+
     * edges and 15 k candidates that's billions of strcmps. */
    cand_index ix;
    {
        char  (*ips)[INET_ADDRSTRLEN] = malloc((size_t)cand_n * sizeof(*ips));
        int    *ports = malloc((size_t)cand_n * sizeof(int));
        if (ips && ports) {
            for (int i = 0; i < cand_n; i++) {
                memcpy(ips[i], cands[i].ip, sizeof(ips[i]));
                ports[i] = cands[i].port;
            }
            cand_index_build(&ix, cand_n, ips, ports);
        } else {
            memset(&ix, 0, sizeof(ix));
        }
        free(ips); free(ports);
    }

    sqlite3_stmt *e = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT src_ip,src_port,dst_ip,dst_port FROM edges",
            -1, &e, NULL) == SQLITE_OK) {
        while (sqlite3_step(e) == SQLITE_ROW) {
            const char *sip = (const char *)sqlite3_column_text(e, 0);
            int sport = sqlite3_column_int(e, 1);
            const char *dip = (const char *)sqlite3_column_text(e, 2);
            int dport = sqlite3_column_int(e, 3);
            int si = cand_index_lookup(&ix, sip, sport);
            int di = cand_index_lookup(&ix, dip, dport);
            if (si >= 0 && di >= 0) {
                cands[si].internal_deg++;
                cands[di].internal_deg++;
            }
        }
        sqlite3_finalize(e);
    }

    /* --- Top-N by internal degree (simple selection, N at most 10k) --- */
    /* Mark `keep=1` on the top-N. Tie-break by overall_deg. */
    int kept = 0;
    while (kept < limit) {
        int best = -1;
        for (int i = 0; i < cand_n; i++) {
            if (cands[i].keep || cands[i].internal_deg == 0) continue;
            if (best < 0
                || cands[i].internal_deg > cands[best].internal_deg
                || (cands[i].internal_deg == cands[best].internal_deg
                    && cands[i].overall_deg > cands[best].overall_deg))
                best = i;
        }
        if (best < 0) break;
        cands[best].keep = 1;
        kept++;
    }

    /* --- Emit JSON for kept nodes -------------------------------- */
    json_t *nodes = json_array();
    for (int i = 0; i < cand_n; i++) {
        if (!cands[i].keep) continue;
        char ip_red[64];
        const char *ip_out = cands[i].ip;
        if (redact_ip(cands[i].ip, ip_red, sizeof(ip_red)) == 0) ip_out = ip_red;
        char id[80];
        snprintf(id, sizeof(id), "%s:%d", ip_out, cands[i].port);
        json_t *o = json_object();
        json_object_set_new(o, "id",   json_string(id));
        json_object_set_new(o, "ip",   json_string(ip_out));
        json_object_set_new(o, "port", json_integer(cands[i].port));
        /* "deg" reports the in-result degree — what the user actually sees. */
        json_object_set_new(o, "deg",  json_integer(cands[i].internal_deg));
        json_set_blob_hex(o, "v_string", cands[i].v, cands[i].v_len);
        json_set_blob_hex(o, "node_id",  cands[i].node_id, cands[i].node_id_len);
        json_object_set_new(o, "as_src",  json_integer(cands[i].as_src));
        json_object_set_new(o, "as_dst",  json_integer(cands[i].as_dst));
        json_object_set_new(o, "same_ip", json_integer(cands[i].same_ip));
        json_object_set_new(o, "first_seen",  json_integer(cands[i].first_seen));
        json_object_set_new(o, "last_seen",   json_integer(cands[i].last_seen));
        json_object_set_new(o, "queries_in",  json_integer(cands[i].queries_in));
        json_object_set_new(o, "queries_out", json_integer(cands[i].queries_out));
        json_object_set_new(o, "ro",
            cands[i].ro       < 0 ? json_null() : json_integer(cands[i].ro));
        json_object_set_new(o, "bep42_ok",
            cands[i].bep42_ok < 0 ? json_null() : json_integer(cands[i].bep42_ok));
        json_object_set_new(o, "rtt_ms",
            cands[i].rtt_ms_ewma < 0 ? json_null() : json_integer(cands[i].rtt_ms_ewma));
        json_object_set_new(o, "supports_bep51",
            cands[i].supports_bep51 < 0 ? json_null() : json_integer(cands[i].supports_bep51));
        /* Legacy single-bit; the http_ws layer overlays the full classifier
         * (crawler_class/score/signals/reason) on top after geoip enrichment. */
        int crawler = (cands[i].as_dst == 0 && cands[i].as_src >= 50)
                   || cands[i].same_ip >= 3;
        json_object_set_new(o, "likely_crawler", json_integer(crawler ? 1 : 0));
        json_array_append_new(nodes, o);
        cands[i].node_json = o;     /* pointer ref, owned by `nodes` */
    }

    /* --- Emit edges between kept nodes --------------------------- */
    json_t *links = json_array();
    if (sqlite3_prepare_v2(g_db,
            "SELECT src_ip,src_port,dst_ip,dst_port FROM edges",
            -1, &e, NULL) == SQLITE_OK) {
        while (sqlite3_step(e) == SQLITE_ROW) {
            const char *sip = (const char *)sqlite3_column_text(e, 0);
            int sport = sqlite3_column_int(e, 1);
            const char *dip = (const char *)sqlite3_column_text(e, 2);
            int dport = sqlite3_column_int(e, 3);
            int si = cand_index_lookup(&ix, sip, sport);
            int di = cand_index_lookup(&ix, dip, dport);
            if (si >= 0 && di >= 0 && cands[si].keep && cands[di].keep) {
                /* Redact link endpoints the same way as node IDs (above)
                 * so that link.source / link.target match the corresponding
                 * node.id strings. Without this, the SPA can't resolve
                 * link endpoints to nodes (every IPv4 → /24, IPv6 → /48).
                 * Also: emit `source`/`target` (not `src`/`dst`) — that's
                 * the field convention the React/D3 graph layer expects. */
                char ip_red_s[64], ip_red_d[64];
                const char *sip_out = cands[si].ip;
                const char *dip_out = cands[di].ip;
                if (redact_ip(cands[si].ip, ip_red_s, sizeof(ip_red_s)) == 0) sip_out = ip_red_s;
                if (redact_ip(cands[di].ip, ip_red_d, sizeof(ip_red_d)) == 0) dip_out = ip_red_d;
                char sbuf[80], dbuf[80];
                snprintf(sbuf, sizeof(sbuf), "%s:%d", sip_out, cands[si].port);
                snprintf(dbuf, sizeof(dbuf), "%s:%d", dip_out, cands[di].port);
                json_t *lo = json_object();
                json_object_set_new(lo, "source", json_string(sbuf));
                json_object_set_new(lo, "target", json_string(dbuf));
                json_array_append_new(links, lo);
            }
        }
        sqlite3_finalize(e);
    }

    cand_index_free(&ix);

    /* Free per-candidate v_string + node_id copies. */
    for (int i = 0; i < cand_n; i++) {
        if (cands[i].v) free((void *)cands[i].v);
        if (cands[i].node_id) free((void *)cands[i].node_id);
    }
    free(cands);

    json_t *env = json_object();
    json_object_set_new(env, "nodes", nodes);
    json_object_set_new(env, "links", links);
    char *js = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    return js;
}

char *
db_select_infohash_sources_json(void)
{
    if (!g_db) return NULL;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COALESCE(source,'unknown') src, COUNT(*) c"
            "  FROM infohashes GROUP BY 1 ORDER BY c DESC",
            -1, &s, NULL) != SQLITE_OK) return NULL;
    json_t *arr = json_array();
    int64_t total = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        int64_t c = sqlite3_column_int64(s, 1);
        total += c;
        json_t *o = json_object();
        json_object_set_new(o, "source",
            json_string((const char *)sqlite3_column_text(s, 0)));
        json_object_set_new(o, "count", json_integer(c));
        json_array_append_new(arr, o);
    }
    sqlite3_finalize(s);
    json_t *env = json_object();
    json_object_set_new(env, "total",   json_integer(total));
    json_object_set_new(env, "sources", arr);
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
db_upsert_edge(const struct sockaddr *src, socklen_t srclen,
               const struct sockaddr *dst, socklen_t dstlen)
{
    (void)srclen; (void)dstlen;
    if (!g_db || !src || !dst) return;
    tx_begin_if_needed();

    char sip[INET6_ADDRSTRLEN], dip[INET6_ADDRSTRLEN];
    int  sport, dport;
    if (peer_key(src, sip, sizeof(sip), &sport) < 0) return;
    if (peer_key(dst, dip, sizeof(dip), &dport) < 0) return;

    sqlite3_stmt *s = g_ins_edge;
    sqlite3_reset(s);
    sqlite3_bind_text (s, 1, sip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 2, sport);
    sqlite3_bind_text (s, 3, dip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (s, 4, dport);
    sqlite3_bind_int64(s, 5, (int64_t)time(NULL));
    if (sqlite3_step(s) != SQLITE_DONE) log_err("upsert edge");
}

/* Mark a peer as BEP 51-capable (sets supports_bep51=1 if null). */
void
db_mark_peer_bep51(const struct sockaddr *peer, socklen_t peerlen)
{
    (void)peerlen;
    if (!g_db || !peer) return;
    char ip[INET6_ADDRSTRLEN];
    int  port;
    if (peer_key(peer, ip, sizeof(ip), &port) < 0) return;

    tx_begin_if_needed();
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db,
            "UPDATE peers SET supports_bep51 = 1 WHERE ip=? AND port=?",
            -1, &s, NULL) != SQLITE_OK) { log_err("prep bep51 mark"); return; }
    sqlite3_bind_text(s, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (s, 2, port);
    if (sqlite3_step(s) != SQLITE_DONE) log_err("mark bep51");
    sqlite3_finalize(s);
}

/* Return a random sample of up to max_count observed infohashes for the
 * meta-indexer BEP 51 reply. out must point to max_count * 20 bytes of
 * buffer. Returns the number of hashes written. */
int
db_sample_infohashes(uint8_t *out, int max_count)
{
    if (!g_db || !out || max_count <= 0) return 0;
    /* SQLi safety: `max_count` is an `int` callable only from internal
     * code paths (BEP 51 sweeper in crawl.c). Not user-controlled.
     * Bound the value before formatting so a future caller passing a
     * pathological size won't blow past `sql[]`. */
    if (max_count > 10000) max_count = 10000;
    char sql[128];
    snprintf(sql, sizeof(sql),
        "SELECT hash FROM infohashes ORDER BY RANDOM() LIMIT %d",
        max_count);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) return 0;
    int n = 0;
    while (n < max_count && sqlite3_step(s) == SQLITE_ROW) {
        const void *h = sqlite3_column_blob(s, 0);
        int hlen = sqlite3_column_bytes(s, 0);
        if (h && hlen == 20) {
            memcpy(out + n * 20, h, 20);
            n++;
        }
    }
    sqlite3_finalize(s);
    return n;
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
    /* v4 vs v6 split: v6 IPs contain a colon, v4 don't. */
    json_object_set_new(o, "peers_v6",
        json_integer(scalar_i64("SELECT COUNT(*) FROM peers WHERE ip LIKE '%:%'")));
    json_object_set_new(o, "peers_v4",
        json_integer(scalar_i64("SELECT COUNT(*) FROM peers WHERE ip NOT LIKE '%:%'")));
    json_object_set_new(o, "queries",     json_integer(db_count_queries()));
    json_object_set_new(o, "infohashes",  json_integer(db_count_infohashes()));
    json_object_set_new(o, "bep44_items", json_integer(db_count_bep44()));
    /* "alive" = last_seen within window. The liveness sweeper keeps these
     * meaningful by re-pinging every peer at its configured cadence (default
     * 6h); without --liveness, only peers we happen to talk to count. */
    int64_t alive_6h  = db_count_peers_since(now - 6  * 3600);
    int64_t alive_24h = db_count_peers_since(now - 24 * 3600);
    json_object_set_new(o, "peers_alive_6h",  json_integer(alive_6h));
    json_object_set_new(o, "peers_alive_24h", json_integer(alive_24h));
    json_object_set_new(o, "peers_stale",
        json_integer(db_count_peers() - alive_24h));
    /* rates: rows in last 60s. SQLi safety: `now` is `time(NULL)` on
     * the server; never user-controlled. Formatted as %lld with
     * sufficient buffer. */
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT COUNT(*) FROM queries WHERE ts >= %lld", (long long)(now - 60));
    json_object_set_new(o, "queries_per_min", json_integer(scalar_i64(sql)));
    /* Uptime anchor: timestamp of the very first peer observation in this
     * db. Stable across daemon restarts (only resets if observe.db is
     * deleted). 0 if the db is fresh and no peer has been observed yet. */
    json_object_set_new(o, "db_first_seen",
        json_integer(scalar_i64("SELECT COALESCE(MIN(first_seen), 0) FROM peers")));
    char *js = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    return js;
}
