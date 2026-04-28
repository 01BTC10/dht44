#ifndef DHT44_DB_H
#define DHT44_DB_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "bep44.h"

/*
 * SQLite persistence for the crawler:
 *   peers, queries, infohashes, bep44_items
 *
 * All writes are buffered inside an implicit transaction opened on the first
 * write after a commit, and closed by db_flush() (called ~1 Hz from the
 * daemon loop). This keeps fsync cost amortized while bounding data loss to
 * the last second on crash.
 */

int  db_open(const char *path);
void db_close(void);

/* Force a commit of any pending transaction. Safe to call when idle. */
void db_flush(void);

/* ---- writes ---- */

/* UPSERT: create-or-update peer row. Any of node_id/v_string/ro/rtt_ms may
 * be NULL / -1 if unknown (existing column values are preserved). direction
 * determines which counter (queries_in or queries_out) gets bumped — pass 'i',
 * 'o', or 0 for no bump. peer may be AF_INET or AF_INET6; the `ip` column
 * is TEXT so storage doesn't care about the family. */
void db_upsert_peer(const struct sockaddr *peer, socklen_t peerlen,
                    const uint8_t node_id[BEP44_NODE_ID_LEN], int has_node_id,
                    const uint8_t *v_string, size_t v_len,
                    int ro /* 0|1|-1 */,
                    int bep42_ok /* 0|1|-1 */,
                    int rtt_ms /* -1 for none */,
                    char direction /* 'i'|'o'|0 */);

/* Append a query-log row. target may be NULL. q may be NULL for responses. */
void db_insert_query(int64_t ts,
                     const struct sockaddr *peer, socklen_t peerlen,
                     const char *direction /* "in"|"out" */,
                     const char *y /* "q"|"r"|"e" */,
                     const char *q /* "ping"|"find_node"|... or NULL */,
                     const uint8_t *target /* 20B or NULL */,
                     int raw_size);

/* Upsert infohash sighting. Bumps times_queried. */
void db_upsert_infohash(const uint8_t hash[BEP44_TARGET_LEN],
                        const char *source /* "get_peers"|... */);

/* Upsert BEP 44 item. pk/salt/sig may be NULL for immutable. */
void db_upsert_bep44_item(const uint8_t target[BEP44_TARGET_LEN],
                          int mutable_,
                          const uint8_t *pk, size_t pk_len,
                          const uint8_t *salt, size_t salt_len,
                          int64_t seq,
                          const uint8_t *sig, size_t sig_len,
                          const uint8_t *v, size_t v_len);

/* ---- reads (JSON output via jansson) ---- */

/* Each read returns a char* of malloc'd JSON; caller free()s.
 * Returns NULL on error. */
char *db_select_peers_json(int limit, const char *order);
char *db_select_queries_json(int64_t since_ts, int limit);
char *db_select_infohashes_json(int limit);
char *db_select_bep44_json(int limit);
char *db_select_stats_json(void);

/* Aggregate peer count by v_string (BEP 20 client id). Returns a JSON array
 * [ { "v_string": "<hex|null>", "count": N }, ... ] ordered desc by count. */
char *db_select_client_stats_json(int limit);

/* Enumerate every (ip, port) peer row; cb returns nonzero to stop early.
 * Used by http_ws to aggregate by GeoIP country at read time. */
int db_foreach_peer_ip(int (*cb)(const char *ip, void *closure), void *closure);

/* BEP 51 helpers. */
void db_mark_peer_bep51(const struct sockaddr *peer, socklen_t peerlen);
int  db_sample_infohashes(uint8_t *out, int max_count);

/* Aggregate infohashes by source. Returns JSON array. */
char *db_select_infohash_sources_json(void);

/* Record a directed "A knows about B" edge (B appeared in a nodes list that
 * A sent back in a find_node response). Safe to call many times; dedupes on
 * (src, dst) and touches last_seen. Accepts mixed families. */
void db_upsert_edge(const struct sockaddr *src, socklen_t srclen,
                    const struct sockaddr *dst, socklen_t dstlen);

/* Return the graph snapshot JSON: top-N peers by degree + the subgraph of
 * edges between them. Shape:
 *   { "nodes": [ { "id":"ip:port","ip":"..","port":N,"deg":D,
 *                  "v_string":"hex|null","country":"XX|null" } ],
 *     "links": [ { "src":"ip:port","dst":"ip:port" } ] } */
char *db_select_graph_json(int limit);

/* Count of rows in each table (for heartbeat stats). */
int64_t db_count_peers(void);
int64_t db_count_queries(void);
int64_t db_count_infohashes(void);
int64_t db_count_bep44(void);

/* Count of peers whose last_seen is at or after `since_ts`. Used by the web
 * stats endpoint to populate "alive in last N hours" buckets. */
int64_t db_count_peers_since(int64_t since_ts);

/* peer_reputation cache: out-of-process scripts (e.g. the GreyNoise helper)
 * write rows here; the http layer reads at classify time.
 *   ip          TEXT  — same v4/v6 dotted form used in `peers`
 *   source      TEXT  — 'greynoise' / 'iblocklist' / 'tor' / future
 *   label       TEXT  — human-readable, e.g. 'benign:censys', 'malicious'
 *   queried_at  INTEGER unix ts — read paths can age out via `WHERE queried_at > ?`
 * PRIMARY KEY(ip, source) so multiple sources per IP coexist.
 *
 * Local lists (iblocklist, tor) load via reputation.c at boot from flat
 * files — those are NOT mirrored into this table. Only the API-driven
 * GreyNoise side touches it. */
char *db_select_reputation_json(const char *ip);
void  db_upsert_reputation(const char *ip, const char *source,
                           const char *label, int64_t queried_at);
/* Pull up to `max` peers (with last_seen >= since) that DON'T yet have
 * a row in peer_reputation for the given source. Used by the GreyNoise
 * helper to pick what to look up next. Output: ip column only. */
int   db_select_peers_missing_reputation(const char *source, int max,
                                         int64_t since,
                                         char (*out_ips)[64]);

/* Closest-N alive peers of `family` (AF_INET or AF_INET6) by XOR distance to
 * `target`. Considers only rows with a known node_id and last_seen >=
 * fresh_threshold. Returns the count actually filled (<= n_max). Used by the
 * crawler's reseed path: peers we have directly observed talking recently are
 * a much better seed than jech's routing-table snapshot, which can hold
 * long-stale entries that drag down a walk's first few hops. */
int db_select_closest_alive(int family,
                            const uint8_t target[BEP44_NODE_ID_LEN],
                            int64_t fresh_threshold,
                            int n_max,
                            struct sockaddr_storage *out_addrs,
                            int *out_lens,
                            uint8_t (*out_ids)[BEP44_NODE_ID_LEN]);

/* Row shape used by the deny refresh task. Keep packed; the refresh
 * tick stack-allocates an array of these (max 1000) and walks them. */
struct db_peer_signal_row {
    char    ip[64];
    int     port;
    int64_t as_src;          /* derived from edges table */
    int64_t as_dst;          /* derived from edges table */
    int64_t same_ip;         /* number of distinct ports observed on this IP */
    int64_t queries_in;
    int64_t queries_out;
    int     ro;              /* -1 = NULL */
    int     bep42_ok;        /* -1 = NULL */
    int     has_v_string;    /* 0|1 */
};

/* Pull up to `max` peers with last_seen >= since_ts, latest first,
 * along with the edge-derived signals (as_src, as_dst, same_ip) the
 * classifier needs. Caller provides a stack-allocated array. Returns
 * count actually filled (<= max). */
int db_select_peers_with_signals(int max, int64_t since_ts,
                                 struct db_peer_signal_row *out);

/* Liveness sweeper helpers. */
int  db_select_liveness_candidates(int max, int64_t older_than_ts,
                                   struct sockaddr_storage *out, int *out_lens);
void db_mark_pinged(const struct sockaddr *peer, socklen_t peerlen, int64_t ts);

/* Prune peers whose last_seen is older than `older_than_ts`. Returns the
 * number of rows removed. */
int  db_prune_peers_older_than(int64_t older_than_ts);

#endif
