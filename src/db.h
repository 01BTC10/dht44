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
 * 'o', or 0 for no bump. */
void db_upsert_peer(const struct sockaddr_in *peer,
                    const uint8_t node_id[BEP44_NODE_ID_LEN], int has_node_id,
                    const uint8_t *v_string, size_t v_len,
                    int ro /* 0|1|-1 */,
                    int bep42_ok /* 0|1|-1 */,
                    int rtt_ms /* -1 for none */,
                    char direction /* 'i'|'o'|0 */);

/* Append a query-log row. target may be NULL. q may be NULL for responses. */
void db_insert_query(int64_t ts,
                     const struct sockaddr_in *peer,
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

/* Count of rows in each table (for heartbeat stats). */
int64_t db_count_peers(void);
int64_t db_count_queries(void);
int64_t db_count_infohashes(void);
int64_t db_count_bep44(void);

#endif
