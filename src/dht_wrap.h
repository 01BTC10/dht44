#ifndef DHT44_DHT_WRAP_H
#define DHT44_DHT_WRAP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "bencode.h"

/*
 * Minimal peek of a top-level KRPC dict. Returns 0 on success and fills the
 * three fields with pointers INTO `buf` (no copy). y and t are required;
 * q is optional and left as { NULL, 0 } when absent. Returns -1 if the
 * buffer isn't a valid top-level dict or required fields are missing.
 */
typedef struct {
    const uint8_t *y; size_t y_len;
    const uint8_t *q; size_t q_len;
    const uint8_t *t; size_t t_len;
    const uint8_t *v; size_t v_len;       /* BEP 20 client id, may be NULL */
    int            ro; /* -1 unknown, 0 or 1 if "ro" key present as int */
} dht_wrap_peek;

int dht_wrap_peek_top(const uint8_t *buf, size_t len, dht_wrap_peek *out);

/* ================================================================
 * Wrap lifecycle
 * ================================================================ */

/*
 * Bind a non-blocking AF_INET UDP socket on `port` (0 = ephemeral), load or
 * generate the persistent node_id, and call dht_init. Returns 0 on success.
 *
 * On success, sodium_init() has been invoked (callable repeatedly).
 */
int dht_wrap_init(uint16_t port);

/* Cleanup. Safe to call even if init failed partway. */
void dht_wrap_uninit(void);

/* The bound socket fd, for select(). -1 if not initialised. */
int dht_wrap_socket(void);

/* The 20-byte node ID we registered with jech. */
const uint8_t *dht_wrap_node_id(void);

/* ================================================================
 * Bootstrap helpers
 * ================================================================ */

/*
 * Resolve the four public bootstrap routers and dht_ping_node() each. The
 * pings are fire-and-forget; the routing table populates as responses arrive
 * via subsequent dht_wrap_step calls.
 */
int dht_wrap_ping_routers(void);

/* Insert a saved warm-start node by address. Soft bootstrap: no traffic. */
int dht_wrap_insert_warm(const struct sockaddr_in *sa);

/* Routing-table populations (good / dubious counts, IPv4 only in v1). */
void dht_wrap_status(int *good, int *dubious);

/*
 * Dump up to `max` IPv4 nodes from jech's routing table into `out`. Returns
 * the number written. Used to persist nodes.bin for warm restart.
 */
int dht_wrap_get_nodes(struct sockaddr_in *out, int max);

/*
 * Return up to `max` good IPv4 nodes from jech's routing table, sorted by
 * XOR distance to `target` (closest first). out[i] paired with out_ids[i].
 */
int dht_wrap_closest_to(const uint8_t target[20],
                        struct sockaddr_in *out,
                        uint8_t (*out_ids)[20],
                        int max);

/*
 * Kick off jech's own iterative search toward `target`. Fire-and-forget;
 * jech's internal find_node / get_peers iterations will populate the routing
 * table with peers near the target. Used as a pre-step in lookup_start so
 * subsequent dht_wrap_closest_to calls see a well-populated neighborhood.
 */
int dht_wrap_kick_search(const uint8_t target[20]);

/* ================================================================
 * Event pump
 * ================================================================ */

/*
 * Drive one iteration of the wrap loop:
 *   - If buf != NULL, treat as a freshly recvfrom'd packet from `from`.
 *     Peek for BEP 44 traffic; intercepted packets are dispatched to the
 *     registered handlers and NOT forwarded to dht_periodic. All other
 *     packets are passed to dht_periodic so jech's routing table stays
 *     fresh.
 *   - If buf == NULL, only run periodic processing.
 *
 * Sets *next_wake_ms to the maximum number of ms the caller may sleep before
 * the next dht_wrap_step is required. Returns 0 on success, -1 on a fatal
 * error (caller should uninit).
 */
int dht_wrap_step(const void *buf, size_t buflen,
                  const struct sockaddr *from, int fromlen,
                  int *next_wake_ms);

/* ================================================================
 * Outbound BEP 44 (queries)
 * ================================================================ */

typedef enum {
    BEP44_TX_RESPONSE,   /* peer replied with y="r" */
    BEP44_TX_ERROR,      /* peer replied with y="e" */
    BEP44_TX_TIMEOUT,    /* no reply within deadline */
} bep44_tx_event;

/*
 * Callback fired exactly once per registered tx, on first matching response,
 * matching error, or timeout — whichever comes first.
 *   - r is the parsed `r` sub-dict on RESPONSE (otherwise NULL).
 *   - e is the parsed `e` list on ERROR (otherwise NULL).
 *   - peer is the responding peer (or original peer for timeout).
 * The bencode tree is freed by the wrap after the callback returns; copy
 * anything you need to keep.
 */
typedef void (*bep44_tx_cb)(bep44_tx_event ev,
                            const struct sockaddr *peer, int peerlen,
                            const bencode_value *r,
                            const bencode_value *e,
                            void *closure);

/*
 * Send `packet` to `peer` and remember the transaction id `tid` so the
 * callback fires on a matching response (or after `timeout_ms`). Returns 0
 * on success, -1 on error (table full, send failure).
 */
int dht_wrap_send_query(const struct sockaddr *peer, int peerlen,
                        const void *packet, size_t packet_len,
                        const uint8_t *tid, size_t tid_len,
                        int timeout_ms,
                        bep44_tx_cb cb, void *closure);

/* Generate a fresh 2-byte random transaction id. */
void dht_wrap_random_tid(uint8_t out[2]);

/* Send a packet without registering a callback (e.g. a response we built). */
int dht_wrap_sendto(const struct sockaddr *peer, int peerlen,
                    const void *packet, size_t packet_len);

/* ================================================================
 * Inbound BEP 44 (queries) — handler installed by the daemon
 * ================================================================ */

typedef void (*bep44_query_cb)(const struct sockaddr *peer, int peerlen,
                               const uint8_t *tid, size_t tid_len,
                               int is_put,
                               const bencode_value *a,
                               void *closure);

void dht_wrap_set_query_handler(bep44_query_cb cb, void *closure);

#endif
