#ifndef DHT44_DENY_H
#define DHT44_DENY_H

#include <stddef.h>
#include <sys/socket.h>
#include <time.h>

/*
 * In-memory deny list of (ip_string, port) tuples.
 *
 *   * dht_wrap.c packet-receive path consults this between
 *     observe_packet (which keeps logging) and dht_periodic / BEP 44
 *     dispatch — denied peers are recorded for the dashboard but get
 *     no response.
 *   * crawl.c sl_insert and lookup.c shortlist_insert refuse to add
 *     denied peers to outgoing shortlists.
 *
 * Three populating sources:
 *
 *   "reputation"  iBlockList strong-match (anti-P2P operator,
 *                 bogon, honeypot, hijacked, ...). Added inline in
 *                 the receive path on first sight, TTL ~1h.
 *   "rate_limit"  per-IP packet rate exceeded. Added inline by
 *                 the rate counter in dht_wrap.c, TTL ~10min.
 *   "classifier"  class >=monitor in the daemon's behavioural
 *                 classifier. Added by the 60s refresh tick in
 *                 cmd_daemon.c, TTL ~1h.
 *
 * The reason string is a stable interned constant — pointer-stable,
 * no free needed. Callers compare by pointer or strcmp; both work.
 */

/* String constants the caller can compare reason pointers against. */
extern const char *DENY_REASON_REPUTATION;
extern const char *DENY_REASON_RATE_LIMIT;
extern const char *DENY_REASON_CLASSIFIER;

/* Initialise / tear down. Safe to call before / after observe is set up. */
int  deny_init(void);
void deny_shutdown(void);

/* Add (ip, port) with the given reason and TTL. If the entry already
 * exists, extends its expiry to max(current, now+ttl_s) and updates
 * reason if the new one is "stronger" (reputation > classifier > rate_limit). */
void deny_add(const struct sockaddr *peer, socklen_t peerlen,
              const char *reason, int ttl_s);

/* Returns the reason string if the peer is currently denied (entry
 * present and not expired), otherwise NULL. Sub-µs hot path —
 * single hash probe. */
const char *deny_check(const struct sockaddr *peer, socklen_t peerlen);

/* Lazy eviction of expired entries. Called from the daemon main loop
 * (~1 Hz). Cheap when the set is small. */
void deny_tick(time_t now);

/* Stats for /api/stats. by_reason indices map to the three reason
 * constants in this header (rep=0, rate=1, cls=2). out_total can be
 * NULL if the caller only wants per-reason. */
void deny_stats(int *out_total, int out_by_reason[3]);

#endif
