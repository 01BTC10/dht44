#ifndef DHT44_REPUTATION_H
#define DHT44_REPUTATION_H

#include <stdint.h>
#include <sys/socket.h>

/*
 * Reputation lookups against community-maintained range lists.
 *
 *   * iBlockList .p2p — "Description:start_ip-end_ip" per line, v4 only
 *     in practice. Sourced as bt_level1 (the BitTorrent-monitoring
 *     subset) refreshed daily by deploy/systemd/dht44-reputation.timer.
 *
 *   * Tor exit list — one IP per line, mixed v4/v6, refreshed daily
 *     from check.torproject.org/torbulkexitlist.
 *
 * On lookup the module returns the most-restrictive hit (iblocklist
 * before tor since iblocklist labels are usually more specific). All
 * label / source strings live in interned pools so the per-row return
 * is just two pointers — safe to share across threads, stable until
 * the next reload.
 *
 * Reload at runtime is not implemented in v1 — the daemon's
 * single-threaded select loop holds these read-only and the refresh
 * script restarts the daemon after writing new files.
 */

/* Load every supported file under `dir` (e.g. /var/lib/dht44/reputation/).
 * Missing files are silently skipped with a one-line log. Supported
 * filenames: bt_level1.p2p, tor-exits.txt. Returns 0 on success;
 * negative on hard error (e.g. dir present but unreadable). */
int reputation_load_dir(const char *dir);

/* Empty all loaded ranges and free memory. Safe to call when nothing
 * is loaded. */
void reputation_clear(void);

/* Lookup an IP. addr must be a sockaddr_in or sockaddr_in6 (port
 * ignored). Returns 0 with *out_source / *out_label NULL if no hit;
 * 1 with both pointing into the interned pool on hit.
 *
 * Both pointers stay valid until reputation_clear() is called. */
int reputation_lookup(const struct sockaddr *addr,
                      const char **out_source,
                      const char **out_label);

/* Counts for /api/stats. */
int reputation_iblocklist_count(void);
int reputation_tor_count(void);

/* "Strong" classification of a (source, label) pair — i.e. should this
 * hit alone justify denying the peer outright?
 *
 * For source="iblocklist" returns 1 when label starts with one of the
 *   strong category prefixes (AP2P, Anti-P2P, Bogon, Honeypot,
 *   Hijacked, Spider, Brute Force, Spambot) OR contains a known
 *   anti-P2P operator name (MarkMonitor, IP Echelon, Irdeto, Trident
 *   Media Guard, etc.).
 * For source="greynoise" returns 1 when label starts with "malicious".
 * For source="tor" returns 0 — Tor exits are tagged but not denied
 *   on sight; the rate limiter and classifier handle them if they
 *   misbehave.
 *
 * Used in two places: http_ws.c classify_peer (where the strong-hit
 * adds +3 score) and dht_wrap.c packet-receive path (where the
 * strong-hit causes deny_add). Same rule, one source of truth. */
int reputation_label_is_strong(const char *source, const char *label);

#endif
