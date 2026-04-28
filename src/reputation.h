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

#endif
