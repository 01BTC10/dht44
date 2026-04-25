#ifndef DHT44_LIVENESS_H
#define DHT44_LIVENESS_H

#include <stdint.h>

/*
 * Liveness sweeper + pruner.
 *
 * Walks the peers table at a paced rate so every peer gets re-pinged within
 * `window_hours`. Each ping uses jech's dht_ping_node (a normal BEP 5 ping);
 * the response naturally flows through the daemon's recvfrom loop and bumps
 * `last_seen` via the observe pipeline, while `last_pinged` is updated here
 * to space out future probes for that peer.
 *
 * On a separate slower cadence, prunes peers whose `last_seen` predates
 * `prune_days` ago — they're presumed permanently offline.
 */

void liveness_start(int window_hours, int max_pps, int prune_days);
void liveness_stop(void);

/* Drive the sweeper from the daemon event loop. Cheap when not due. */
void liveness_tick(void);

#endif
