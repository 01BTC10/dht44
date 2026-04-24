#ifndef DHT44_CRAWL_H
#define DHT44_CRAWL_H

#include <stdint.h>

/*
 * Active DHT crawler.
 *
 * Workers pick random 160-bit targets, send find_node queries, and feed all
 * learned peers through the observe pipeline (via the implicit hook in
 * dht_wrap_sendto / dht_wrap_step). Rate-limited globally.
 */

int  crawl_start(int workers, int max_pkts_per_sec);
void crawl_stop(void);

/* Called once per daemon tick to advance worker state. */
void crawl_tick(void);

#endif
