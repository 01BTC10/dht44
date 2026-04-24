#ifndef DHT44_LOOKUP_H
#define DHT44_LOOKUP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bep44.h"

#define LOOKUP_ALPHA       8        /* in-flight queries per lookup */
#define LOOKUP_TOP_K      20        /* termination: top-k responded (libtorrent uses 20) */
#define LOOKUP_SHORTLIST  64        /* candidate cap */
#define LOOKUP_MAX_VALUES  4        /* keep at most this many distinct values */
#define LOOKUP_MAX_CONCURRENT 8

typedef struct lookup_run lookup_run;

/* A value carried back from a peer. mutable_ != 0 means k/sig/seq are set.
 * Storage is sockaddr_storage so v4 and v6 responders are both representable. */
typedef struct {
    int      mutable_;
    int64_t  seq;
    uint8_t  k[BEP44_PK_LEN];
    uint8_t  sig[BEP44_SIG_LEN];
    uint8_t  v[BEP44_MAX_V];
    size_t   v_len;
    struct sockaddr_storage from;
    socklen_t fromlen;
} lookup_value;

/* A node that responded with a token (so we can subsequently put to it). */
typedef struct {
    struct sockaddr_storage peer;
    socklen_t          peerlen;
    uint8_t            token[64];
    size_t             token_len;
} lookup_token;

/* Completion callback. rc is 0 on success (timed out or top-k done are both
 * "success" in the BEP 44 sense — nothing left to do). */
typedef void (*lookup_cb)(int rc,
                          const lookup_value *values, size_t value_count,
                          const lookup_token *tokens, size_t token_count,
                          void *closure);

/*
 * Start a new lookup. Returns the run handle (heap-allocated, freed by the
 * lookup module after the callback returns) or NULL on failure.
 *
 * dht_wrap_init must have been called first. Up to LOOKUP_MAX_CONCURRENT may
 * be running at once.
 */
lookup_run *lookup_start(const uint8_t target[BEP44_TARGET_LEN],
                         int timeout_ms,
                         lookup_cb cb, void *closure);

/*
 * Advance lookups: checks per-run deadlines and fires completion for any
 * that have expired or fully converged. The wake-up time of the soonest
 * pending deadline (across all active lookups) is written to *next_wake_ms.
 * If nothing is active, *next_wake_ms is set to a large value.
 */
void lookup_tick(int *next_wake_ms);

#endif
