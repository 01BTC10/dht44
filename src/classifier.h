#ifndef DHT44_CLASSIFIER_H
#define DHT44_CLASSIFIER_H

#include <stdint.h>

/*
 * Behavioural classifier for observed DHT peers.
 *
 * Single source of truth for the score / class taxonomy. Two callers:
 *
 *   - http_ws.c classify_peer(): JSON adaptor for /api/peers etc.
 *     Reads fields off the per-peer json_t row, populates a
 *     peer_signals, calls classify_compute(), writes the result back
 *     onto the row as crawler_score / crawler_class / crawler_signals
 *     / crawler_reason / likely_crawler / reputation.
 *
 *   - cmd_daemon.c deny refresh tick: takes peer_signals straight
 *     from the DB, calls classify_compute(), deny_add()s peers in
 *     class honeypot or monitor.
 *
 * Both call sites must agree on the score and class for the same
 * peer; this header is the contract. To tune, change one place.
 */

/* Per-peer inputs the classifier needs. -1 in the optional integer
 * fields means "unknown / NULL in DB". String fields may be NULL. */
struct peer_signals {
    int64_t as_src;          /* count of edges where this peer was source */
    int64_t as_dst;          /* count of edges where this peer was dest */
    int64_t same_ip;         /* peers sharing this IP (different ports) */
    int64_t queries_in;
    int64_t queries_out;
    int     ro;              /* -1 unknown, 0 no, 1 yes (BEP 5 ro flag) */
    int     bep42_ok;        /* -1 unknown, 0 fail, 1 ok */
    int     has_v_string;    /* 0 = no client identifier, 1 = present */
    const char *asn_org;     /* may be NULL */
    /* Pre-fetched reputation. classify_compute does NOT call
     * reputation_lookup itself — caller must do that and pass the
     * result through. (NULL source/label = no reputation hit.) */
    const char *rep_source;
    const char *rep_label;
    int     gn_malicious;    /* greynoise:malicious from peer_reputation */
    int     gn_benign;       /* greynoise:benign:* from peer_reputation */
};

/* Maximum number of distinct signals + reason chunks one peer can carry.
 * Large enough for current rule set with margin. */
#define CLASSIFY_MAX_SIGNALS 16
#define CLASSIFY_REASON_CAP  1024
#define CLASSIFY_SIG_CAP     160

struct classify_result {
    int    score;
    /* Class label as a stable string constant — caller compares by
     * pointer or strcmp. One of: "ok", "seedbox", "crawler",
     * "monitor", "honeypot". */
    const char *cls;
    int    n_signals;
    /* Each signal is a short tag; some carry a ":argument" suffix
     * (e.g. "monitor_asn:Trident Media Guard"). */
    char   signals[CLASSIFY_MAX_SIGNALS][CLASSIFY_SIG_CAP];
    /* Human-readable explanation, ' · '-separated. */
    char   reason[CLASSIFY_REASON_CAP];
};

void classify_compute(const struct peer_signals *in,
                      struct classify_result *out);

#endif
