#ifndef DHT44_OBSERVE_H
#define DHT44_OBSERVE_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bencode.h"
#include "bep44.h"
#include "dht_wrap.h"

/*
 * Central observation sink.
 *
 * Enabled by the daemon when --web is passed. If enabled, every KRPC packet
 * the daemon sends or receives is fed through observe_packet, which:
 *   - upserts a row in peers with first/last-seen timestamps,
 *   - appends a row to queries,
 *   - mines out targets / info_hashes into the infohashes table,
 *   - notifies a subscriber (http_ws) via the event sink.
 *
 * All functions are no-ops when !observe_enabled().
 */

enum { OBSERVE_IN = 0, OBSERVE_OUT = 1 };

int  observe_enabled(void);
void observe_set_enabled(int on);

/*
 * Event sink — called by observe_*() whenever something new happens that the
 * WebSocket layer may want to push to subscribed clients. topic is one of
 * "peers" | "queries" | "infohashes" | "bep44". json is a transient pointer
 * (freed after the call); implementations must copy if they defer.
 */
typedef void (*observe_event_cb)(const char *topic, const char *json,
                                 void *closure);
void observe_set_event_sink(observe_event_cb cb, void *closure);

/* Raw packet hook. peek may be NULL (forces our own peek). */
void observe_packet(int dir,
                    const struct sockaddr_in *peer,
                    const uint8_t *buf, size_t len,
                    const dht_wrap_peek *peek);

/* Enrichment from a fully decoded inbound query args dict. */
void observe_query_fields(const struct sockaddr_in *peer,
                          int is_put,
                          const bencode_value *a);

/* RTT sample (milliseconds). Called after a response matches our query. */
void observe_rtt(const struct sockaddr_in *peer, int rtt_ms);

/* BEP 44 item. pk/salt/sig may be NULL for immutable. */
void observe_bep44_item(const uint8_t target[BEP44_TARGET_LEN],
                        int mutable_,
                        const uint8_t *pk, size_t pk_len,
                        const uint8_t *salt, size_t salt_len,
                        int64_t seq,
                        const uint8_t *sig, size_t sig_len,
                        const uint8_t *v, size_t v_len);

#endif
