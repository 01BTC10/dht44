#ifndef DHT44_REDACT_H
#define DHT44_REDACT_H

#include <stddef.h>

/*
 * Optional IP-address redaction for the public web/API output. When
 * enabled, every IP serialized into JSON is truncated to its
 * network prefix (IPv4 → /24, IPv6 → /48), keeping ASN and
 * geolocation intact while removing host-level identifiability.
 *
 * Default: ENABLED. The daemon flips it off only when
 * --web-show-full-ips is passed (operator-only mode).
 */

void redact_set_enabled(int on);
int  redact_enabled(void);

/*
 * Format `in` (an IPv4 or IPv6 address in textual form) into `out`,
 * applying redaction iff redact_enabled() is non-zero. The result
 * is "<masked-ip>/<prefix>" when redacting, or `in` verbatim
 * otherwise. Returns 0 on success, -1 if `in` is unparseable or
 * `out_cap` is too small. `out_cap` >= 64 is sufficient for any
 * IPv6 form.
 */
int  redact_ip(const char *in, char *out, size_t out_cap);

#endif
