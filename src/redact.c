/*
 * IP-address redaction for the public web/API output. See redact.h.
 */

#include "redact.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Default ON. Operator can flip via --web-show-full-ips. */
static int s_enabled = 1;

void redact_set_enabled(int on) { s_enabled = on ? 1 : 0; }
int  redact_enabled(void)       { return s_enabled; }

int
redact_ip(const char *in, char *out, size_t out_cap)
{
    if (!in || !out || out_cap < 64) return -1;

    if (!s_enabled) {
        size_t n = strlen(in);
        if (n + 1 > out_cap) return -1;
        memcpy(out, in, n + 1);
        return 0;
    }

    /* Try IPv4 first; fall back to IPv6. */
    struct in_addr v4;
    if (inet_pton(AF_INET, in, &v4) == 1) {
        /* /24 — zero the last byte */
        unsigned char *b = (unsigned char *)&v4.s_addr;
        b[3] = 0;
        char tmp[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &v4, tmp, sizeof(tmp))) return -1;
        int n = snprintf(out, out_cap, "%s/24", tmp);
        return (n > 0 && (size_t)n < out_cap) ? 0 : -1;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, in, &v6) == 1) {
        /* /48 — zero everything past the first 6 bytes */
        memset(((unsigned char *)&v6) + 6, 0, 16 - 6);
        char tmp[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &v6, tmp, sizeof(tmp))) return -1;
        int n = snprintf(out, out_cap, "%s/48", tmp);
        return (n > 0 && (size_t)n < out_cap) ? 0 : -1;
    }

    return -1;
}
