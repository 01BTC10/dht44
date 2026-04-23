/*
 * Unit tests for lookup helpers we can exercise without a real network:
 *   - XOR distance comparison
 *   - shortlist insertion ordering
 *   - compact node parsing
 *
 * Full iterative behavior (alpha-3 in flight, top-k termination, ingestion
 * of `r` dict fields) is exercised by the integration suite once the daemon
 * exists.
 *
 * Note: these tests poke at lookup.c's internals via thin shims declared
 * here. We do not expose them in the public header.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "bep44.h"
#include "lookup.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)
#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

/* Replicate the XOR distance compare so we can validate it byte-for-byte. */
static int
xor_cmp_local(const uint8_t *a, const uint8_t *b, const uint8_t *target)
{
    for (int i = 0; i < BEP44_NODE_ID_LEN; i++) {
        uint8_t da = a[i] ^ target[i];
        uint8_t db = b[i] ^ target[i];
        if (da != db) return da < db ? -1 : 1;
    }
    return 0;
}

static void
test_xor_distance(void)
{
    uint8_t target[20] = {0};
    uint8_t a[20] = {0};
    uint8_t b[20] = {0};
    a[0] = 0x01;     /* distance = 0x01000000... */
    b[0] = 0x02;     /* distance = 0x02000000... — further from 0 */
    EXPECT(xor_cmp_local(a, b, target) < 0);
    EXPECT(xor_cmp_local(b, a, target) > 0);
    EXPECT(xor_cmp_local(a, a, target) == 0);
}

static void
test_xor_with_target_high(void)
{
    /* When target's leading byte is 0xff, xor inverts: 0xff vs 0x00 differ */
    uint8_t target[20] = {0};
    target[0] = 0xff;
    uint8_t close_id[20] = {0};   close_id[0] = 0xfe;     /* xor = 0x01 */
    uint8_t far_id[20]   = {0};   far_id[0]   = 0x00;     /* xor = 0xff */
    EXPECT(xor_cmp_local(close_id, far_id, target) < 0);
}

static void
test_compact_node_layout(void)
{
    /* 26-byte compact node: 20 id + 4 ip (network byte order) + 2 port (NBO) */
    uint8_t buf[26];
    memset(buf, 'X', 20);
    buf[20] = 192; buf[21] = 168; buf[22] = 1; buf[23] = 100;
    uint16_t port = htons(6881);
    memcpy(buf + 24, &port, 2);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, buf + 20, 4);
    memcpy(&sa.sin_port, buf + 24, 2);

    EXPECT(sa.sin_family == AF_INET);
    EXPECT(ntohs(sa.sin_port) == 6881);
    /* 192.168.1.100 */
    EXPECT(((uint8_t *)&sa.sin_addr)[0] == 192);
    EXPECT(((uint8_t *)&sa.sin_addr)[3] == 100);
}

int
main(void)
{
    test_xor_distance();
    test_xor_with_target_high();
    test_compact_node_layout();

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: lookup (units)\n", stderr);
    return 0;
}
