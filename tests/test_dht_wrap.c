/*
 * Unit tests for dht_wrap_peek_top — the only piece of dht_wrap that's
 * meaningfully testable in isolation. Init/bootstrap/loop is exercised by
 * the integration suite.
 */

#include <stdio.h>
#include <string.h>

#include "bencode.h"
#include "bep44.h"
#include "dht_wrap.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

static void
test_peek_query(void)
{
    /* d1:ad2:id20:AAAAAAAAAAAAAAAAAAAA6:target20:BBBBBBBBBBBBBBBBBBBBe
       1:q3:get1:t2:\x12\x341:y1:qe */
    uint8_t our_id[20]; memset(our_id, 'A', 20);
    uint8_t target[20]; memset(target, 'B', 20);
    uint8_t tid[2] = { 0x12, 0x34 };

    uint8_t buf[256];
    ssize_t n = bep44_build_get_query(buf, sizeof(buf),
                                      tid, sizeof(tid),
                                      our_id, target, NULL);
    EXPECT(n > 0);

    dht_wrap_peek p;
    EXPECT(dht_wrap_peek_top(buf, (size_t)n, &p) == 0);
    EXPECT(p.y_len == 1 && p.y[0] == 'q');
    EXPECT(p.q_len == 3 && memcmp(p.q, "get", 3) == 0);
    EXPECT(p.t_len == 2 && p.t[0] == 0x12 && p.t[1] == 0x34);
}

static void
test_peek_put_query(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t pk[32];     memset(pk, 'K', 32);
    uint8_t sig[64];    memset(sig, 'S', 64);
    uint8_t tok[8];     memset(tok, 't', 8);
    uint8_t tid[2] = { 0xab, 0xcd };

    uint8_t buf[512];
    ssize_t n = bep44_build_put_query_mutable(buf, sizeof(buf),
                                              tid, sizeof(tid),
                                              our_id, pk, NULL, 0,
                                              42, NULL, sig,
                                              tok, sizeof(tok),
                                              (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);

    dht_wrap_peek p;
    EXPECT(dht_wrap_peek_top(buf, (size_t)n, &p) == 0);
    EXPECT(p.q_len == 3 && memcmp(p.q, "put", 3) == 0);
    EXPECT(p.y_len == 1 && p.y[0] == 'q');
}

static void
test_peek_response(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t tid[2] = { 0xff, 0x00 };

    uint8_t buf[256];
    ssize_t n = bep44_build_put_response(buf, sizeof(buf),
                                         tid, sizeof(tid), our_id);
    EXPECT(n > 0);

    dht_wrap_peek p;
    EXPECT(dht_wrap_peek_top(buf, (size_t)n, &p) == 0);
    EXPECT(p.y_len == 1 && p.y[0] == 'r');
    EXPECT(p.q == NULL && p.q_len == 0);    /* responses have no q */
    EXPECT(p.t_len == 2 && p.t[0] == 0xff && p.t[1] == 0x00);
}

static void
test_peek_error(void)
{
    uint8_t tid[2] = { 0xab, 0xcd };
    uint8_t buf[128];
    ssize_t n = bep44_build_error(buf, sizeof(buf), tid, sizeof(tid),
                                  301, "CAS mismatch");
    EXPECT(n > 0);

    dht_wrap_peek p;
    EXPECT(dht_wrap_peek_top(buf, (size_t)n, &p) == 0);
    EXPECT(p.y_len == 1 && p.y[0] == 'e');
}

static void
test_peek_reject_garbage(void)
{
    dht_wrap_peek p;
    /* not a dict */
    EXPECT(dht_wrap_peek_top((const uint8_t *)"l3:fooe", 7, &p) == -1);
    /* truncated */
    EXPECT(dht_wrap_peek_top((const uint8_t *)"d1:y1:q", 7, &p) == -1);
    /* missing y */
    EXPECT(dht_wrap_peek_top((const uint8_t *)"d1:t2:abe", 9, &p) == -1);
    /* empty */
    EXPECT(dht_wrap_peek_top((const uint8_t *)"", 0, &p) == -1);
    /* lone 'd' */
    EXPECT(dht_wrap_peek_top((const uint8_t *)"d", 1, &p) == -1);
}

int
main(void)
{
    test_peek_query();
    test_peek_put_query();
    test_peek_response();
    test_peek_error();
    test_peek_reject_garbage();

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: dht_wrap (peek)\n", stderr);
    return 0;
}
