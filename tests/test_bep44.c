#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "bencode.h"
#include "bep44.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

static void
hex(char *out, const uint8_t *bytes, size_t len)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = d[bytes[i] >> 4];
        out[i * 2 + 1] = d[bytes[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static void
expect_hex(const char *what, const uint8_t *bytes, size_t len, const char *want)
{
    char got[64];
    hex(got, bytes, len);
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s:\n  want: %s\n  got:  %s\n", what, want, got);
        failures++;
    }
}

static void
expect_bytes(const char *what, const uint8_t *got, size_t got_len,
             const char *want, size_t want_len)
{
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        fprintf(stderr, "FAIL %s: bytes mismatch\n  want (%zu): ", what, want_len);
        for (size_t i = 0; i < want_len; i++) fprintf(stderr, "%02x", (unsigned char)want[i]);
        fprintf(stderr, "\n  got  (%zu): ", got_len);
        for (size_t i = 0; i < got_len; i++) fprintf(stderr, "%02x", got[i]);
        fputc('\n', stderr);
        failures++;
    }
}

/* SHA-1 fixtures (computed with python3 hashlib):
 *   sha1(b'A'*32)            = 43d83b2e816a89cac876f16530b0b625585c8160
 *   sha1(b'A'*32 + b'foo')   = 43a153765e3d4c0ccab204bca192bef90d5a435b
 *   sha1(b'5:hello')         = e28910ea0adb94dd45ced75fbff3e135c01bc437
 */

static void
test_target_no_salt(void)
{
    uint8_t pk[32];
    memset(pk, 'A', sizeof(pk));
    uint8_t out[20];
    bep44_target(out, pk, NULL, 0);
    expect_hex("target no salt", out, 20, "43d83b2e816a89cac876f16530b0b625585c8160");
}

static void
test_target_with_salt(void)
{
    uint8_t pk[32];
    memset(pk, 'A', sizeof(pk));
    uint8_t out[20];
    bep44_target(out, pk, (const uint8_t *)"foo", 3);
    expect_hex("target with salt foo", out, 20,
               "43a153765e3d4c0ccab204bca192bef90d5a435b");
}

static void
test_immutable_target(void)
{
    uint8_t out[20];
    bep44_immutable_target(out, (const uint8_t *)"5:hello", 7);
    expect_hex("immutable target of 5:hello", out, 20,
               "e28910ea0adb94dd45ced75fbff3e135c01bc437");
}

static void
test_signable_with_salt(void)
{
    uint8_t out[64];
    ssize_t n = bep44_signable(out, sizeof(out),
                               (const uint8_t *)"foo", 3,
                               5,
                               (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);
    expect_bytes("signable salt=foo seq=5 v=5:hello", out, (size_t)n,
                 "4:salt3:foo3:seqi5e1:v5:hello", 29);
}

static void
test_signable_no_salt(void)
{
    uint8_t out[64];
    ssize_t n = bep44_signable(out, sizeof(out),
                               NULL, 0,
                               1,
                               (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);
    expect_bytes("signable no salt seq=1", out, (size_t)n,
                 "3:seqi1e1:v5:hello", 18);
}

static void
test_signable_oversize_rejected(void)
{
    uint8_t out[2048];
    uint8_t big_v[1100];
    memset(big_v, 'x', sizeof(big_v));
    EXPECT(bep44_signable(out, sizeof(out), NULL, 0, 1, big_v, sizeof(big_v)) == -1);

    uint8_t big_salt[100];
    memset(big_salt, 's', sizeof(big_salt));
    EXPECT(bep44_signable(out, sizeof(out), big_salt, sizeof(big_salt), 1,
                          (const uint8_t *)"1:x", 3) == -1);
}

static void
test_sign_verify_roundtrip(void)
{
    uint8_t seed[crypto_sign_SEEDBYTES];
    memset(seed, 0xa5, sizeof(seed));
    uint8_t pk[BEP44_PK_LEN], sk[BEP44_SK_LEN];
    crypto_sign_seed_keypair(pk, sk, seed);

    uint8_t signable[64];
    ssize_t slen = bep44_signable(signable, sizeof(signable),
                                  (const uint8_t *)"foo", 3, 7,
                                  (const uint8_t *)"5:hello", 7);
    EXPECT(slen > 0);

    uint8_t sig[BEP44_SIG_LEN];
    EXPECT(bep44_sign(sig, sk, signable, (size_t)slen) == 0);
    EXPECT(bep44_verify(sig, pk, signable, (size_t)slen) == 0);

    /* tamper signature → verify must fail */
    sig[0] ^= 0x01;
    EXPECT(bep44_verify(sig, pk, signable, (size_t)slen) == -1);
    sig[0] ^= 0x01;

    /* tamper signable → verify must fail */
    signable[(size_t)slen - 1] ^= 0x01;
    EXPECT(bep44_verify(sig, pk, signable, (size_t)slen) == -1);
}

/*
 * KRPC builders: we don't byte-compare against a hardcoded oracle here
 * (deferred to live integration testing against bittorrent-dht). Instead we
 * decode the output and assert all expected fields are present, in the
 * documented order, with correct values.
 */

static void
expect_dict_key_order(const bencode_value *d, const char **keys, size_t n,
                      const char *what)
{
    EXPECT(d != NULL && d->type == BENCODE_DICT);
    if (!d || d->type != BENCODE_DICT) return;
    if (d->dict.len != n) {
        fprintf(stderr, "FAIL %s: expected %zu keys, got %zu\n",
                what, n, d->dict.len);
        failures++;
        return;
    }
    for (size_t i = 0; i < n; i++) {
        size_t kl = strlen(keys[i]);
        if (d->dict.entries[i].key_len != kl
            || memcmp(d->dict.entries[i].key, keys[i], kl) != 0) {
            char k[64] = {0};
            size_t copy = d->dict.entries[i].key_len < 63
                          ? d->dict.entries[i].key_len : 63;
            memcpy(k, d->dict.entries[i].key, copy);
            fprintf(stderr, "FAIL %s: key[%zu] expected '%s' got '%s'\n",
                    what, i, keys[i], k);
            failures++;
        }
    }
}

static void
test_build_get_query(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t target[20]; memset(target, 'T', 20);
    uint8_t tid[2] = { 0x12, 0x34 };

    uint8_t out[256];
    ssize_t n = bep44_build_get_query(out, sizeof(out),
                                      tid, sizeof(tid),
                                      our_id, target, NULL);
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(out, (size_t)n, &a);
    EXPECT(v != NULL);
    if (!v) return;

    const char *outer[] = { "a", "q", "t", "y" };
    expect_dict_key_order(v, outer, 4, "get query outer");

    const bencode_value *aa = bencode_dict_get(v, "a");
    const char *inner[] = { "id", "target" };
    expect_dict_key_order(aa, inner, 2, "get query a");

    const bencode_value *q = bencode_dict_get(v, "q");
    EXPECT(q && q->type == BENCODE_STR && q->str.len == 3
           && memcmp(q->str.bytes, "get", 3) == 0);
    const bencode_value *y = bencode_dict_get(v, "y");
    EXPECT(y && y->type == BENCODE_STR && y->str.len == 1 && y->str.bytes[0] == 'q');

    bencode_free(a);
}

static void
test_build_put_query_mutable(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t pk[32];     memset(pk, 'K', 32);
    uint8_t sig[64];    memset(sig, 'S', 64);
    uint8_t tok[8];     memset(tok, 't', 8);
    uint8_t tid[2] = { 0xab, 0xcd };

    uint8_t out[512];
    ssize_t n = bep44_build_put_query_mutable(out, sizeof(out),
                                              tid, sizeof(tid),
                                              our_id, pk,
                                              (const uint8_t *)"foo", 3,
                                              42, NULL, sig,
                                              tok, sizeof(tok),
                                              (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(out, (size_t)n, &a);
    EXPECT(v != NULL);
    if (!v) return;

    const char *outer[] = { "a", "q", "t", "y" };
    expect_dict_key_order(v, outer, 4, "put query outer");

    const bencode_value *aa = bencode_dict_get(v, "a");
    const char *inner[] = { "id", "k", "salt", "seq", "sig", "token", "v" };
    expect_dict_key_order(aa, inner, 7, "put query a");

    const bencode_value *seq = bencode_dict_get(aa, "seq");
    EXPECT(seq && seq->type == BENCODE_INT && seq->i == 42);

    bencode_free(a);
}

static void
test_build_put_query_mutable_with_cas(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t pk[32];     memset(pk, 'K', 32);
    uint8_t sig[64];    memset(sig, 'S', 64);
    uint8_t tok[8];     memset(tok, 't', 8);
    uint8_t tid[2] = { 0xab, 0xcd };
    int64_t cas = 41;

    uint8_t out[512];
    ssize_t n = bep44_build_put_query_mutable(out, sizeof(out),
                                              tid, sizeof(tid),
                                              our_id, pk,
                                              NULL, 0,            /* no salt */
                                              42, &cas, sig,
                                              tok, sizeof(tok),
                                              (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(out, (size_t)n, &a);
    EXPECT(v != NULL);
    if (!v) return;

    const bencode_value *aa = bencode_dict_get(v, "a");
    const char *inner[] = { "cas", "id", "k", "seq", "sig", "token", "v" };
    expect_dict_key_order(aa, inner, 7, "put query a (cas, no salt)");

    const bencode_value *cas_v = bencode_dict_get(aa, "cas");
    EXPECT(cas_v && cas_v->type == BENCODE_INT && cas_v->i == 41);

    bencode_free(a);
}

static void
test_build_put_query_immutable(void)
{
    uint8_t our_id[20]; memset(our_id, 'I', 20);
    uint8_t tok[8];     memset(tok, 't', 8);
    uint8_t tid[2] = { 0xab, 0xcd };

    uint8_t out[256];
    ssize_t n = bep44_build_put_query_immutable(out, sizeof(out),
                                                tid, sizeof(tid),
                                                our_id,
                                                tok, sizeof(tok),
                                                (const uint8_t *)"5:hello", 7);
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(out, (size_t)n, &a);
    EXPECT(v != NULL);
    if (!v) return;

    const bencode_value *aa = bencode_dict_get(v, "a");
    const char *inner[] = { "id", "token", "v" };
    expect_dict_key_order(aa, inner, 3, "put query a (immutable)");

    bencode_free(a);
}

static void
test_build_error(void)
{
    uint8_t tid[2] = { 0xab, 0xcd };
    uint8_t out[128];
    ssize_t n = bep44_build_error(out, sizeof(out), tid, sizeof(tid),
                                  301, "CAS mismatch");
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(out, (size_t)n, &a);
    EXPECT(v != NULL);
    if (!v) return;

    const char *outer[] = { "e", "t", "y" };
    expect_dict_key_order(v, outer, 3, "error outer");

    const bencode_value *e = bencode_dict_get(v, "e");
    EXPECT(e && e->type == BENCODE_LIST && e->list.len == 2);
    EXPECT(e->list.items[0]->type == BENCODE_INT && e->list.items[0]->i == 301);
    EXPECT(e->list.items[1]->type == BENCODE_STR
           && e->list.items[1]->str.len == 12
           && memcmp(e->list.items[1]->str.bytes, "CAS mismatch", 12) == 0);

    const bencode_value *y = bencode_dict_get(v, "y");
    EXPECT(y && y->type == BENCODE_STR && y->str.len == 1 && y->str.bytes[0] == 'e');

    bencode_free(a);
}

int
main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 2;
    }

    test_target_no_salt();
    test_target_with_salt();
    test_immutable_target();
    test_signable_with_salt();
    test_signable_no_salt();
    test_signable_oversize_rejected();
    test_sign_verify_roundtrip();
    test_build_get_query();
    test_build_put_query_mutable();
    test_build_put_query_mutable_with_cas();
    test_build_put_query_immutable();
    test_build_error();

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: bep44\n", stderr);
    return 0;
}
