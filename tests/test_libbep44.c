/*
 * Public API smoke tests. No live network — these exercise just the
 * crypto, key, target, and lifecycle calls that don't require talking
 * to the DHT.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <sodium.h>

#include "libbep44.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

static char tmpdir[64];

static void
setup_tmp(void)
{
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/libbep44_test_XXXXXX");
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        exit(2);
    }
}

static void
rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

/* ------------------------------------------------------------ */

static void
test_keygen_produces_valid_pair(void)
{
    bep44_keypair_t kp;
    EXPECT(bep44_keygen(&kp) == 0);

    /* Sign + verify a sample message via raw libsodium, using only the
     * keypair the library produced. If pk doesn't match sk, this fails. */
    const char msg[] = "smoke";
    unsigned char sig[crypto_sign_BYTES];
    EXPECT(crypto_sign_detached(sig, NULL,
                                (const unsigned char *)msg, sizeof(msg) - 1,
                                kp.sk) == 0);
    EXPECT(crypto_sign_verify_detached(sig,
                                       (const unsigned char *)msg, sizeof(msg) - 1,
                                       kp.pk) == 0);
}

static void
test_keypair_from_sk_recovers_pk(void)
{
    bep44_keypair_t a, b;
    EXPECT(bep44_keygen(&a) == 0);
    EXPECT(bep44_keypair_from_sk(&b, a.sk) == 0);
    EXPECT(memcmp(a.pk, b.pk, BEP44_PK_LEN) == 0);
    EXPECT(memcmp(a.sk, b.sk, BEP44_SK_LEN) == 0);
}

static void
test_save_load_roundtrip(void)
{
    char path[128];
    snprintf(path, sizeof(path), "%s/key.json", tmpdir);

    bep44_keypair_t saved;
    EXPECT(bep44_keygen(&saved) == 0);
    EXPECT(bep44_save_key(path, &saved) == 0);

    /* Mode should be 0600 — keyfiles carry secret material. */
    struct stat st;
    EXPECT(stat(path, &st) == 0);
    EXPECT((st.st_mode & 0777) == 0600);

    bep44_keypair_t loaded;
    EXPECT(bep44_load_key(path, &loaded) == 0);
    EXPECT(memcmp(saved.sk, loaded.sk, BEP44_SK_LEN) == 0);
    EXPECT(memcmp(saved.pk, loaded.pk, BEP44_PK_LEN) == 0);
}

static void
test_target_mutable_matches_sha1_pk_salt(void)
{
    /* Spec: target = SHA1(pk || salt). Verify against a direct EVP SHA-1. */
    bep44_keypair_t kp;
    EXPECT(bep44_keygen(&kp) == 0);

    const char salt[] = "saltA";
    uint8_t got[BEP44_TARGET_LEN];
    EXPECT(bep44_target_mutable(kp.pk, salt, sizeof(salt) - 1, got) == 0);

    uint8_t expected[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int el = 0;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, kp.pk, BEP44_PK_LEN);
    EVP_DigestUpdate(ctx, salt, sizeof(salt) - 1);
    EVP_DigestFinal_ex(ctx, expected, &el);
    EVP_MD_CTX_free(ctx);

    EXPECT(memcmp(got, expected, 20) == 0);

    /* Empty salt → SHA1(pk only) */
    uint8_t got_empty[BEP44_TARGET_LEN];
    EXPECT(bep44_target_mutable(kp.pk, NULL, 0, got_empty) == 0);

    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx2, kp.pk, BEP44_PK_LEN);
    EVP_DigestFinal_ex(ctx2, expected, &el);
    EVP_MD_CTX_free(ctx2);
    EXPECT(memcmp(got_empty, expected, 20) == 0);
}

static void
test_target_immutable_matches_sha1_v(void)
{
    const uint8_t v[] = "5:hello";   /* bencoded */
    uint8_t got[BEP44_TARGET_LEN];
    EXPECT(bep44_target_immutable(v, sizeof(v) - 1, got) == 0);

    uint8_t expected[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int el = 0;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, v, sizeof(v) - 1);
    EVP_DigestFinal_ex(ctx, expected, &el);
    EVP_MD_CTX_free(ctx);

    EXPECT(memcmp(got, expected, 20) == 0);
}

static void
test_open_close_cycle(void)
{
    /* open with bootstrap_routers=0 to avoid hitting the network */
    bep44_opts_t opts = {
        .port = 0,                  /* OS-assigned ephemeral */
        .state_dir = tmpdir,
        .bootstrap_routers = 0,
    };
    bep44_ctx_t *ctx = bep44_open(&opts);
    EXPECT(ctx != NULL);
    if (!ctx) return;

    int fd = bep44_fd(ctx);
    EXPECT(fd >= 0);

    /* second open in the same process must fail */
    bep44_ctx_t *ctx2 = bep44_open(&opts);
    EXPECT(ctx2 == NULL);

    /* step shouldn't crash even with no bootstrap */
    EXPECT(bep44_step(ctx, 10) == 0);
    EXPECT(bep44_good_nodes(ctx) >= 0);

    bep44_close(ctx);

    /* after close, open should work again */
    bep44_ctx_t *ctx3 = bep44_open(&opts);
    EXPECT(ctx3 != NULL);
    if (ctx3) bep44_close(ctx3);
}

static void
test_input_validation(void)
{
    bep44_keypair_t kp;
    EXPECT(bep44_keygen(&kp) == 0);

    uint8_t target[BEP44_TARGET_LEN];

    /* salt > BEP44_SALT_MAX rejected */
    char big_salt[BEP44_SALT_MAX + 1];
    memset(big_salt, 'x', sizeof(big_salt));
    EXPECT(bep44_target_mutable(kp.pk, big_salt, sizeof(big_salt), target) == -1);

    /* v > BEP44_VALUE_MAX rejected */
    uint8_t big_v[BEP44_VALUE_MAX + 1];
    memset(big_v, 'x', sizeof(big_v));
    EXPECT(bep44_target_immutable(big_v, sizeof(big_v), target) == -1);

    /* NULL inputs rejected */
    EXPECT(bep44_target_mutable(NULL, NULL, 0, target) == -1);
    EXPECT(bep44_target_immutable(NULL, 0, target) == -1);
    EXPECT(bep44_keygen(NULL) == -1);
    EXPECT(bep44_keypair_from_sk(NULL, kp.sk) == -1);
    EXPECT(bep44_keypair_from_sk(&kp, NULL) == -1);
}

int
main(void)
{
    setup_tmp();

    test_keygen_produces_valid_pair();
    test_keypair_from_sk_recovers_pk();
    test_save_load_roundtrip();
    test_target_mutable_matches_sha1_pk_salt();
    test_target_immutable_matches_sha1_v();
    test_open_close_cycle();
    test_input_validation();

    rm_rf(tmpdir);

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    printf("ok: libbep44 (public API smoke)\n");
    return 0;
}
