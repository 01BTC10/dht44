#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "bep44.h"
#include "commands.h"
#include "state.h"

static const char USAGE_KEYGEN[] = "usage: dht44 keygen -o KEYFILE\n";
static const char USAGE_PUBKEY[] = "usage: dht44 pubkey -k KEYFILE\n";
static const char USAGE_TARGET[] = "usage: dht44 target -k KEYFILE [--salt S]\n";

static int
init_sodium(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "[dht44:cmd_key] sodium_init failed\n");
        return -1;
    }
    return 0;
}

static void
print_hex(const uint8_t *bytes, size_t len)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(d[bytes[i] >> 4]);
        putchar(d[bytes[i] & 0xf]);
    }
    putchar('\n');
}

int
cmd_keygen(int argc, char **argv)
{
    const char *out_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            fputs(USAGE_KEYGEN, stderr);
            return 1;
        }
    }
    if (!out_path) {
        fputs(USAGE_KEYGEN, stderr);
        return 1;
    }
    if (init_sodium() < 0) return 2;

    uint8_t pk[BEP44_PK_LEN], sk[BEP44_SK_LEN];
    crypto_sign_keypair(pk, sk);

    int rc = 0;
    if (state_save_key(out_path, sk) < 0) {
        rc = 2;
    }
    sodium_memzero(sk, sizeof(sk));
    return rc;
}

int
cmd_pubkey(int argc, char **argv)
{
    const char *key_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else {
            fputs(USAGE_PUBKEY, stderr);
            return 1;
        }
    }
    if (!key_path) {
        fputs(USAGE_PUBKEY, stderr);
        return 1;
    }
    if (init_sodium() < 0) return 2;

    uint8_t sk[BEP44_SK_LEN], pk[BEP44_PK_LEN];
    if (state_load_key(key_path, sk) < 0) return 2;

    int rc = 0;
    if (crypto_sign_ed25519_sk_to_pk(pk, sk) != 0) {
        fprintf(stderr, "[dht44:cmd_key] derive pubkey failed\n");
        rc = 3;
    } else {
        print_hex(pk, sizeof(pk));
    }
    sodium_memzero(sk, sizeof(sk));
    return rc;
}

int
cmd_target(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *salt = NULL;
    size_t salt_len = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            salt = argv[++i];
            salt_len = strlen(salt);
        } else {
            fputs(USAGE_TARGET, stderr);
            return 1;
        }
    }
    if (!key_path) {
        fputs(USAGE_TARGET, stderr);
        return 1;
    }
    if (salt_len > BEP44_MAX_SALT) {
        fprintf(stderr, "[dht44:cmd_key] salt too long (%zu > %d)\n",
                salt_len, BEP44_MAX_SALT);
        return 1;
    }
    if (init_sodium() < 0) return 2;

    uint8_t sk[BEP44_SK_LEN], pk[BEP44_PK_LEN], target[BEP44_TARGET_LEN];
    if (state_load_key(key_path, sk) < 0) return 2;

    int rc = 0;
    if (crypto_sign_ed25519_sk_to_pk(pk, sk) != 0) {
        fprintf(stderr, "[dht44:cmd_key] derive pubkey failed\n");
        rc = 3;
    } else {
        bep44_target(target, pk, (const uint8_t *)salt, salt_len);
        print_hex(target, sizeof(target));
    }
    sodium_memzero(sk, sizeof(sk));
    return rc;
}
