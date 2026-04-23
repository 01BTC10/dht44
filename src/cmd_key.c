#define _GNU_SOURCE         /* fchmod, fileno */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "bep44.h"
#include "commands.h"
#include "state.h"

static const char USAGE_KEYGEN[] =
    "usage: dht44 keygen -o KEYFILE [-k EXISTING.json ...] [--salt S ...]\n"
    "       (writes a JSON keyfile, also prints it to stdout)\n";
static const char USAGE_PUBKEY[] = "usage: dht44 pubkey -k KEYFILE\n";
static const char USAGE_TARGET[] = "usage: dht44 target -k KEYFILE [--salt S]\n";

#define MAX_KEYGEN_INPUTS 16
#define MAX_KEYGEN_SALTS  16

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

/*
 * Build the per-key JSON object: { sk, pk, targets: { <salt>: <hex>, ... } }.
 * Salts are an array of (cstring, len) pairs; "" maps to the no-salt target.
 * The empty-salt entry is always included so callers always have a default
 * target to pluck out.
 */
static json_t *
build_key_obj(const uint8_t sk[BEP44_SK_LEN],
              const char *salts[], const size_t salt_lens[], size_t n_salts)
{
    uint8_t pk[BEP44_PK_LEN];
    if (crypto_sign_ed25519_sk_to_pk(pk, sk) != 0) return NULL;

    char *sk_hex = state_bytes_to_hex(sk, BEP44_SK_LEN);
    char *pk_hex = state_bytes_to_hex(pk, BEP44_PK_LEN);
    if (!sk_hex || !pk_hex) { free(sk_hex); free(pk_hex); return NULL; }

    json_t *obj = json_object();
    json_object_set_new(obj, "sk", json_string(sk_hex));
    json_object_set_new(obj, "pk", json_string(pk_hex));
    free(sk_hex); free(pk_hex);

    json_t *targets = json_object();
    /* always include the no-salt target */
    {
        uint8_t t[BEP44_TARGET_LEN];
        bep44_target(t, pk, NULL, 0);
        char *th = state_bytes_to_hex(t, BEP44_TARGET_LEN);
        json_object_set_new(targets, "", json_string(th));
        free(th);
    }
    for (size_t i = 0; i < n_salts; i++) {
        if (salt_lens[i] == 0) continue;        /* dedupes the empty salt */
        uint8_t t[BEP44_TARGET_LEN];
        bep44_target(t, pk, (const uint8_t *)salts[i], salt_lens[i]);
        char *th = state_bytes_to_hex(t, BEP44_TARGET_LEN);
        json_object_set_new(targets, salts[i], json_string(th));
        free(th);
    }
    json_object_set_new(obj, "targets", targets);
    return obj;
}

/*
 * Pull the first key entry's sk out of EXISTING.json. We reuse
 * state_load_key for this since it already returns sk of keys[0].
 */
static int
sk_from_keyfile(const char *path, uint8_t sk[BEP44_SK_LEN])
{
    return state_load_key(path, sk);
}

int
cmd_keygen(int argc, char **argv)
{
    const char *out_path = NULL;
    const char *inputs[MAX_KEYGEN_INPUTS];
    int n_inputs = 0;
    const char *salts[MAX_KEYGEN_SALTS];
    size_t salt_lens[MAX_KEYGEN_SALTS];
    int n_salts = 0;
    int no_generate = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            if (n_inputs >= MAX_KEYGEN_INPUTS) {
                fprintf(stderr, "[dht44:cmd_key] too many -k entries\n");
                return 1;
            }
            inputs[n_inputs++] = argv[++i];
        } else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            if (n_salts >= MAX_KEYGEN_SALTS) {
                fprintf(stderr, "[dht44:cmd_key] too many --salt entries\n");
                return 1;
            }
            salts[n_salts]     = argv[++i];
            salt_lens[n_salts] = strlen(salts[n_salts]);
            n_salts++;
        } else if (strcmp(argv[i], "--no-generate") == 0) {
            no_generate = 1;
        } else {
            fputs(USAGE_KEYGEN, stderr);
            return 1;
        }
    }
    if (!out_path && n_inputs == 0 && no_generate) {
        fputs(USAGE_KEYGEN, stderr);
        return 1;
    }
    if (no_generate && n_inputs == 0) {
        fprintf(stderr,
                "[dht44:cmd_key] --no-generate without -k means no keys\n");
        return 1;
    }
    if (init_sodium() < 0) return 2;

    json_t *root = json_object();
    json_t *keys = json_array();
    int rc = 0;

    /* freshly generated key (unless --no-generate) */
    if (!no_generate) {
        uint8_t pk[BEP44_PK_LEN], sk[BEP44_SK_LEN];
        crypto_sign_keypair(pk, sk);
        json_t *o = build_key_obj(sk, salts, salt_lens, (size_t)n_salts);
        sodium_memzero(sk, sizeof(sk));
        if (!o) { rc = 2; goto end; }
        json_array_append_new(keys, o);
    }

    /* imported keys */
    for (int i = 0; i < n_inputs; i++) {
        uint8_t sk[BEP44_SK_LEN];
        if (sk_from_keyfile(inputs[i], sk) < 0) { rc = 2; goto end; }
        json_t *o = build_key_obj(sk, salts, salt_lens, (size_t)n_salts);
        sodium_memzero(sk, sizeof(sk));
        if (!o) { rc = 2; goto end; }
        json_array_append_new(keys, o);
    }
    json_object_set_new(root, "keys", keys);
    keys = NULL;        /* steal */

    char *txt = json_dumps(root, JSON_INDENT(2) | JSON_SORT_KEYS);
    if (!txt) { rc = 2; goto end; }

    /* always print to stdout */
    fputs(txt, stdout);
    fputc('\n', stdout);

    if (out_path) {
        FILE *f = fopen(out_path, "w");
        if (!f) {
            fprintf(stderr,
                    "[dht44:cmd_key] open %s for write failed\n", out_path);
            free(txt);
            rc = 2;
            goto end;
        }
        /* mode 0600 — chmod after fopen since fopen doesn't take mode bits */
        fchmod(fileno(f), 0600);
        fputs(txt, f);
        fputc('\n', f);
        fclose(f);
    }
    free(txt);

end:
    if (keys) json_decref(keys);
    json_decref(root);
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
