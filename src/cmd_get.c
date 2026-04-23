#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "bencode.h"
#include "bep44.h"
#include "commands.h"
#include "ipc.h"
#include "state.h"

static const char USAGE_GET[] =
    "usage: dht44 get --target HEX                    [--no-cache] [--bencode]\n"
    "       dht44 get -k KEYFILE [--salt S]          [--no-cache] [--bencode]\n"
    "       dht44 get --pubkey HEX [--salt S]        [--no-cache] [--bencode]\n"
    "  --no-cache  bypass daemon's local items store; force network lookup.\n"
    "  --bencode   write the raw bencoded `v` to stdout (no string decode).\n";

static int
hex2byte(char hi, char lo, uint8_t *out)
{
    int h = isxdigit((unsigned char)hi) ? (isdigit((unsigned char)hi) ? hi - '0'
            : (tolower((unsigned char)hi) - 'a' + 10)) : -1;
    int l = isxdigit((unsigned char)lo) ? (isdigit((unsigned char)lo) ? lo - '0'
            : (tolower((unsigned char)lo) - 'a' + 10)) : -1;
    if (h < 0 || l < 0) return -1;
    *out = (uint8_t)((h << 4) | l);
    return 0;
}

static int
hex_decode(const char *hex, uint8_t *out, size_t expected_len)
{
    if (strlen(hex) != expected_len * 2) return -1;
    for (size_t i = 0; i < expected_len; i++) {
        if (hex2byte(hex[i * 2], hex[i * 2 + 1], &out[i]) < 0) return -1;
    }
    return 0;
}

int
cmd_get(int argc, char **argv)
{
    const char *target_hex = NULL;
    const char *key_path = NULL;
    const char *pubkey_hex = NULL;
    const char *salt = NULL;
    size_t salt_len = 0;
    int is_bencode_out = 0;     /* default: print v as raw bytes */
    int no_cache = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target_hex = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc) {
            pubkey_hex = argv[++i];
        } else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            salt = argv[++i];
            salt_len = strlen(salt);
        } else if (strcmp(argv[i], "--bencode") == 0) {
            is_bencode_out = 1;
        } else if (strcmp(argv[i], "--no-cache") == 0) {
            no_cache = 1;
        } else {
            fputs(USAGE_GET, stderr);
            return 1;
        }
    }
    int sources = (target_hex ? 1 : 0) + (key_path ? 1 : 0) + (pubkey_hex ? 1 : 0);
    if (sources != 1) { fputs(USAGE_GET, stderr); return 1; }
    if (salt_len > BEP44_MAX_SALT) {
        fprintf(stderr, "[dht44:cmd_get] salt too long\n");
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "[dht44:cmd_get] sodium_init failed\n");
        return 2;
    }

    int is_mutable = 0;
    uint8_t target[BEP44_TARGET_LEN];
    uint8_t pk[BEP44_PK_LEN];
    int     have_pk = 0;

    if (target_hex) {
        if (hex_decode(target_hex, target, BEP44_TARGET_LEN) < 0) {
            fprintf(stderr, "[dht44:cmd_get] bad target hex\n");
            return 1;
        }
        is_mutable = 0;
    } else if (key_path) {
        uint8_t sk[BEP44_SK_LEN];
        if (state_load_key(key_path, sk) < 0) return 2;
        if (crypto_sign_ed25519_sk_to_pk(pk, sk) != 0) {
            sodium_memzero(sk, sizeof(sk));
            return 3;
        }
        sodium_memzero(sk, sizeof(sk));
        have_pk = 1;
        bep44_target(target, pk, (const uint8_t *)salt, salt_len);
        is_mutable = 1;
    } else {
        if (hex_decode(pubkey_hex, pk, BEP44_PK_LEN) < 0) {
            fprintf(stderr, "[dht44:cmd_get] bad pubkey hex\n");
            return 1;
        }
        have_pk = 1;
        bep44_target(target, pk, (const uint8_t *)salt, salt_len);
        is_mutable = 1;
    }

    /* IPC request: { mutable: 0|1, no_cache?: 1, op:"get", target } */
    uint8_t req[256];
    bencode_writer w;
    bencode_writer_init(&w, req, sizeof(req));
    bencode_dict_open(&w);
        bencode_cstr(&w, "mutable");  bencode_int(&w, is_mutable);
        if (no_cache) {
            bencode_cstr(&w, "no_cache"); bencode_int(&w, 1);
        }
        bencode_cstr(&w, "op");       bencode_cstr(&w, "get");
        bencode_cstr(&w, "target");   bencode_str(&w, target, BEP44_TARGET_LEN);
    bencode_dict_close(&w);
    ssize_t reqn = bencode_writer_finish(&w);
    if (reqn < 0) return 1;

    int fd = ipc_connect();
    if (fd < 0) {
        fprintf(stderr, "error: no daemon running. Start with: dht44 daemon &\n");
        return 5;
    }
    uint8_t resp[8192];
    size_t  resp_len = 0;
    if (ipc_request(fd, req, (size_t)reqn, resp, sizeof(resp), &resp_len) < 0) {
        close(fd);
        return 2;
    }
    close(fd);

    bencode_arena *a;
    bencode_value *root = bencode_parse(resp, resp_len, &a);
    if (!root) {
        fprintf(stderr, "[dht44:cmd_get] malformed daemon reply\n");
        return 2;
    }
    int rc = 0;
    const bencode_value *found = bencode_dict_get(root, "found");
    const bencode_value *v     = bencode_dict_get(root, "v");
    if (!found || found->type != BENCODE_INT || !found->i || !v
        || v->type != BENCODE_STR) {
        fprintf(stderr, "[dht44:cmd_get] not found\n");
        rc = 2;
        goto end;
    }

    /* For mutable, verify sig locally before printing. */
    if (is_mutable && have_pk) {
        const bencode_value *resp_k   = bencode_dict_get(root, "k");
        const bencode_value *resp_sig = bencode_dict_get(root, "sig");
        const bencode_value *resp_seq = bencode_dict_get(root, "seq");
        if (!resp_k || resp_k->type != BENCODE_STR || resp_k->str.len != BEP44_PK_LEN
            || !resp_sig || resp_sig->type != BENCODE_STR
            || resp_sig->str.len != BEP44_SIG_LEN
            || !resp_seq || resp_seq->type != BENCODE_INT) {
            fprintf(stderr, "[dht44:cmd_get] mutable response missing fields\n");
            rc = 3; goto end;
        }
        if (memcmp(resp_k->str.bytes, pk, BEP44_PK_LEN) != 0) {
            fprintf(stderr, "[dht44:cmd_get] returned k != requested pk\n");
            rc = 3; goto end;
        }
        uint8_t signable[BEP44_MAX_V + 128];
        ssize_t slen = bep44_signable(signable, sizeof(signable),
                                      (const uint8_t *)salt, salt_len,
                                      resp_seq->i,
                                      v->str.bytes, v->str.len);
        if (slen < 0
            || bep44_verify(resp_sig->str.bytes, pk, signable, (size_t)slen) < 0) {
            fprintf(stderr, "[dht44:cmd_get] signature verify failed\n");
            rc = 3; goto end;
        }
    }

    if (is_bencode_out) {
        fwrite(v->str.bytes, 1, v->str.len, stdout);
    } else {
        /* Decode the bencode `v` if it's a string; otherwise dump raw. */
        bencode_arena *va;
        bencode_value *vv = bencode_parse(v->str.bytes, v->str.len, &va);
        if (vv && vv->type == BENCODE_STR) {
            fwrite(vv->str.bytes, 1, vv->str.len, stdout);
        } else {
            fwrite(v->str.bytes, 1, v->str.len, stdout);
        }
        if (vv) bencode_free(va);
    }
    putchar('\n');

end:
    bencode_free(a);
    return rc;
}
