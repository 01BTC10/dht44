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

static const char USAGE_PUT[] =
    "usage: dht44 put -k KEYFILE [--salt S] --seq N [--cas M]"
    " [--bencode|--string] VALUE\n";
static const char USAGE_PUT_IMM[] =
    "usage: dht44 put-immutable [--bencode|--string] VALUE\n";

static int
init_sodium(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "[dht44:cmd_put] sodium_init failed\n");
        return -1;
    }
    return 0;
}

static int
ipc_send_and_print(const uint8_t *req, size_t req_len, int print_target)
{
    int fd = ipc_connect();
    if (fd < 0) {
        fprintf(stderr, "error: no daemon running. Start with: dht44 daemon &\n");
        return 5;
    }
    uint8_t resp[2048];
    size_t  resp_len = 0;
    if (ipc_request(fd, req, req_len, resp, sizeof(resp), &resp_len) < 0) {
        fprintf(stderr, "[dht44:cmd_put] IPC request failed\n");
        close(fd);
        return 2;
    }
    close(fd);

    bencode_arena *a;
    bencode_value *root = bencode_parse(resp, resp_len, &a);
    if (!root) {
        fprintf(stderr, "[dht44:cmd_put] malformed daemon reply\n");
        return 2;
    }
    int rc = 0;
    const bencode_value *err = bencode_dict_get(root, "err");
    if (err && err->type == BENCODE_STR) {
        fprintf(stderr, "[dht44:cmd_put] daemon: %.*s\n",
                (int)err->str.len, err->str.bytes);
        const bencode_value *acks = bencode_dict_get(root, "acks");
        if (acks && acks->type == BENCODE_INT) {
            fprintf(stderr, "                  acks=%lld\n", (long long)acks->i);
        }
        rc = 4;
    }
    const bencode_value *target = bencode_dict_get(root, "target");
    const bencode_value *acks   = bencode_dict_get(root, "acks");
    if (print_target && target && target->type == BENCODE_STR) {
        fwrite(target->str.bytes, 1, target->str.len, stdout);
        if (acks && acks->type == BENCODE_INT) {
            printf("\tacks=%lld\n", (long long)acks->i);
        } else {
            putchar('\n');
        }
    } else if (acks && acks->type == BENCODE_INT) {
        printf("acks=%lld\n", (long long)acks->i);
    }
    bencode_free(a);
    return rc;
}

/* ---- VALUE encoding helpers ---- */

static int
build_v_bencoded(int is_bencode, const char *value,
                 uint8_t *out, size_t cap, size_t *out_len)
{
    if (is_bencode) {
        size_t n = strlen(value);
        if (n > cap) return -1;
        memcpy(out, value, n);
        *out_len = n;
        return 0;
    }
    /* string: wrap as bencoded string */
    bencode_writer w;
    bencode_writer_init(&w, out, cap);
    bencode_cstr(&w, value);
    ssize_t n = bencode_writer_finish(&w);
    if (n < 0) return -1;
    *out_len = (size_t)n;
    return 0;
}

/* ============================================================
 * put-immutable
 * ============================================================ */

int
cmd_put_immutable(int argc, char **argv)
{
    int is_bencode = 0;
    const char *value = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bencode") == 0) {
            is_bencode = 1;
        } else if (strcmp(argv[i], "--string") == 0) {
            is_bencode = 0;
        } else if (argv[i][0] == '-') {
            fputs(USAGE_PUT_IMM, stderr);
            return 1;
        } else if (!value) {
            value = argv[i];
        } else {
            fputs(USAGE_PUT_IMM, stderr);
            return 1;
        }
    }
    if (!value) { fputs(USAGE_PUT_IMM, stderr); return 1; }

    uint8_t v[BEP44_MAX_V];
    size_t  v_len = 0;
    if (build_v_bencoded(is_bencode, value, v, sizeof(v), &v_len) < 0) {
        fprintf(stderr, "[dht44:cmd_put] value too large\n");
        return 1;
    }

    /* Build IPC request: { op: "put", mutable: 0, v: <v_bencoded> } */
    uint8_t req[BEP44_MAX_V + 256];
    bencode_writer w;
    bencode_writer_init(&w, req, sizeof(req));
    bencode_dict_open(&w);
        bencode_cstr(&w, "mutable"); bencode_int(&w, 0);
        bencode_cstr(&w, "op");      bencode_cstr(&w, "put");
        bencode_cstr(&w, "v");       bencode_str(&w, v, v_len);
    bencode_dict_close(&w);
    ssize_t n = bencode_writer_finish(&w);
    if (n < 0) { fprintf(stderr, "[dht44:cmd_put] request too large\n"); return 1; }
    return ipc_send_and_print(req, (size_t)n, 1);
}

/* ============================================================
 * put (mutable)
 * ============================================================ */

int
cmd_put(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *salt = NULL;
    size_t      salt_len = 0;
    long long   seq = -1;
    int         has_cas = 0;
    long long   cas = 0;
    int         is_bencode = 0;
    const char *value = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            salt = argv[++i];
            salt_len = strlen(salt);
        } else if (strcmp(argv[i], "--seq") == 0 && i + 1 < argc) {
            seq = atoll(argv[++i]);
        } else if (strcmp(argv[i], "--cas") == 0 && i + 1 < argc) {
            has_cas = 1; cas = atoll(argv[++i]);
        } else if (strcmp(argv[i], "--bencode") == 0) {
            is_bencode = 1;
        } else if (strcmp(argv[i], "--string") == 0) {
            is_bencode = 0;
        } else if (argv[i][0] == '-') {
            fputs(USAGE_PUT, stderr); return 1;
        } else if (!value) {
            value = argv[i];
        } else {
            fputs(USAGE_PUT, stderr); return 1;
        }
    }
    if (!key_path || seq < 0 || !value) {
        fputs(USAGE_PUT, stderr); return 1;
    }
    if (salt_len > BEP44_MAX_SALT) {
        fprintf(stderr, "[dht44:cmd_put] salt too long\n");
        return 1;
    }
    if (init_sodium() < 0) return 2;

    uint8_t sk[BEP44_SK_LEN];
    if (state_load_key(key_path, sk) < 0) return 2;

    uint8_t pk[BEP44_PK_LEN];
    if (crypto_sign_ed25519_sk_to_pk(pk, sk) != 0) {
        fprintf(stderr, "[dht44:cmd_put] derive pubkey failed\n");
        sodium_memzero(sk, sizeof(sk));
        return 3;
    }

    uint8_t v[BEP44_MAX_V];
    size_t  v_len = 0;
    if (build_v_bencoded(is_bencode, value, v, sizeof(v), &v_len) < 0) {
        fprintf(stderr, "[dht44:cmd_put] value too large\n");
        sodium_memzero(sk, sizeof(sk));
        return 1;
    }

    /* sign locally */
    uint8_t signable[BEP44_MAX_V + 128];
    ssize_t slen = bep44_signable(signable, sizeof(signable),
                                  (const uint8_t *)salt, salt_len,
                                  seq, v, v_len);
    if (slen < 0) {
        fprintf(stderr, "[dht44:cmd_put] signable too large\n");
        sodium_memzero(sk, sizeof(sk));
        return 1;
    }

    uint8_t sig[BEP44_SIG_LEN];
    if (bep44_sign(sig, sk, signable, (size_t)slen) < 0) {
        fprintf(stderr, "[dht44:cmd_put] sign failed\n");
        sodium_memzero(sk, sizeof(sk));
        return 3;
    }
    sodium_memzero(sk, sizeof(sk));

    /* derive target */
    uint8_t target[BEP44_TARGET_LEN];
    bep44_target(target, pk, (const uint8_t *)salt, salt_len);

    /* assemble item blob: seq(8) || salt_len(1) || salt || sig(64) || v_len(2) || v */
    size_t item_cap = 8 + 1 + salt_len + 64 + 2 + v_len;
    uint8_t *item = malloc(item_cap);
    if (!item) return 2;
    size_t off = 0;
    for (int i = 7; i >= 0; i--) item[off++] = (uint8_t)((uint64_t)seq >> (i * 8));
    item[off++] = (uint8_t)salt_len;
    if (salt_len) { memcpy(item + off, salt, salt_len); off += salt_len; }
    memcpy(item + off, sig, 64); off += 64;
    item[off++] = (uint8_t)(v_len >> 8);
    item[off++] = (uint8_t)v_len;
    memcpy(item + off, v, v_len); off += v_len;

    /* IPC request: { cas?, item, k, mutable:1, op:"put", target } */
    uint8_t req[BEP44_MAX_V + 1024];
    bencode_writer w;
    bencode_writer_init(&w, req, sizeof(req));
    bencode_dict_open(&w);
        if (has_cas) { bencode_cstr(&w, "cas"); bencode_int(&w, cas); }
        bencode_cstr(&w, "item");    bencode_str(&w, item, off);
        bencode_cstr(&w, "k");       bencode_str(&w, pk, BEP44_PK_LEN);
        bencode_cstr(&w, "mutable"); bencode_int(&w, 1);
        bencode_cstr(&w, "op");      bencode_cstr(&w, "put");
        bencode_cstr(&w, "target");  bencode_str(&w, target, BEP44_TARGET_LEN);
    bencode_dict_close(&w);
    ssize_t rn = bencode_writer_finish(&w);
    free(item);
    if (rn < 0) {
        fprintf(stderr, "[dht44:cmd_put] request too large\n");
        return 1;
    }

    /* Print target hex up front so user sees it even if daemon is slow */
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
        putchar(d[target[i] >> 4]); putchar(d[target[i] & 0xf]);
    }
    putchar('\n');
    fflush(stdout);

    return ipc_send_and_print(req, (size_t)rn, 0);
}
