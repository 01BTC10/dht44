/*
 * Tiny CLI used by tests/integration/lib_roundtrip.sh. Exercises the
 * libbep44 public API end-to-end. No daemon, no IPC — each invocation
 * opens its own ctx, runs the requested op, and prints the result.
 *
 * Subcommands:
 *   keygen --out KEYFILE
 *   serve  --port N --state DIR --seconds S      (just runs the loop)
 *   put    --port N --state DIR --key KEYFILE --seq N --value STR \
 *          --peer 127.0.0.1:PORT --seconds S
 *   get    --port N --state DIR --pk-from KEYFILE \
 *          --peer 127.0.0.1:PORT --seconds S
 *
 * --value is treated as a raw string and bencoded as L:bytes.
 * --peer adds a known peer to the routing table for bootstrap.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libbep44.h"

static const char *
arg_value(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    return NULL;
}

static int
parse_peer(const char *s, char *ip_out, size_t ip_cap, uint16_t *port_out)
{
    const char *colon = strchr(s, ':');
    if (!colon) return -1;
    size_t n = (size_t)(colon - s);
    if (n + 1 > ip_cap) return -1;
    memcpy(ip_out, s, n);
    ip_out[n] = 0;
    *port_out = (uint16_t)atoi(colon + 1);
    return 0;
}

/* ---------- keygen ---------- */

static int
do_keygen(int argc, char **argv)
{
    const char *out = arg_value(argc, argv, "--out");
    if (!out) { fputs("usage: keygen --out KEYFILE\n", stderr); return 1; }
    bep44_keypair_t kp;
    if (bep44_keygen(&kp) < 0) return 2;
    if (bep44_save_key(out, &kp) < 0) return 2;
    /* print pk hex on stdout for the harness to consume */
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < BEP44_PK_LEN; i++) {
        putchar(d[kp.pk[i] >> 4]); putchar(d[kp.pk[i] & 0xf]);
    }
    putchar('\n');
    return 0;
}

/* ---------- shared open ---------- */

static bep44_ctx_t *
open_ctx(int argc, char **argv)
{
    const char *port_s  = arg_value(argc, argv, "--port");
    const char *state   = arg_value(argc, argv, "--state");
    const char *peer    = arg_value(argc, argv, "--peer");
    if (!port_s || !state) {
        fputs("missing --port / --state\n", stderr);
        return NULL;
    }
    bep44_opts_t opts = { 0 };
    opts.port = atoi(port_s);
    opts.state_dir = state;
    opts.bootstrap_routers = 0;
    bep44_ctx_t *ctx = bep44_open(&opts);
    if (!ctx) return NULL;

    if (peer) {
        char ip[64]; uint16_t p;
        if (parse_peer(peer, ip, sizeof(ip), &p) < 0
            || bep44_add_peer(ctx, ip, p) < 0) {
            fprintf(stderr, "bad --peer %s\n", peer);
            bep44_close(ctx);
            return NULL;
        }
        /* Pump events long enough for the warm-bootstrap ping to
         * round-trip and promote the peer from dubious to good — the
         * lookup engine seeds from good nodes only. */
        time_t end = time(NULL) + 2;
        while (time(NULL) < end) bep44_step(ctx, 100);
    }
    return ctx;
}

static void
pump_for(bep44_ctx_t *ctx, int seconds)
{
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) bep44_step(ctx, 200);
}

/* ---------- serve ---------- */

static int
do_serve(int argc, char **argv)
{
    bep44_ctx_t *ctx = open_ctx(argc, argv);
    if (!ctx) return 2;
    const char *secs = arg_value(argc, argv, "--seconds");
    pump_for(ctx, secs ? atoi(secs) : 30);
    bep44_close(ctx);
    return 0;
}

/* ---------- put ---------- */

typedef struct { int done; bep44_put_result_t r; } put_state;

static void
on_put(const bep44_put_result_t *r, void *u)
{
    put_state *ps = u;
    ps->r = *r;
    ps->done = 1;
}

static int
do_put(int argc, char **argv)
{
    const char *keyfile = arg_value(argc, argv, "--key");
    const char *seq_s   = arg_value(argc, argv, "--seq");
    const char *value   = arg_value(argc, argv, "--value");
    const char *secs    = arg_value(argc, argv, "--seconds");
    if (!keyfile || !seq_s || !value) {
        fputs("missing --key/--seq/--value\n", stderr); return 1;
    }
    bep44_keypair_t kp;
    if (bep44_load_key(keyfile, &kp) < 0) return 2;

    bep44_ctx_t *ctx = open_ctx(argc, argv);
    if (!ctx) return 2;

    /* bencode the value as a string: "<len>:<bytes>" */
    size_t vlen = strlen(value);
    uint8_t v[BEP44_VALUE_MAX];
    int n = snprintf((char *)v, sizeof(v), "%zu:", vlen);
    if (n < 0 || (size_t)n + vlen > sizeof(v)) return 1;
    memcpy(v + n, value, vlen);
    size_t v_total = (size_t)n + vlen;

    put_state ps = { 0 };
    if (bep44_put_mutable(ctx, &kp, NULL, 0, atoll(seq_s), -1,
                          v, v_total, on_put, &ps) < 0) {
        bep44_close(ctx); return 2;
    }
    int budget = secs ? atoi(secs) : 20;
    time_t end = time(NULL) + budget;
    while (!ps.done && time(NULL) < end) bep44_step(ctx, 200);
    bep44_close(ctx);
    if (!ps.done) { fprintf(stderr, "put timed out\n"); return 2; }
    printf("acks=%d err=%d\n", ps.r.stored_count, ps.r.err_code);
    return ps.r.success ? 0 : 4;
}

/* ---------- get ---------- */

typedef struct {
    int done;
    int found;
    int64_t seq;
    uint8_t value[BEP44_VALUE_MAX];
    size_t  value_len;
} get_state;

static void
on_get(const bep44_get_result_t *r, void *u)
{
    get_state *gs = u;
    gs->done = 1;
    gs->found = r->found;
    if (r->found) {
        gs->seq = r->seq;
        gs->value_len = r->value_len;
        memcpy(gs->value, r->value, r->value_len);
    }
}

static int
do_get(int argc, char **argv)
{
    const char *keyfile = arg_value(argc, argv, "--pk-from");
    const char *secs    = arg_value(argc, argv, "--seconds");
    if (!keyfile) { fputs("missing --pk-from\n", stderr); return 1; }
    bep44_keypair_t kp;
    if (bep44_load_key(keyfile, &kp) < 0) return 2;

    bep44_ctx_t *ctx = open_ctx(argc, argv);
    if (!ctx) return 2;

    get_state gs = { 0 };
    if (bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get, &gs) < 0) {
        bep44_close(ctx); return 2;
    }
    int budget = secs ? atoi(secs) : 20;
    time_t end = time(NULL) + budget;
    while (!gs.done && time(NULL) < end) bep44_step(ctx, 200);
    bep44_close(ctx);
    if (!gs.done)  { fprintf(stderr, "get timed out\n"); return 2; }
    if (!gs.found) { fprintf(stderr, "not found\n"); return 4; }
    /* echo the bencoded value back out for the harness to compare */
    fwrite(gs.value, 1, gs.value_len, stdout);
    putchar('\n');
    fprintf(stderr, "seq=%lld\n", (long long)gs.seq);
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fputs("usage: lib_driver <keygen|serve|put|get> [args]\n", stderr);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "keygen") == 0) return do_keygen(argc, argv);
    if (strcmp(cmd, "serve")  == 0) return do_serve(argc, argv);
    if (strcmp(cmd, "put")    == 0) return do_put(argc, argv);
    if (strcmp(cmd, "get")    == 0) return do_get(argc, argv);
    fprintf(stderr, "unknown subcommand: %s\n", cmd);
    return 1;
}
