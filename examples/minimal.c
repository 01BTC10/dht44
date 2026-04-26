/*
 * libbep44 minimal example.
 *
 *   $ make example
 *   $ ./examples/minimal --put hello
 *   <waits for the public DHT to accept the put>
 *   $ ./examples/minimal --get
 *   value: hello
 *
 * Persists keys + node id under ./libbep44_state/.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libbep44.h"

static const char *STATE_DIR = "./libbep44_state";
static const char *KEY_FILE  = "./libbep44_state/key.json";

typedef struct { int done; bep44_put_result_t r; } put_state;
typedef struct {
    int done; int found;
    char value[BEP44_VALUE_MAX]; size_t value_len;
} get_state;

static void
on_put(const bep44_put_result_t *r, void *u)
{
    put_state *ps = u; ps->r = *r; ps->done = 1;
    fprintf(stderr, "put: stored on %d node(s), err=%d\n",
            r->stored_count, r->err_code);
}

static void
on_get(const bep44_get_result_t *r, void *u)
{
    get_state *gs = u;
    gs->done = 1;
    gs->found = r->found;
    if (r->found && r->value_len < sizeof(gs->value)) {
        memcpy(gs->value, r->value, r->value_len);
        gs->value_len = r->value_len;
    }
}

static int
cmd_put(bep44_ctx_t *ctx, const char *value)
{
    bep44_keypair_t kp;
    if (bep44_load_key(KEY_FILE, &kp) != 0) {
        if (bep44_keygen(&kp) != 0) return 2;
        bep44_save_key(KEY_FILE, &kp);
    }

    /* bencode the user value as a string: "<len>:<bytes>" */
    uint8_t v[BEP44_VALUE_MAX];
    size_t  vl = strlen(value);
    int n = snprintf((char *)v, sizeof(v), "%zu:", vl);
    if (n < 0 || (size_t)n + vl > sizeof(v)) return 1;
    memcpy(v + n, value, vl);

    put_state ps = { 0 };
    if (bep44_put_mutable(ctx, &kp, NULL, 0,
                          /*seq=*/(int64_t)time(NULL),
                          /*cas=*/-1,
                          v, n + vl, on_put, &ps) != 0) return 2;

    time_t end = time(NULL) + 30;
    while (!ps.done && time(NULL) < end) bep44_step(ctx, 250);
    return ps.r.success ? 0 : 4;
}

static int
cmd_get(bep44_ctx_t *ctx)
{
    bep44_keypair_t kp;
    if (bep44_load_key(KEY_FILE, &kp) != 0) {
        fprintf(stderr, "no key — run --put first\n");
        return 1;
    }

    get_state gs = { 0 };
    if (bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get, &gs) != 0) return 2;

    time_t end = time(NULL) + 30;
    while (!gs.done && time(NULL) < end) bep44_step(ctx, 250);
    if (!gs.done)  { fprintf(stderr, "get timed out\n"); return 2; }
    if (!gs.found) { fprintf(stderr, "not found\n"); return 4; }
    /* gs.value is the bencoded form (e.g. "5:hello") */
    fwrite(gs.value, 1, gs.value_len, stdout);
    putchar('\n');
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "--put") != 0 && strcmp(argv[1], "--get") != 0)) {
        fputs("usage: minimal --put VALUE | --get\n", stderr);
        return 1;
    }

    bep44_opts_t opts = {
        .port = 0,                   /* OS picks an ephemeral port */
        .state_dir = STATE_DIR,
        .bootstrap_routers = 1,      /* talk to the public DHT */
    };
    bep44_ctx_t *ctx = bep44_open(&opts);
    if (!ctx) return 2;

    /* let bootstrap settle a bit before issuing ops */
    time_t end = time(NULL) + 5;
    while (time(NULL) < end) bep44_step(ctx, 200);
    fprintf(stderr, "bootstrap: %d good nodes\n", bep44_good_nodes(ctx));

    int rc = strcmp(argv[1], "--put") == 0
             ? cmd_put(ctx, argc >= 3 ? argv[2] : "hello")
             : cmd_get(ctx);
    bep44_close(ctx);
    return rc;
}
