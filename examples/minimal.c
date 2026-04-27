/*
 * libbep44 minimal example.
 *
 *   $ make example
 *   $ ./examples/minimal --put hello       # one-shot publish, exits
 *   $ ./examples/minimal --get             # one-shot retrieve, exits
 *   $ ./examples/minimal --serve hello     # long-lived publisher,
 *                                          # republishes every 60 min
 *
 * Persists keys + node id + stored items under ./libbep44_state/.
 *
 * BEP 44 items expire from peer caches after ~2 hours unless somebody
 * re-publishes them. --put exits immediately, so the value disappears
 * from the network 2h later. For long-lived publication use --serve,
 * which keeps the process running and lets the library's built-in
 * republish loop fire every 60 minutes. (See "Persistence and
 * republish" in the README.)
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

    /* Get-after-put on a freshly-bootstrapped node is sometimes flaky:
     * our lookup may converge on different peers than the put just hit
     * because the routing table is still warming up. Each get's
     * lookup itself grows the table, so a couple of retries reliably
     * resolves it. */
    get_state gs = { 0 };
    for (int attempt = 0; attempt < 5 && !gs.found; attempt++) {
        memset(&gs, 0, sizeof(gs));
        if (bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get, &gs) != 0) return 2;
        time_t end = time(NULL) + 30;
        while (!gs.done && time(NULL) < end) bep44_step(ctx, 250);
        if (!gs.done) { fprintf(stderr, "get timed out\n"); return 2; }
        if (!gs.found)
            fprintf(stderr, "  attempt %d: not found, retrying\n", attempt + 1);
    }
    if (!gs.found) { fprintf(stderr, "not found\n"); return 4; }
    /* gs.value is the bencoded form (e.g. "5:hello") */
    fwrite(gs.value, 1, gs.value_len, stdout);
    putchar('\n');
    return 0;
}

static int
cmd_serve(bep44_ctx_t *ctx, const char *value)
{
    /* Long-lived publisher: put once, then keep the process alive so
     * the library's built-in republish loop (every 60 min by default)
     * keeps the value pinned past the BEP 44 ~2h expiry. */
    int rc = cmd_put(ctx, value);
    if (rc != 0) return rc;
    fprintf(stderr,
            "serving — republishing every 60 min. Ctrl-C to stop.\n");
    while (1) bep44_step(ctx, 1000);
    return 0;       /* unreachable */
}

int
main(int argc, char **argv)
{
    if (argc < 2
        || (strcmp(argv[1], "--put")   != 0
            && strcmp(argv[1], "--get")   != 0
            && strcmp(argv[1], "--serve") != 0)) {
        fputs("usage: minimal --put VALUE | --get | --serve VALUE\n",
              stderr);
        return 1;
    }

    bep44_opts_t opts = {
        .port              = 6881,    /* fixed port so UPnP can map it */
        .state_dir         = STATE_DIR,
        .bootstrap_routers = 1,       /* talk to the public DHT */
        .use_upnp          = 1,       /* best-effort gateway port forward */
        .republish_minutes = 60,      /* default; spelled out for clarity */
    };
    bep44_ctx_t *ctx = bep44_open(&opts);
    if (!ctx) return 2;

    /* This example runs put and get in *separate processes* (one per
     * invocation), so the get can't reuse the routing table the put
     * built up. We need enough peers in the table that an iterative
     * lookup converges to the same closest-K set the put hit. ≥16
     * good nodes makes that reliable in practice; cold boot to that
     * size takes ~60-90s on the public DHT. (The same-process pattern
     * in the README quickstart only needs ≥4 because put-then-get
     * share routing table state.) */
    fprintf(stderr, "bootstrapping (waiting for >=16 good peers)...\n");
    while (bep44_good_nodes(ctx) < 16) bep44_step(ctx, 250);
    fprintf(stderr, "bootstrap: %d good nodes\n", bep44_good_nodes(ctx));

    int rc;
    if (strcmp(argv[1], "--put") == 0)
        rc = cmd_put(ctx, argc >= 3 ? argv[2] : "hello");
    else if (strcmp(argv[1], "--get") == 0)
        rc = cmd_get(ctx);
    else
        rc = cmd_serve(ctx, argc >= 3 ? argv[2] : "hello");
    bep44_close(ctx);
    return rc;
}
