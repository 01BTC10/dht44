#define _GNU_SOURCE         /* mkdtemp */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bep44.h"
#include "state.h"

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
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/dht44_test_state_XXXXXX");
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        exit(2);
    }
    setenv("DHT44_HOME", tmpdir, 1);
}

static void
rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        fprintf(stderr, "warn: rm -rf %s failed\n", path);
    }
}

static void
test_ensure_dir(void)
{
    EXPECT(state_ensure_dir() == 0);
    struct stat st;
    EXPECT(stat(tmpdir, &st) == 0 && S_ISDIR(st.st_mode));
    EXPECT((st.st_mode & 0777) == 0700);
    char items[256];
    snprintf(items, sizeof(items), "%s/items", tmpdir);
    EXPECT(stat(items, &st) == 0 && S_ISDIR(st.st_mode));
}

static void
test_lock(void)
{
    int a = state_lock();
    EXPECT(a >= 0);
    int b = state_lock();
    EXPECT(b == -1);            /* second concurrent acquire must fail */
    state_unlock(a);
    int c = state_lock();
    EXPECT(c >= 0);             /* lock released, available again */
    state_unlock(c);
}

static void
test_node_id(void)
{
    uint8_t a[BEP44_NODE_ID_LEN], b[BEP44_NODE_ID_LEN];
    EXPECT(state_get_node_id(a) == 0);
    EXPECT(state_get_node_id(b) == 0);
    EXPECT(memcmp(a, b, BEP44_NODE_ID_LEN) == 0);   /* persisted */
    /* Not all zero (overwhelmingly unlikely from CSPRNG) */
    int all_zero = 1;
    for (int i = 0; i < BEP44_NODE_ID_LEN; i++) if (a[i]) { all_zero = 0; break; }
    EXPECT(!all_zero);
}

static void
test_keyfile(void)
{
    uint8_t sk[BEP44_SK_LEN], sk2[BEP44_SK_LEN];
    for (int i = 0; i < BEP44_SK_LEN; i++) sk[i] = (uint8_t)(i ^ 0x55);
    char path[256];
    snprintf(path, sizeof(path), "%s/key.bin", tmpdir);
    EXPECT(state_save_key(path, sk) == 0);

    struct stat st;
    EXPECT(stat(path, &st) == 0);
    EXPECT((st.st_mode & 0777) == 0600);

    EXPECT(state_load_key(path, sk2) == 0);
    EXPECT(memcmp(sk, sk2, BEP44_SK_LEN) == 0);
}

static void
test_nodes_roundtrip(void)
{
    struct sockaddr_in nodes[3] = {0};
    for (int i = 0; i < 3; i++) {
        nodes[i].sin_family = AF_INET;
        nodes[i].sin_addr.s_addr = htonl(0x0a000001 + (uint32_t)i);  /* 10.0.0.1.. */
        nodes[i].sin_port = htons((uint16_t)(6881 + i));
    }
    EXPECT(state_save_nodes(nodes, 3) == 0);

    struct sockaddr_in out[16] = {0};
    int count = -1;
    EXPECT(state_load_nodes(out, 16, &count) == 0);
    EXPECT(count == 3);
    for (int i = 0; i < 3; i++) {
        EXPECT(out[i].sin_family == AF_INET);
        EXPECT(out[i].sin_addr.s_addr == htonl(0x0a000001 + (uint32_t)i));
        EXPECT(out[i].sin_port == htons((uint16_t)(6881 + i)));
    }
}

static void
test_nodes_missing(void)
{
    /* Remove nodes.bin and re-load */
    char path[256];
    snprintf(path, sizeof(path), "%s/nodes.bin", tmpdir);
    unlink(path);
    struct sockaddr_in out[4] = {0};
    int count = 99;
    EXPECT(state_load_nodes(out, 4, &count) == 0);
    EXPECT(count == 0);
}

struct walk_ctx {
    int seen;
    uint8_t expected[BEP44_TARGET_LEN];
};

static int
walk_cb(const uint8_t target[BEP44_TARGET_LEN], void *closure)
{
    struct walk_ctx *c = closure;
    if (memcmp(target, c->expected, BEP44_TARGET_LEN) == 0) c->seen++;
    return 0;
}

static void
test_items(void)
{
    uint8_t target[BEP44_TARGET_LEN];
    for (int i = 0; i < BEP44_TARGET_LEN; i++) target[i] = (uint8_t)(0x10 + i);
    const uint8_t blob[] = "item-payload-bytes";
    EXPECT(state_save_item(target, blob, sizeof(blob)) == 0);

    uint8_t buf[64];
    size_t n = 0;
    EXPECT(state_load_item(target, buf, sizeof(buf), &n) == 0);
    EXPECT(n == sizeof(blob));
    EXPECT(memcmp(buf, blob, sizeof(blob)) == 0);

    struct walk_ctx ctx = { .seen = 0 };
    memcpy(ctx.expected, target, BEP44_TARGET_LEN);
    EXPECT(state_walk_items(walk_cb, &ctx) == 0);
    EXPECT(ctx.seen == 1);
}

int
main(void)
{
    setup_tmp();

    test_ensure_dir();
    test_lock();
    test_node_id();
    test_keyfile();
    test_nodes_roundtrip();
    test_nodes_missing();
    test_items();

    rm_rf(tmpdir);
    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: state\n", stderr);
    return 0;
}
