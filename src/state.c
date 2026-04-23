#define _GNU_SOURCE         /* O_CLOEXEC, flock, etc. under -std=c11 */

#include "state.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>

/* PATH_MAX isn't reliably defined under -std=c11 without feature test macros.
 * 4096 covers Linux's PATH_MAX; all our paths are short suffixes of $DHT44_HOME. */
#define PATH_MAX 4096

#include <sodium.h>

/* ============================================================
 * Path resolution
 * ============================================================ */

int
state_home(char *out, size_t cap)
{
    const char *override = getenv("DHT44_HOME");
    if (override && override[0]) {
        size_t n = strlen(override);
        /* trim trailing slashes for canonical form */
        while (n > 1 && override[n - 1] == '/') n--;
        if (n + 1 > cap) return -1;
        memcpy(out, override, n);
        out[n] = '\0';
        return 0;
    }
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        fprintf(stderr, "[dht44:state] HOME not set and DHT44_HOME unset\n");
        return -1;
    }
    int n = snprintf(out, cap, "%s/.dht44", home);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

static int
join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* mkdir if absent; fail only on error other than EEXIST. */
static int
mkdir_p_one(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    }
    fprintf(stderr, "[dht44:state] mkdir %s: %s\n", path, strerror(errno));
    return -1;
}

int
state_ensure_dir(void)
{
    char home[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (mkdir_p_one(home, 0700) < 0) return -1;
    char items[PATH_MAX];
    if (join(items, sizeof(items), home, "items") < 0) return -1;
    if (mkdir_p_one(items, 0700) < 0) return -1;
    return 0;
}

/* ============================================================
 * Lock
 * ============================================================ */

int
state_lock(void)
{
    if (state_ensure_dir() < 0) return -1;
    char home[PATH_MAX], path[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (join(path, sizeof(path), home, "lock") < 0) return -1;

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[dht44:state] open lock: %s\n", strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr, "[dht44:state] another daemon holds %s\n", path);
        } else {
            fprintf(stderr, "[dht44:state] flock: %s\n", strerror(errno));
        }
        close(fd);
        return -1;
    }
    return fd;
}

void
state_unlock(int fd)
{
    if (fd >= 0) close(fd);     /* close releases the flock */
}

/* ============================================================
 * Generic file I/O helpers (atomic write-then-rename)
 * ============================================================ */

static int
write_atomic(const char *path, const void *data, size_t len, mode_t mode)
{
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        fprintf(stderr, "[dht44:state] open %s: %s\n", tmp, strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const char *)data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[dht44:state] write %s: %s\n", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t)w;
    }
    if (close(fd) < 0) {
        fprintf(stderr, "[dht44:state] close %s: %s\n", tmp, strerror(errno));
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) < 0) {
        fprintf(stderr, "[dht44:state] rename %s -> %s: %s\n",
                tmp, path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

static ssize_t
read_all(const char *path, void *out, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < cap) {
        ssize_t r = read(fd, (char *)out + off, cap - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    return (ssize_t)off;
}

/* ============================================================
 * Keyfile
 * ============================================================ */

int
state_save_key(const char *path, const uint8_t sk[BEP44_SK_LEN])
{
    return write_atomic(path, sk, BEP44_SK_LEN, 0600);
}

int
state_load_key(const char *path, uint8_t sk[BEP44_SK_LEN])
{
    ssize_t n = read_all(path, sk, BEP44_SK_LEN);
    if (n < 0) {
        fprintf(stderr, "[dht44:state] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (n != (ssize_t)BEP44_SK_LEN) {
        fprintf(stderr, "[dht44:state] %s: expected %d bytes, got %zd\n",
                path, BEP44_SK_LEN, n);
        sodium_memzero(sk, BEP44_SK_LEN);
        return -1;
    }
    return 0;
}

/* ============================================================
 * Persistent node_id
 * ============================================================ */

int
state_get_node_id(uint8_t out[BEP44_NODE_ID_LEN])
{
    if (state_ensure_dir() < 0) return -1;
    char home[PATH_MAX], path[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (join(path, sizeof(path), home, "node_id.bin") < 0) return -1;

    ssize_t n = read_all(path, out, BEP44_NODE_ID_LEN);
    if (n == (ssize_t)BEP44_NODE_ID_LEN) return 0;

    /* generate fresh */
    randombytes_buf(out, BEP44_NODE_ID_LEN);
    if (write_atomic(path, out, BEP44_NODE_ID_LEN, 0600) < 0) return -1;
    return 0;
}

/* ============================================================
 * Nodes blob (compact IPv4)
 * ============================================================ */

#define COMPACT_V4_LEN 6   /* 4 B addr + 2 B port */

int
state_save_nodes(const struct sockaddr_in *nodes, int count)
{
    if (state_ensure_dir() < 0) return -1;
    char home[PATH_MAX], path[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (join(path, sizeof(path), home, "nodes.bin") < 0) return -1;

    if (count <= 0) {
        return write_atomic(path, "", 0, 0600);
    }
    size_t blob_len = (size_t)count * COMPACT_V4_LEN;
    uint8_t *blob = malloc(blob_len);
    if (!blob) return -1;
    for (int i = 0; i < count; i++) {
        memcpy(blob + i * COMPACT_V4_LEN, &nodes[i].sin_addr, 4);
        memcpy(blob + i * COMPACT_V4_LEN + 4, &nodes[i].sin_port, 2);
    }
    int rc = write_atomic(path, blob, blob_len, 0600);
    free(blob);
    return rc;
}

int
state_load_nodes(struct sockaddr_in *out, int max, int *count_out)
{
    *count_out = 0;
    char home[PATH_MAX], path[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (join(path, sizeof(path), home, "nodes.bin") < 0) return -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;      /* no warm-start file is fine */
        fprintf(stderr, "[dht44:state] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    int n = 0;
    uint8_t rec[COMPACT_V4_LEN];
    while (n < max) {
        ssize_t r = read(fd, rec, COMPACT_V4_LEN);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r != COMPACT_V4_LEN) break;     /* truncated trailing record */
        memset(&out[n], 0, sizeof(out[n]));
        out[n].sin_family = AF_INET;
        memcpy(&out[n].sin_addr, rec, 4);
        memcpy(&out[n].sin_port, rec + 4, 2);
        n++;
    }
    close(fd);
    *count_out = n;
    return 0;
}

/* ============================================================
 * Items
 * ============================================================ */

static void
target_to_hex(char out[BEP44_TARGET_LEN * 2 + 1], const uint8_t target[BEP44_TARGET_LEN])
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
        out[i * 2]     = d[target[i] >> 4];
        out[i * 2 + 1] = d[target[i] & 0xf];
    }
    out[BEP44_TARGET_LEN * 2] = '\0';
}

static int
hex_to_target(const char *hex, uint8_t target[BEP44_TARGET_LEN])
{
    if (strlen(hex) != BEP44_TARGET_LEN * 2) return -1;
    for (size_t i = 0; i < BEP44_TARGET_LEN * 2; i++) {
        if (!isxdigit((unsigned char)hex[i])) return -1;
    }
    for (size_t i = 0; i < BEP44_TARGET_LEN; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        target[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return 0;
}

static int
item_path(char *out, size_t cap, const uint8_t target[BEP44_TARGET_LEN])
{
    char home[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    char hex[BEP44_TARGET_LEN * 2 + 1];
    target_to_hex(hex, target);
    int n = snprintf(out, cap, "%s/items/%s.json", home, hex);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Generic hex helpers — bytes <-> alloc'd C string. */
static char *
bytes_to_hexstr(const uint8_t *bytes, size_t len)
{
    static const char *d = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = d[bytes[i] >> 4];
        out[i * 2 + 1] = d[bytes[i] & 0xf];
    }
    out[len * 2] = '\0';
    return out;
}

static int
hexstr_to_bytes(const char *hex, uint8_t *out, size_t expected_len)
{
    if (!hex) return -1;
    if (strlen(hex) != expected_len * 2) return -1;
    for (size_t i = 0; i < expected_len; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) return -1;
        char b[3] = { hi, lo, '\0' };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return 0;
}

int
state_save_item(const uint8_t target[BEP44_TARGET_LEN], const stored_item *item)
{
    if (!item) return -1;
    if (state_ensure_dir() < 0) return -1;
    char path[PATH_MAX];
    if (item_path(path, sizeof(path), target) < 0) return -1;

    json_t *root = json_object();
    if (!root) return -1;

    json_object_set_new(root, "mutable",
                        item->mutable_ ? json_true() : json_false());

    char *v_hex = bytes_to_hexstr(item->v, item->v_len);
    if (!v_hex) { json_decref(root); return -1; }

    if (item->mutable_) {
        char *pk_hex  = bytes_to_hexstr(item->pk,  BEP44_PK_LEN);
        char *sig_hex = bytes_to_hexstr(item->sig, BEP44_SIG_LEN);
        if (!pk_hex || !sig_hex) {
            free(pk_hex); free(sig_hex); free(v_hex);
            json_decref(root);
            return -1;
        }
        json_object_set_new(root, "pk",  json_string(pk_hex));
        json_object_set_new(root, "seq", json_integer(item->seq));
        if (item->salt_len > 0) {
            char *salt_hex = bytes_to_hexstr(item->salt, item->salt_len);
            if (!salt_hex) {
                free(pk_hex); free(sig_hex); free(v_hex);
                json_decref(root);
                return -1;
            }
            json_object_set_new(root, "salt", json_string(salt_hex));
            free(salt_hex);
        }
        json_object_set_new(root, "sig", json_string(sig_hex));
        free(pk_hex);
        free(sig_hex);
    }
    json_object_set_new(root, "v", json_string(v_hex));
    free(v_hex);

    char *txt = json_dumps(root, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);
    if (!txt) return -1;
    int rc = write_atomic(path, txt, strlen(txt), 0600);
    free(txt);
    return rc;
}

int
state_load_item(const uint8_t target[BEP44_TARGET_LEN], stored_item *out)
{
    if (!out) return -1;
    char path[PATH_MAX];
    if (item_path(path, sizeof(path), target) < 0) return -1;

    /* read entire file (cap at 8 KiB — items are at most ~2 KiB) */
    uint8_t buf[8192];
    ssize_t n = read_all(path, buf, sizeof(buf) - 1);
    if (n < 0) return -1;
    buf[n] = 0;

    json_error_t err;
    json_t *root = json_loads((const char *)buf, 0, &err);
    if (!root) {
        fprintf(stderr, "[dht44:state] json parse %s: %s\n", path, err.text);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    json_t *jmut = json_object_get(root, "mutable");
    out->mutable_ = jmut && json_is_true(jmut) ? 1 : 0;

    json_t *jv = json_object_get(root, "v");
    if (!jv || !json_is_string(jv)) goto bad;
    {
        const char *vhex = json_string_value(jv);
        size_t vlen = strlen(vhex) / 2;
        if (vlen > BEP44_MAX_V || hexstr_to_bytes(vhex, out->v, vlen) < 0) goto bad;
        out->v_len = vlen;
    }

    if (out->mutable_) {
        json_t *jpk  = json_object_get(root, "pk");
        json_t *jseq = json_object_get(root, "seq");
        json_t *jsig = json_object_get(root, "sig");
        json_t *jsalt = json_object_get(root, "salt");
        if (!jpk || !json_is_string(jpk)
            || hexstr_to_bytes(json_string_value(jpk), out->pk, BEP44_PK_LEN) < 0)
            goto bad;
        if (!jseq || !json_is_integer(jseq)) goto bad;
        out->seq = json_integer_value(jseq);
        if (!jsig || !json_is_string(jsig)
            || hexstr_to_bytes(json_string_value(jsig), out->sig, BEP44_SIG_LEN) < 0)
            goto bad;
        if (jsalt && json_is_string(jsalt)) {
            const char *shex = json_string_value(jsalt);
            size_t slen = strlen(shex) / 2;
            if (slen > BEP44_MAX_SALT
                || hexstr_to_bytes(shex, out->salt, slen) < 0)
                goto bad;
            out->salt_len = slen;
        }
    }

    json_decref(root);
    return 0;

bad:
    fprintf(stderr, "[dht44:state] %s: malformed item json\n", path);
    json_decref(root);
    return -1;
}

int
state_walk_items(state_item_cb cb, void *closure)
{
    char home[PATH_MAX], items[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    if (join(items, sizeof(items), home, "items") < 0) return -1;

    DIR *d = opendir(items);
    if (!d) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "[dht44:state] opendir %s: %s\n", items, strerror(errno));
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d))) {
        const char *name = e->d_name;
        size_t nl = strlen(name);
        if (nl != BEP44_TARGET_LEN * 2 + 5) continue;       /* "<40hex>.json" */
        if (memcmp(name + BEP44_TARGET_LEN * 2, ".json", 5) != 0) continue;
        char hex[BEP44_TARGET_LEN * 2 + 1];
        memcpy(hex, name, BEP44_TARGET_LEN * 2);
        hex[BEP44_TARGET_LEN * 2] = '\0';
        uint8_t target[BEP44_TARGET_LEN];
        if (hex_to_target(hex, target) < 0) continue;
        if ((rc = cb(target, closure)) != 0) break;
    }
    closedir(d);
    return rc;
}
