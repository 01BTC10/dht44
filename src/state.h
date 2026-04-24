#ifndef DHT44_STATE_H
#define DHT44_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bep44.h"

/*
 * State directory layout (default: $HOME/.dht44, override with DHT44_HOME):
 *
 *   key.bin                       Ed25519 secret key (64 B), mode 0600
 *   node_id.bin                   20 B persistent DHT node ID
 *   nodes.bin                     warm-start IPv4 peers, 6 B compact each
 *   items/<40-hex-target>.bin     daemon's republish queue
 *   sock                          IPC UNIX socket (daemon-owned)
 *   lock                          flock-based daemon mutex
 */

/*
 * Resolve the state directory. Caller-supplied buffer; returns the directory
 * path with NO trailing slash. Returns 0 on success, -1 if neither
 * DHT44_HOME nor $HOME is set or the path overflows.
 */
int state_home(char *out, size_t cap);

/* mkdir -p the state dir (and items/ subdir) with mode 0700. */
int state_ensure_dir(void);

/*
 * Acquire the daemon's exclusive lock on $home/lock. Returns the held fd on
 * success, -1 if another daemon already holds it (or on I/O error).
 * Releasing the fd releases the lock; state_unlock() is provided for clarity.
 */
int state_lock(void);
void state_unlock(int fd);

/* Ed25519 secret key file. Save with mode 0600; both zero key buffer at exit. */
int state_save_key(const char *path, const uint8_t sk[BEP44_SK_LEN]);
int state_load_key(const char *path, uint8_t sk[BEP44_SK_LEN]);

/*
 * Persistent DHT node ID. state_get_node_id auto-generates and persists on
 * first call; subsequent calls return the same ID.
 */
int state_get_node_id(uint8_t out[BEP44_NODE_ID_LEN]);

/*
 * IPv4 warm-start peers. Stored as a stream of 6-byte compact records
 * (4 B IP || 2 B port, network order).
 */
int state_save_nodes(const struct sockaddr_in *nodes, int count);
int state_load_nodes(struct sockaddr_in *out, int max, int *count_out);

/*
 * IPv6 warm-start peers. Stored as 18-byte compact records in nodes6.bin
 * (16 B addr || 2 B port, network order). Mirrors state_save_nodes for
 * the v6 routing table.
 */
int state_save_nodes6(const struct sockaddr_in6 *nodes, int count);
int state_load_nodes6(struct sockaddr_in6 *out, int max, int *count_out);

/*
 * Items the daemon stores for republish + inbound serve.
 *
 * On disk: $DHT44_HOME/items/<40-hex-target>.json — human-readable JSON.
 * Binary fields (pk, sig, salt, v) are hex-encoded inside the JSON.
 *
 * Mutable example:
 *   { "mutable": true,
 *     "pk":  "<64-hex>",
 *     "seq": 5,
 *     "salt":"<2*saltlen-hex>",       (omitted when salt_len == 0)
 *     "sig": "<128-hex>",
 *     "v":   "<2*vlen-hex>" }
 *
 * Immutable example:
 *   { "mutable": false,
 *     "v":   "<2*vlen-hex>" }
 */
typedef enum {
    ITEM_ORIGIN_SELF = 0,    /* we put it via the CLI; republish loop owns it */
    ITEM_ORIGIN_PEER = 1,    /* a remote peer asked us to store it */
} item_origin;

typedef struct {
    int          mutable_;
    item_origin  origin;
    uint8_t      pk[BEP44_PK_LEN];
    int64_t      seq;
    uint8_t      salt[BEP44_MAX_SALT];
    size_t       salt_len;
    uint8_t      sig[BEP44_SIG_LEN];
    uint8_t      v[BEP44_MAX_V];
    size_t       v_len;
} stored_item;

int state_save_item(const uint8_t target[BEP44_TARGET_LEN],
                    const stored_item *item);
int state_load_item(const uint8_t target[BEP44_TARGET_LEN],
                    stored_item *out);

/* Iterate items/<target>.json files. cb returns non-zero to stop early. */
typedef int (*state_item_cb)(const uint8_t target[BEP44_TARGET_LEN], void *closure);
int state_walk_items(state_item_cb cb, void *closure);

/* Hex helpers (used by state.c, cmd_keygen, etc.).
 * state_bytes_to_hex returns a newly malloc'd, NUL-terminated string.
 * state_hex_to_bytes parses exactly expected_len bytes from a hex string;
 * returns 0 on success, -1 on length mismatch / non-hex input. */
char *state_bytes_to_hex(const uint8_t *bytes, size_t len);
int   state_hex_to_bytes(const char *hex, uint8_t *out, size_t expected_len);

#endif
