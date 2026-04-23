#ifndef DHT44_BENCODE_H
#define DHT44_BENCODE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    BENCODE_INT,
    BENCODE_STR,
    BENCODE_LIST,
    BENCODE_DICT,
} bencode_type;

typedef struct bencode_value bencode_value;

struct bencode_dict_entry {
    const uint8_t *key;
    size_t key_len;
    bencode_value *val;
};

struct bencode_value {
    bencode_type type;
    union {
        int64_t i;
        struct { const uint8_t *bytes; size_t len; } str;
        struct { bencode_value **items; size_t len; } list;
        struct { struct bencode_dict_entry *entries; size_t len; } dict;
    };
};

/* ===== Writer =====
 * Bounded-buffer encoder. Caller initialises with a buffer + capacity, calls
 * encoder primitives, then finishes to retrieve the byte length (or -1 on
 * overflow).
 *
 * Dict key ordering is the CALLER's responsibility — the writer does not
 * enforce it. The decoder DOES enforce it on parse, and tests verify expected
 * output bytes.
 */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int err;        /* sticky: any failure latches this */
} bencode_writer;

void bencode_writer_init(bencode_writer *w, uint8_t *buf, size_t cap);
ssize_t bencode_writer_finish(const bencode_writer *w);

int bencode_int(bencode_writer *w, int64_t v);
int bencode_str(bencode_writer *w, const void *s, size_t len);
int bencode_cstr(bencode_writer *w, const char *s);
int bencode_list_open(bencode_writer *w);
int bencode_list_close(bencode_writer *w);
int bencode_dict_open(bencode_writer *w);
int bencode_dict_close(bencode_writer *w);
/* Splice already-bencoded bytes verbatim (e.g. a pre-encoded `v`). */
int bencode_raw(bencode_writer *w, const void *data, size_t len);

/* ===== Reader =====
 * Pull-style parser. Allocates a single arena per parse and returns a tree
 * whose string/byte pointers reference the input buffer (caller must keep it
 * alive). One bencode_free releases everything.
 *
 * Strict on parse: rejects unsorted dict keys, duplicate keys, leading-zero
 * integers ("i03e"), negative zero ("i-0e"), trailing data, non-string dict
 * keys, and over-deep nesting.
 */
typedef struct bencode_arena bencode_arena;

bencode_value *bencode_parse(const void *buf, size_t len, bencode_arena **arena_out);
void bencode_free(bencode_arena *arena);

/* Linear lookup; dicts are small. Returns NULL if d is not a dict, or no key. */
const bencode_value *bencode_dict_get(const bencode_value *d, const char *key);

#endif
