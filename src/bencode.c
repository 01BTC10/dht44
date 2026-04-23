#include "bencode.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Writer
 * ============================================================ */

void
bencode_writer_init(bencode_writer *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

ssize_t
bencode_writer_finish(const bencode_writer *w)
{
    return w->err ? -1 : (ssize_t)w->len;
}

static int
writer_putc(bencode_writer *w, uint8_t c)
{
    if (w->err) return -1;
    if (w->len + 1 > w->cap) { w->err = 1; return -1; }
    w->buf[w->len++] = c;
    return 0;
}

static int
writer_write(bencode_writer *w, const void *data, size_t n)
{
    if (w->err) return -1;
    if (w->len + n > w->cap) { w->err = 1; return -1; }
    memcpy(w->buf + w->len, data, n);
    w->len += n;
    return 0;
}

int
bencode_int(bencode_writer *w, int64_t v)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "i%" PRId64 "e", v);
    if (n < 0 || (size_t)n >= sizeof(tmp)) { w->err = 1; return -1; }
    return writer_write(w, tmp, (size_t)n);
}

int
bencode_str(bencode_writer *w, const void *s, size_t len)
{
    char hdr[24];
    int n = snprintf(hdr, sizeof(hdr), "%zu:", len);
    if (n < 0 || (size_t)n >= sizeof(hdr)) { w->err = 1; return -1; }
    if (writer_write(w, hdr, (size_t)n) < 0) return -1;
    return writer_write(w, s, len);
}

int
bencode_cstr(bencode_writer *w, const char *s)
{
    return bencode_str(w, s, strlen(s));
}

int bencode_list_open(bencode_writer *w)  { return writer_putc(w, 'l'); }
int bencode_list_close(bencode_writer *w) { return writer_putc(w, 'e'); }
int bencode_dict_open(bencode_writer *w)  { return writer_putc(w, 'd'); }
int bencode_dict_close(bencode_writer *w) { return writer_putc(w, 'e'); }

int
bencode_raw(bencode_writer *w, const void *data, size_t len)
{
    return writer_write(w, data, len);
}

/* ============================================================
 * Reader
 * ============================================================ */

#define MAX_DEPTH      16
#define ARENA_PER_BYTE 32     /* arena cap = max(input_len * 32, ARENA_MIN) */
#define ARENA_MIN      4096

struct bencode_arena {
    uint8_t *base;
    size_t   cap;
    size_t   used;
};

static void *
arena_alloc(bencode_arena *a, size_t n)
{
    n = (n + 7u) & ~(size_t)7u;     /* 8-byte align */
    if (a->used + n > a->cap) return NULL;
    void *p = a->base + a->used;
    a->used += n;
    return p;
}

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    int            depth;
    bencode_arena *arena;
} parser;

static int parse_value(parser *p, bencode_value *out);

static int
is_digit(int c)
{
    return c >= '0' && c <= '9';
}

/*
 * Parse `[-]<digits>` then expect `term`. Strict: reject leading zero
 * (except "0"), reject "-0", reject empty digits.
 */
static int
parse_int_until(parser *p, int term, int64_t *out)
{
    if (p->pos >= p->len) return -1;
    int neg = 0;
    if (p->buf[p->pos] == '-') {
        neg = 1;
        p->pos++;
        if (p->pos >= p->len || !is_digit(p->buf[p->pos])) return -1;
        if (p->buf[p->pos] == '0') return -1;       /* -0 forbidden */
    }
    if (p->pos >= p->len || !is_digit(p->buf[p->pos])) return -1;
    int leading_zero = (p->buf[p->pos] == '0');
    int64_t v = 0;
    int digits = 0;
    while (p->pos < p->len && is_digit(p->buf[p->pos])) {
        if (leading_zero && digits > 0) return -1;  /* "01" forbidden */
        int d = p->buf[p->pos] - '0';
        if (v > (INT64_MAX - d) / 10) return -1;    /* overflow */
        v = v * 10 + d;
        digits++;
        p->pos++;
    }
    if (digits == 0) return -1;
    if (p->pos >= p->len || p->buf[p->pos] != term) return -1;
    p->pos++;                                       /* consume terminator */
    *out = neg ? -v : v;
    return 0;
}

static int
parse_int(parser *p, int64_t *out)
{
    if (p->pos >= p->len || p->buf[p->pos] != 'i') return -1;
    p->pos++;
    return parse_int_until(p, 'e', out);
}

static int
parse_str(parser *p, const uint8_t **bytes, size_t *str_len)
{
    int64_t n;
    if (parse_int_until(p, ':', &n) < 0) return -1;
    if (n < 0) return -1;
    if ((size_t)n > p->len - p->pos) return -1;
    *bytes = p->buf + p->pos;
    *str_len = (size_t)n;
    p->pos += (size_t)n;
    return 0;
}

static int
parse_list(parser *p, bencode_value *out)
{
    if (p->depth >= MAX_DEPTH) return -1;
    p->pos++;                                       /* consume 'l' */
    p->depth++;

    bencode_value **items = NULL;
    size_t cap = 0, len = 0;

    while (p->pos < p->len && p->buf[p->pos] != 'e') {
        if (len >= cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            bencode_value **ni = arena_alloc(p->arena, new_cap * sizeof(*ni));
            if (!ni) return -1;
            if (items) memcpy(ni, items, len * sizeof(*ni));
            items = ni;
            cap = new_cap;
        }
        bencode_value *v = arena_alloc(p->arena, sizeof(*v));
        if (!v) return -1;
        if (parse_value(p, v) < 0) return -1;
        items[len++] = v;
    }
    if (p->pos >= p->len) return -1;
    p->pos++;                                       /* consume 'e' */
    p->depth--;

    out->type = BENCODE_LIST;
    out->list.items = items;
    out->list.len = len;
    return 0;
}

static int
parse_dict(parser *p, bencode_value *out)
{
    if (p->depth >= MAX_DEPTH) return -1;
    p->pos++;                                       /* consume 'd' */
    p->depth++;

    struct bencode_dict_entry *entries = NULL;
    size_t cap = 0, len = 0;
    const uint8_t *prev_key = NULL;
    size_t prev_key_len = 0;

    while (p->pos < p->len && p->buf[p->pos] != 'e') {
        const uint8_t *kb;
        size_t kl;
        if (parse_str(p, &kb, &kl) < 0) return -1;

        /* strict: keys must be in strictly increasing byte order */
        if (prev_key) {
            size_t mn = prev_key_len < kl ? prev_key_len : kl;
            int cmp = memcmp(prev_key, kb, mn);
            if (cmp > 0) return -1;
            if (cmp == 0 && prev_key_len >= kl) return -1;
        }

        if (len >= cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            struct bencode_dict_entry *ne =
                arena_alloc(p->arena, new_cap * sizeof(*ne));
            if (!ne) return -1;
            if (entries) memcpy(ne, entries, len * sizeof(*ne));
            entries = ne;
            cap = new_cap;
        }
        bencode_value *v = arena_alloc(p->arena, sizeof(*v));
        if (!v) return -1;
        if (parse_value(p, v) < 0) return -1;

        entries[len].key = kb;
        entries[len].key_len = kl;
        entries[len].val = v;
        prev_key = kb;
        prev_key_len = kl;
        len++;
    }
    if (p->pos >= p->len) return -1;
    p->pos++;                                       /* consume 'e' */
    p->depth--;

    out->type = BENCODE_DICT;
    out->dict.entries = entries;
    out->dict.len = len;
    return 0;
}

static int
parse_value(parser *p, bencode_value *out)
{
    if (p->pos >= p->len) return -1;
    int c = p->buf[p->pos];
    if (c == 'i') {
        int64_t v;
        if (parse_int(p, &v) < 0) return -1;
        out->type = BENCODE_INT;
        out->i = v;
        return 0;
    }
    if (c == 'l') return parse_list(p, out);
    if (c == 'd') return parse_dict(p, out);
    if (is_digit(c)) {
        const uint8_t *bytes;
        size_t slen;
        if (parse_str(p, &bytes, &slen) < 0) return -1;
        out->type = BENCODE_STR;
        out->str.bytes = bytes;
        out->str.len = slen;
        return 0;
    }
    return -1;
}

bencode_value *
bencode_parse(const void *buf, size_t len, bencode_arena **arena_out)
{
    bencode_arena *a = malloc(sizeof(*a));
    if (!a) return NULL;
    size_t cap = len * ARENA_PER_BYTE;
    if (cap < ARENA_MIN) cap = ARENA_MIN;
    a->base = malloc(cap);
    if (!a->base) { free(a); return NULL; }
    a->cap = cap;
    a->used = 0;

    bencode_value *root = arena_alloc(a, sizeof(*root));
    if (!root) goto fail;

    parser p = { .buf = buf, .len = len, .pos = 0, .depth = 0, .arena = a };
    if (parse_value(&p, root) < 0) goto fail;
    if (p.pos != len) goto fail;                    /* reject trailing data */

    *arena_out = a;
    return root;

fail:
    free(a->base);
    free(a);
    return NULL;
}

void
bencode_free(bencode_arena *a)
{
    if (!a) return;
    free(a->base);
    free(a);
}

const bencode_value *
bencode_dict_get(const bencode_value *d, const char *key)
{
    if (!d || d->type != BENCODE_DICT) return NULL;
    size_t kl = strlen(key);
    for (size_t i = 0; i < d->dict.len; i++) {
        const struct bencode_dict_entry *e = &d->dict.entries[i];
        if (e->key_len == kl && memcmp(e->key, key, kl) == 0) {
            return e->val;
        }
    }
    return NULL;
}
