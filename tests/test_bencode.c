#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bencode.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

static void
expect_bytes(const char *what, const uint8_t *got, size_t got_len,
             const char *want, size_t want_len)
{
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        fprintf(stderr, "FAIL %s: bytes mismatch\n", what);
        fprintf(stderr, "  want (%zu): ", want_len);
        for (size_t i = 0; i < want_len; i++) fprintf(stderr, "%02x", (unsigned char)want[i]);
        fprintf(stderr, "\n  got  (%zu): ", got_len);
        for (size_t i = 0; i < got_len; i++) fprintf(stderr, "%02x", got[i]);
        fputc('\n', stderr);
        failures++;
    }
}

static void
test_encode_int(void)
{
    uint8_t buf[32];
    bencode_writer w;

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_int(&w, 42);
    expect_bytes("int 42", buf, (size_t)bencode_writer_finish(&w), "i42e", 4);

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_int(&w, -7);
    expect_bytes("int -7", buf, (size_t)bencode_writer_finish(&w), "i-7e", 4);

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_int(&w, 0);
    expect_bytes("int 0", buf, (size_t)bencode_writer_finish(&w), "i0e", 3);
}

static void
test_encode_str(void)
{
    uint8_t buf[32];
    bencode_writer w;

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_cstr(&w, "hello");
    expect_bytes("str hello", buf, (size_t)bencode_writer_finish(&w), "5:hello", 7);

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_str(&w, "", 0);
    expect_bytes("str empty", buf, (size_t)bencode_writer_finish(&w), "0:", 2);

    /* binary safe */
    bencode_writer_init(&w, buf, sizeof(buf));
    const uint8_t bin[] = { 0x00, 0xff, 0x7f };
    bencode_str(&w, bin, sizeof(bin));
    expect_bytes("str bin", buf, (size_t)bencode_writer_finish(&w),
                 "3:\x00\xff\x7f", 5);
}

static void
test_encode_list(void)
{
    uint8_t buf[64];
    bencode_writer w;

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_list_open(&w);
    bencode_cstr(&w, "spam");
    bencode_int(&w, 42);
    bencode_list_close(&w);
    expect_bytes("list", buf, (size_t)bencode_writer_finish(&w),
                 "l4:spami42ee", 12);
}

static void
test_encode_dict(void)
{
    uint8_t buf[64];
    bencode_writer w;

    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_dict_open(&w);
    bencode_cstr(&w, "bar");
    bencode_int(&w, 2);
    bencode_cstr(&w, "foo");
    bencode_int(&w, 1);
    bencode_dict_close(&w);
    expect_bytes("dict", buf, (size_t)bencode_writer_finish(&w),
                 "d3:bari2e3:fooi1ee", 18);
}

static void
test_encode_overflow(void)
{
    uint8_t buf[4];
    bencode_writer w;
    bencode_writer_init(&w, buf, sizeof(buf));
    bencode_cstr(&w, "this is too long");
    EXPECT(bencode_writer_finish(&w) == -1);
}

static void
test_decode_int(void)
{
    bencode_arena *a;
    bencode_value *v = bencode_parse("i42e", 4, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->type == BENCODE_INT);
        EXPECT(v->i == 42);
        bencode_free(a);
    }

    v = bencode_parse("i-7e", 4, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->i == -7);
        bencode_free(a);
    }

    v = bencode_parse("i0e", 3, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->i == 0);
        bencode_free(a);
    }
}

static void
test_decode_str(void)
{
    bencode_arena *a;
    bencode_value *v = bencode_parse("5:hello", 7, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->type == BENCODE_STR);
        EXPECT(v->str.len == 5);
        EXPECT(memcmp(v->str.bytes, "hello", 5) == 0);
        bencode_free(a);
    }

    v = bencode_parse("0:", 2, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->str.len == 0);
        bencode_free(a);
    }
}

static void
test_decode_list(void)
{
    bencode_arena *a;
    bencode_value *v = bencode_parse("l4:spami42ee", 12, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->type == BENCODE_LIST);
        EXPECT(v->list.len == 2);
        EXPECT(v->list.items[0]->type == BENCODE_STR);
        EXPECT(v->list.items[0]->str.len == 4);
        EXPECT(memcmp(v->list.items[0]->str.bytes, "spam", 4) == 0);
        EXPECT(v->list.items[1]->type == BENCODE_INT);
        EXPECT(v->list.items[1]->i == 42);
        bencode_free(a);
    }
}

static void
test_decode_dict(void)
{
    bencode_arena *a;
    bencode_value *v = bencode_parse("d3:bari2e3:fooi1ee", 18, &a);
    EXPECT(v != NULL);
    if (v) {
        EXPECT(v->type == BENCODE_DICT);
        EXPECT(v->dict.len == 2);
        const bencode_value *foo = bencode_dict_get(v, "foo");
        EXPECT(foo != NULL && foo->type == BENCODE_INT && foo->i == 1);
        const bencode_value *bar = bencode_dict_get(v, "bar");
        EXPECT(bar != NULL && bar->type == BENCODE_INT && bar->i == 2);
        EXPECT(bencode_dict_get(v, "baz") == NULL);
        bencode_free(a);
    }
}

static void
test_decode_reject(void)
{
    bencode_arena *a;
    /* unsorted dict keys */
    EXPECT(bencode_parse("d3:fooi1e3:bari2ee", 18, &a) == NULL);
    /* duplicate dict keys */
    EXPECT(bencode_parse("d3:fooi1e3:fooi2ee", 18, &a) == NULL);
    /* leading zero integer */
    EXPECT(bencode_parse("i03e", 4, &a) == NULL);
    /* negative zero */
    EXPECT(bencode_parse("i-0e", 4, &a) == NULL);
    /* empty integer */
    EXPECT(bencode_parse("ie", 2, &a) == NULL);
    /* non-digit string length */
    EXPECT(bencode_parse("a:x", 3, &a) == NULL);
    /* trailing data */
    EXPECT(bencode_parse("i42eX", 5, &a) == NULL);
    /* unterminated list */
    EXPECT(bencode_parse("l4:spam", 7, &a) == NULL);
    /* unterminated dict */
    EXPECT(bencode_parse("d3:fooi1e", 9, &a) == NULL);
    /* string length exceeds buffer */
    EXPECT(bencode_parse("9:hi", 4, &a) == NULL);
    /* dict key not a string */
    EXPECT(bencode_parse("di1ei2ee", 8, &a) == NULL);
    /* lone 'e' */
    EXPECT(bencode_parse("e", 1, &a) == NULL);
}

static void
test_roundtrip(void)
{
    uint8_t buf[256];
    bencode_writer w;
    bencode_writer_init(&w, buf, sizeof(buf));

    /* Build d3:fooi1e3:lstl1:ai2eee — covers nested list inside dict */
    bencode_dict_open(&w);
    bencode_cstr(&w, "foo");
    bencode_int(&w, 1);
    bencode_cstr(&w, "lst");
    bencode_list_open(&w);
    bencode_cstr(&w, "a");
    bencode_int(&w, 2);
    bencode_list_close(&w);
    bencode_dict_close(&w);

    ssize_t n = bencode_writer_finish(&w);
    EXPECT(n > 0);

    bencode_arena *a;
    bencode_value *v = bencode_parse(buf, (size_t)n, &a);
    EXPECT(v != NULL);
    if (v) {
        const bencode_value *foo = bencode_dict_get(v, "foo");
        EXPECT(foo && foo->type == BENCODE_INT && foo->i == 1);
        const bencode_value *lst = bencode_dict_get(v, "lst");
        EXPECT(lst && lst->type == BENCODE_LIST && lst->list.len == 2);
        EXPECT(lst->list.items[0]->type == BENCODE_STR);
        EXPECT(lst->list.items[1]->i == 2);
        bencode_free(a);
    }
}

static void
test_bep44_signable_fixture(void)
{
    /* BEP 44 signable bytes for salt="foo", seq=5, v="hello":
     *   4:salt3:foo3:seqi5e1:v5:hello
     * Built piece-by-piece (no outer dict — that's the spec).
     */
    uint8_t buf[64];
    bencode_writer w;
    bencode_writer_init(&w, buf, sizeof(buf));

    bencode_cstr(&w, "salt"); bencode_cstr(&w, "foo");
    bencode_cstr(&w, "seq");  bencode_int(&w, 5);
    bencode_cstr(&w, "v");    bencode_cstr(&w, "hello");

    expect_bytes("BEP 44 signable", buf, (size_t)bencode_writer_finish(&w),
                 "4:salt3:foo3:seqi5e1:v5:hello", 29);
}

int
main(void)
{
    test_encode_int();
    test_encode_str();
    test_encode_list();
    test_encode_dict();
    test_encode_overflow();
    test_decode_int();
    test_decode_str();
    test_decode_list();
    test_decode_dict();
    test_decode_reject();
    test_roundtrip();
    test_bep44_signable_fixture();

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: bencode\n", stderr);
    return 0;
}
