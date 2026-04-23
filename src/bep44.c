#include "bep44.h"

#include <string.h>

#include <openssl/evp.h>
#include <sodium.h>

#include "bencode.h"

/* ============================================================
 * SHA-1 helpers
 * ============================================================ */

static void
sha1_two(uint8_t out[20], const void *a, size_t alen, const void *b, size_t blen)
{
    unsigned int n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    if (alen) EVP_DigestUpdate(ctx, a, alen);
    if (blen) EVP_DigestUpdate(ctx, b, blen);
    EVP_DigestFinal_ex(ctx, out, &n);
    EVP_MD_CTX_free(ctx);
}

void
bep44_target(uint8_t out[BEP44_TARGET_LEN],
             const uint8_t pk[BEP44_PK_LEN],
             const uint8_t *salt, size_t salt_len)
{
    sha1_two(out, pk, BEP44_PK_LEN, salt, salt_len);
}

void
bep44_immutable_target(uint8_t out[BEP44_TARGET_LEN],
                       const uint8_t *v_bencoded, size_t v_len)
{
    sha1_two(out, v_bencoded, v_len, NULL, 0);
}

/* ============================================================
 * Signable bytes / sign / verify
 * ============================================================ */

ssize_t
bep44_signable(uint8_t *out, size_t out_cap,
               const uint8_t *salt, size_t salt_len,
               int64_t seq,
               const uint8_t *v_bencoded, size_t v_len)
{
    if (salt_len > BEP44_MAX_SALT) return -1;
    if (v_len > BEP44_MAX_V) return -1;

    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);
    if (salt_len > 0) {
        bencode_cstr(&w, "salt");
        bencode_str(&w, salt, salt_len);
    }
    bencode_cstr(&w, "seq");
    bencode_int(&w, seq);
    bencode_cstr(&w, "v");
    bencode_raw(&w, v_bencoded, v_len);
    return bencode_writer_finish(&w);
}

int
bep44_sign(uint8_t out[BEP44_SIG_LEN],
           const uint8_t sk[BEP44_SK_LEN],
           const uint8_t *signable, size_t signable_len)
{
    if (crypto_sign_detached(out, NULL, signable, signable_len, sk) != 0) {
        return -1;
    }
    return 0;
}

int
bep44_verify(const uint8_t sig[BEP44_SIG_LEN],
             const uint8_t pk[BEP44_PK_LEN],
             const uint8_t *signable, size_t signable_len)
{
    return crypto_sign_verify_detached(sig, signable, signable_len, pk) == 0
        ? 0 : -1;
}

/* ============================================================
 * KRPC message builders
 *
 * Each builder constructs an outer dict with keys in strict alphabetical
 * order. The `a`/`r` sub-dict keys are also strictly ordered.
 * ============================================================ */

ssize_t
bep44_build_get_query(uint8_t *out, size_t out_cap,
                      const uint8_t *tid, size_t tid_len,
                      const uint8_t our_id[BEP44_NODE_ID_LEN],
                      const uint8_t target[BEP44_TARGET_LEN],
                      const int64_t *seq)
{
    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "a");
        bencode_dict_open(&w);
            bencode_cstr(&w, "id");     bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
            if (seq) {
                bencode_cstr(&w, "seq"); bencode_int(&w, *seq);
            }
            bencode_cstr(&w, "target"); bencode_str(&w, target, BEP44_TARGET_LEN);
        bencode_dict_close(&w);
        bencode_cstr(&w, "q");          bencode_cstr(&w, "get");
        bencode_cstr(&w, "t");          bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");          bencode_cstr(&w, "q");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_put_query_mutable(uint8_t *out, size_t out_cap,
                              const uint8_t *tid, size_t tid_len,
                              const uint8_t our_id[BEP44_NODE_ID_LEN],
                              const uint8_t pk[BEP44_PK_LEN],
                              const uint8_t *salt, size_t salt_len,
                              int64_t seq,
                              const int64_t *cas,
                              const uint8_t sig[BEP44_SIG_LEN],
                              const uint8_t *token, size_t token_len,
                              const uint8_t *v_bencoded, size_t v_len)
{
    if (salt_len > BEP44_MAX_SALT) return -1;
    if (v_len > BEP44_MAX_V) return -1;

    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "a");
        bencode_dict_open(&w);
            /* sub-dict order: cas, id, k, salt, seq, sig, token, v */
            if (cas) {
                bencode_cstr(&w, "cas");   bencode_int(&w, *cas);
            }
            bencode_cstr(&w, "id");        bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
            bencode_cstr(&w, "k");         bencode_str(&w, pk, BEP44_PK_LEN);
            if (salt_len > 0) {
                bencode_cstr(&w, "salt");  bencode_str(&w, salt, salt_len);
            }
            bencode_cstr(&w, "seq");       bencode_int(&w, seq);
            bencode_cstr(&w, "sig");       bencode_str(&w, sig, BEP44_SIG_LEN);
            bencode_cstr(&w, "token");     bencode_str(&w, token, token_len);
            bencode_cstr(&w, "v");         bencode_raw(&w, v_bencoded, v_len);
        bencode_dict_close(&w);
        bencode_cstr(&w, "q");             bencode_cstr(&w, "put");
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "q");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_put_query_immutable(uint8_t *out, size_t out_cap,
                                const uint8_t *tid, size_t tid_len,
                                const uint8_t our_id[BEP44_NODE_ID_LEN],
                                const uint8_t *token, size_t token_len,
                                const uint8_t *v_bencoded, size_t v_len)
{
    if (v_len > BEP44_MAX_V) return -1;

    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "a");
        bencode_dict_open(&w);
            bencode_cstr(&w, "id");        bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
            bencode_cstr(&w, "token");     bencode_str(&w, token, token_len);
            bencode_cstr(&w, "v");         bencode_raw(&w, v_bencoded, v_len);
        bencode_dict_close(&w);
        bencode_cstr(&w, "q");             bencode_cstr(&w, "put");
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "q");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_put_response(uint8_t *out, size_t out_cap,
                         const uint8_t *tid, size_t tid_len,
                         const uint8_t our_id[BEP44_NODE_ID_LEN])
{
    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "r");
        bencode_dict_open(&w);
            bencode_cstr(&w, "id");        bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
        bencode_dict_close(&w);
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "r");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_get_response_mutable(uint8_t *out, size_t out_cap,
                                 const uint8_t *tid, size_t tid_len,
                                 const uint8_t our_id[BEP44_NODE_ID_LEN],
                                 const uint8_t pk[BEP44_PK_LEN],
                                 const uint8_t *nodes, size_t nodes_len,
                                 int64_t seq,
                                 const uint8_t sig[BEP44_SIG_LEN],
                                 const uint8_t *token, size_t token_len,
                                 const uint8_t *v_bencoded, size_t v_len)
{
    if (v_len > BEP44_MAX_V) return -1;

    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "r");
        bencode_dict_open(&w);
            /* order: id, k, nodes, seq, sig, token, v */
            bencode_cstr(&w, "id");        bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
            bencode_cstr(&w, "k");         bencode_str(&w, pk, BEP44_PK_LEN);
            if (nodes_len > 0) {
                bencode_cstr(&w, "nodes"); bencode_str(&w, nodes, nodes_len);
            }
            bencode_cstr(&w, "seq");       bencode_int(&w, seq);
            bencode_cstr(&w, "sig");       bencode_str(&w, sig, BEP44_SIG_LEN);
            bencode_cstr(&w, "token");     bencode_str(&w, token, token_len);
            bencode_cstr(&w, "v");         bencode_raw(&w, v_bencoded, v_len);
        bencode_dict_close(&w);
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "r");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_get_response_immutable(uint8_t *out, size_t out_cap,
                                   const uint8_t *tid, size_t tid_len,
                                   const uint8_t our_id[BEP44_NODE_ID_LEN],
                                   const uint8_t *nodes, size_t nodes_len,
                                   const uint8_t *token, size_t token_len,
                                   const uint8_t *v_bencoded, size_t v_len)
{
    if (v_len > BEP44_MAX_V) return -1;

    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "r");
        bencode_dict_open(&w);
            bencode_cstr(&w, "id");        bencode_str(&w, our_id, BEP44_NODE_ID_LEN);
            if (nodes_len > 0) {
                bencode_cstr(&w, "nodes"); bencode_str(&w, nodes, nodes_len);
            }
            bencode_cstr(&w, "token");     bencode_str(&w, token, token_len);
            bencode_cstr(&w, "v");         bencode_raw(&w, v_bencoded, v_len);
        bencode_dict_close(&w);
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "r");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}

ssize_t
bep44_build_error(uint8_t *out, size_t out_cap,
                  const uint8_t *tid, size_t tid_len,
                  int64_t code, const char *msg)
{
    bencode_writer w;
    bencode_writer_init(&w, out, out_cap);

    bencode_dict_open(&w);
        bencode_cstr(&w, "e");
        bencode_list_open(&w);
            bencode_int(&w, code);
            bencode_cstr(&w, msg ? msg : "");
        bencode_list_close(&w);
        bencode_cstr(&w, "t");             bencode_str(&w, tid, tid_len);
        bencode_cstr(&w, "y");             bencode_cstr(&w, "e");
    bencode_dict_close(&w);

    return bencode_writer_finish(&w);
}
