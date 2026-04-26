#ifndef DHT44_BEP44_H
#define DHT44_BEP44_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef BEP44_PK_LEN
#define BEP44_PK_LEN     32
#endif
#ifndef BEP44_SK_LEN
#define BEP44_SK_LEN     64
#endif
#ifndef BEP44_SIG_LEN
#define BEP44_SIG_LEN    64
#endif
#ifndef BEP44_TARGET_LEN
#define BEP44_TARGET_LEN 20
#endif
#ifndef BEP44_NODE_ID_LEN
#define BEP44_NODE_ID_LEN 20
#endif
#ifndef BEP44_MAX_SALT
#define BEP44_MAX_SALT   64
#endif
#ifndef BEP44_MAX_V
#define BEP44_MAX_V      1000
#endif
#ifndef BEP44_VALUE_MAX
#define BEP44_VALUE_MAX  BEP44_MAX_V
#endif

/* SHA-1 hashes used by BEP 44.  All output buffers are 20 bytes. */

void bep44_target(uint8_t out[BEP44_TARGET_LEN],
                  const uint8_t pk[BEP44_PK_LEN],
                  const uint8_t *salt, size_t salt_len);

void bep44_immutable_target(uint8_t out[BEP44_TARGET_LEN],
                            const uint8_t *v_bencoded, size_t v_len);

/*
 * Build the BEP 44 "signable" bytes:
 *
 *   [4:salt<L>:<salt>]3:seqi<seq>e1:v<v_bencoded>
 *
 * — concatenated bencode key/value pairs with NO outer dict. The salt section
 * is omitted entirely when salt_len == 0. v_bencoded must already be bencoded
 * (e.g. "5:hello", not "hello").
 *
 * Returns the number of bytes written, or -1 on overflow / oversized fields
 * (salt > 64 or v > 1000).
 */
ssize_t bep44_signable(uint8_t *out, size_t out_cap,
                       const uint8_t *salt, size_t salt_len,
                       int64_t seq,
                       const uint8_t *v_bencoded, size_t v_len);

/*
 * Sign signable bytes with an Ed25519 secret key (libsodium 64-byte form).
 * Returns 0 on success, -1 on failure.
 */
int bep44_sign(uint8_t out[BEP44_SIG_LEN],
               const uint8_t sk[BEP44_SK_LEN],
               const uint8_t *signable, size_t signable_len);

/* Returns 0 if signature verifies, -1 otherwise. */
int bep44_verify(const uint8_t sig[BEP44_SIG_LEN],
                 const uint8_t pk[BEP44_PK_LEN],
                 const uint8_t *signable, size_t signable_len);

/* ===== KRPC message builders =====
 *
 * All builders write into a caller-supplied buffer and return bytes written
 * (or -1 on overflow). Dict keys are emitted in strict alphabetical order as
 * required by BEP 5 / BEP 44.
 *
 * Outer dict order: (a|e|r), q, t, y.
 *   put query  → a, q, t, y
 *   get query  → a, q, t, y
 *   response   → r, t, y
 *   error      → e, t, y
 *
 * `a` (put, mutable):     id, k, salt, seq, sig, token, v   (cas inserted before sig)
 * `a` (put, immutable):   id, token, v
 * `a` (get):              id, target  [+ seq if non-NULL]
 * `r` (put response):     id
 * `r` (get response, mut):id, k, nodes, seq, sig, token, v
 * `r` (get response, imm):id, nodes, token, v
 */

ssize_t bep44_build_get_query(uint8_t *out, size_t out_cap,
                              const uint8_t *tid, size_t tid_len,
                              const uint8_t our_id[BEP44_NODE_ID_LEN],
                              const uint8_t target[BEP44_TARGET_LEN],
                              const int64_t *seq /* NULL if absent */);

ssize_t bep44_build_put_query_mutable(uint8_t *out, size_t out_cap,
                                      const uint8_t *tid, size_t tid_len,
                                      const uint8_t our_id[BEP44_NODE_ID_LEN],
                                      const uint8_t pk[BEP44_PK_LEN],
                                      const uint8_t *salt, size_t salt_len,
                                      int64_t seq,
                                      const int64_t *cas /* NULL if absent */,
                                      const uint8_t sig[BEP44_SIG_LEN],
                                      const uint8_t *token, size_t token_len,
                                      const uint8_t *v_bencoded, size_t v_len);

ssize_t bep44_build_put_query_immutable(uint8_t *out, size_t out_cap,
                                        const uint8_t *tid, size_t tid_len,
                                        const uint8_t our_id[BEP44_NODE_ID_LEN],
                                        const uint8_t *token, size_t token_len,
                                        const uint8_t *v_bencoded, size_t v_len);

ssize_t bep44_build_put_response(uint8_t *out, size_t out_cap,
                                 const uint8_t *tid, size_t tid_len,
                                 const uint8_t our_id[BEP44_NODE_ID_LEN]);

ssize_t bep44_build_get_response_mutable(uint8_t *out, size_t out_cap,
                                         const uint8_t *tid, size_t tid_len,
                                         const uint8_t our_id[BEP44_NODE_ID_LEN],
                                         const uint8_t pk[BEP44_PK_LEN],
                                         const uint8_t *nodes, size_t nodes_len,
                                         int64_t seq,
                                         const uint8_t sig[BEP44_SIG_LEN],
                                         const uint8_t *token, size_t token_len,
                                         const uint8_t *v_bencoded, size_t v_len);

ssize_t bep44_build_get_response_immutable(uint8_t *out, size_t out_cap,
                                           const uint8_t *tid, size_t tid_len,
                                           const uint8_t our_id[BEP44_NODE_ID_LEN],
                                           const uint8_t *nodes, size_t nodes_len,
                                           const uint8_t *token, size_t token_len,
                                           const uint8_t *v_bencoded, size_t v_len);

ssize_t bep44_build_error(uint8_t *out, size_t out_cap,
                          const uint8_t *tid, size_t tid_len,
                          int64_t code, const char *msg);

#endif
