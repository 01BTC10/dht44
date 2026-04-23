/*
 * Symbols required by vendor/jech-dht/dht.c. The init/bootstrap/loop layer
 * lands in a later commit; only the four jech-required callbacks live here
 * for now so commit 1 links cleanly.
 */

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <sodium.h>

#include "dht.h"

int
dht_sendto(int sockfd, const void *buf, int len, int flags,
           const struct sockaddr *to, int tolen)
{
    return sendto(sockfd, buf, (size_t)len, flags, to, (socklen_t)tolen);
}

int
dht_blacklisted(const struct sockaddr *sa, int salen)
{
    (void)sa;
    (void)salen;
    return 0;
}

void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, v1, (size_t)len1);
    EVP_DigestUpdate(ctx, v2, (size_t)len2);
    EVP_DigestUpdate(ctx, v3, (size_t)len3);
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    int copy = (int)digest_len < hash_size ? (int)digest_len : hash_size;
    memcpy(hash_return, digest, (size_t)copy);
    if (copy < hash_size) {
        memset((char *)hash_return + copy, 0, (size_t)(hash_size - copy));
    }
}

int
dht_random_bytes(void *buf, size_t size)
{
    /* sodium_init() is the daemon's responsibility before this fires. */
    randombytes_buf(buf, size);
    return (int)size;
}
