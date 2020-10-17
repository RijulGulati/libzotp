#include <openssl/evp.h>

void compute_sha(char *sha, uint8_t *message1, unsigned int message1_size,
                 uint8_t *message2, unsigned int message2_size, uint8_t *hash,
                 unsigned int *hash_len) {

  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  md = EVP_get_digestbyname(sha);
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, message1, message1_size);
  EVP_DigestUpdate(mdctx, message2, message2_size);
  EVP_DigestFinal_ex(mdctx, hash, hash_len);
  EVP_MD_CTX_free(mdctx);
}
