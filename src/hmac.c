#include "sha.h"
#include <stdlib.h>
#include <string.h>

struct HASH_RESULT compute_hmac(char *sha, uint8_t *secret,
                                unsigned int block_size, uint8_t *message) {

  uint8_t ipad[block_size + 1];
  uint8_t opad[block_size + 1];
  uint8_t inner_hash[65];
  unsigned int hash_len = 0;
  struct HASH_RESULT hash_result;
  hash_result.hash = malloc(65);
  int i = 0;

  bzero(ipad, sizeof ipad);
  bzero(opad, sizeof opad);
  bzero(inner_hash, sizeof inner_hash);

  bcopy(secret, ipad, strlen((char *)secret));
  bcopy(secret, opad, strlen((char *)secret));

  for (i = 0; i < block_size; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5C;
  }

  compute_sha(sha, ipad, block_size, message, sizeof secret, inner_hash,
              &hash_len);
  compute_sha(sha, opad, block_size, inner_hash, hash_len, hash_result.hash,
              &hash_result.hash_len);

  return hash_result;
}
