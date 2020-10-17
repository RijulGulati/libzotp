#ifndef SHA_HEADER_FILE
#define SHA_HEADER_FILE

#include <stdint.h>

struct HASH_RESULT {
  uint8_t *hash;
  unsigned int hash_len;
};

void compute_sha(char *sha, uint8_t *message1, unsigned int message1_size,
                 uint8_t *message2, unsigned int message2_size, uint8_t *hash,
                 unsigned int *hash_len);

#endif
