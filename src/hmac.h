
#ifndef HMAC_HEADER_FILE
#define HMAC_HEADER_FILE

#include "sha.h"

struct HASH_RESULT compute_hmac(char *sha, uint8_t *secret,
                                unsigned int block_size, uint8_t *message);

#endif
