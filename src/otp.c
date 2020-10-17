#include "hmac.h"
#include <math.h>
#include <stdlib.h>

int compute_otp(char *sha, uint8_t *secret, unsigned int block_size,
                uint8_t *counter, int digit_count) {
  int offset = 0;
  int bin_code = 0;
  int otp = 0;

  struct HASH_RESULT hmac_hash = compute_hmac(sha, secret, block_size, counter);
  offset = hmac_hash.hash[hmac_hash.hash_len - 1] & 0xF;
  bin_code = (hmac_hash.hash[offset] & 0x7f) << 24 |
             (hmac_hash.hash[offset + 1] & 0xFF) << 16 |
             (hmac_hash.hash[offset + 2] & 0xFF) << 8 |
             (hmac_hash.hash[offset + 3] & 0xFF);
  otp = (bin_code % (int)pow(10, (double)digit_count));
  free(hmac_hash.hash);
  return otp;
}
