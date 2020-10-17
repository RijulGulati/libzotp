#ifndef OTP_HEADER_FILE
#define OTP_HEADER_FILE

#include <stdint.h>

int compute_otp(char *sha, uint8_t *secret, unsigned int block_size,
                uint8_t *counter, int digit_count);

#endif
