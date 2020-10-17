#include "base32.h"
#include "otp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

void zotp_compute_otp(char *sha, uint8_t *secret, time_t time, int period,
                      int digit_count, char *otp) {
  int i = 0;
  int i_otp = 0;
  int block_size = 64;
  unsigned long int counter = 0;
  uint8_t hex_counter[8];
  uint8_t b32_secret[block_size + 1];
  int i_diff = 0;
  char c_zero = 0x30;
  counter = time / period;
  bzero(b32_secret, sizeof b32_secret);
  base32_decode(secret, b32_secret);

  for (i = (sizeof hex_counter) - 1; i >= 0; i--) {
    hex_counter[i] = counter & 0xFF;
    counter >>= 8;
  }

  i_otp = compute_otp(sha, b32_secret, block_size, hex_counter, digit_count);

  sprintf(otp, "%d", i_otp);
  i_diff = digit_count - strlen(otp);
  while (i_diff > 0) {
    memmove(otp + 1, otp, strlen(otp) + 1);
    memcpy(otp, &c_zero, 1);
    i_diff--;
  }
}
