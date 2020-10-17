#include "base32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int base32_decode(uint8_t *input, uint8_t *output) {

  // uint8_t MAP[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
  //                       0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
  //                       0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
  //                       0x59, 0x5A, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

  uint8_t *ch;
  int i = 0;
  int temp = 0;
  int curr_char_val = 0;
  int bit_count = 5;
  int required_bits = 0;

  for (ch = input; *ch != '\0'; ch++) {
    if (*ch >= 'A' && *ch <= 'Z') {
      curr_char_val = *ch - 65;
    } else if (*ch >= '2' && *ch <= '7') {
      curr_char_val = *ch - 24;
    } else {
      return -1;
    }
    if (required_bits > 0) {
      if (required_bits > 5) {
        temp = temp | (curr_char_val << (required_bits - 5));
        bit_count += 5;
        required_bits = 8 - bit_count;
        continue;
      } else {
        temp |= curr_char_val >> (5 - required_bits);
        bit_count += required_bits;
      }
    }

    if (bit_count == 8) {
      output[i++] = temp << 0;
      if (required_bits > 0) {
        temp = (curr_char_val << (8 - (5 - required_bits))) & 0xFF;
        required_bits = 8 - (5 - required_bits);
        bit_count = 8 - required_bits;
      }
    } else {
      temp |= curr_char_val << (8 - bit_count);
      required_bits = 8 - bit_count;
    }
  }
  return 0;
}
