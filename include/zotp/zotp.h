#ifndef ZOTP_HEADER_FILE
#define ZOTP_HEADER_FILE

#include <stdint.h>
#include <time.h>

void zotp_compute_otp(char *sha, uint8_t *secret, time_t time, int period,
                      int digit_count, char *otp);

#endif
