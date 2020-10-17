#ifndef ZOTP_ANDOTP_HEADER_FILE
#define ZOTP_ANDOTP_HEADER_FILE

#include <stdint.h>

void andotp_encrypt(uint8_t *source_file, uint8_t *dest_file,
                    uint8_t *password);
void andotp_decrypt(uint8_t *file, uint8_t *password, uint8_t **decrypted_text,
                    long *decrypted_text_len);

#endif
