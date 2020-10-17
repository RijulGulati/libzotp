#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#define IV_LEN 12
#define SALT_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32
#define ITERATION_LEN 4
#define MAX_ITERATIONS 160000
#define MIN_ITERATIONS 140000

int aes_gcm_encrypt_decrypt(char *operation, uint8_t *intext, int intext_len,
                            uint8_t *tag, uint8_t *key, uint8_t *iv,
                            uint8_t *outtext) {

  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int text_len = 0;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  if (strcmp(operation, "dec") == 0) {
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
      return -1;
  } else {
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
      return -1;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
    return -1;

  if (strcmp(operation, "dec") == 0) {
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
      return -1;
    if (1 != EVP_DecryptUpdate(ctx, outtext, &len, intext, intext_len))
      return -1;
  } else {
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
      return -1;
    if (1 != EVP_EncryptUpdate(ctx, outtext, &len, intext, intext_len))
      return -1;
  }
  text_len = len;

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
    return -1;

  if (strcmp(operation, "dec") == 0) {
    if (1 != EVP_DecryptFinal_ex(ctx, outtext + len, &len))
      return -1;

  } else {
    if (1 != EVP_EncryptFinal_ex(ctx, outtext + len, &len))
      return -1;
  }

  text_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return text_len;
}

int andotp_encrypt(uint8_t *source_file, uint8_t *dest_file,
                   uint8_t *password) {

  int len = 0;

  uint8_t iv[IV_LEN + 1];
  uint8_t salt[SALT_LEN + 1];
  uint8_t tag[TAG_LEN + 1];
  uint8_t iteration_bytes[ITERATION_LEN + 1];
  uint8_t *ciphertext;
  int ciphertext_len = 0;
  uint8_t pbkdf2_key[KEY_LEN + 1];
  int iterations = 0;
  uint8_t *final_cipher;
  long final_cipher_len = 0;
  uint8_t *buffer;

  FILE *fp = fopen((char *)source_file, "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    buffer = malloc(sizeof(uint8_t *) * (len + 1));
    fseek(fp, 0, SEEK_SET);
    fread(buffer, 1, len, fp);
    fclose(fp);

    ciphertext = malloc(sizeof(uint8_t *) *
                        (len + ITERATION_LEN + SALT_LEN + IV_LEN + 1));

    RAND_bytes(iv, IV_LEN);
    RAND_bytes(salt, SALT_LEN);

    srand((unsigned)time(NULL));
    iterations =
        (rand() % (MAX_ITERATIONS - MIN_ITERATIONS + 1)) + MIN_ITERATIONS;

    iteration_bytes[0] = (iterations >> 24) & 0xFF;
    iteration_bytes[1] = (iterations >> 16) & 0xFF;
    iteration_bytes[2] = (iterations >> 8) & 0xFF;
    iteration_bytes[3] = iterations & 0xFF;
    iteration_bytes[4] = '\0';

    PKCS5_PBKDF2_HMAC_SHA1((char *)password, strlen((char *)password), salt,
                           SALT_LEN, iterations, KEY_LEN, pbkdf2_key);

    ciphertext_len = aes_gcm_encrypt_decrypt("enc", buffer, len, tag,
                                             pbkdf2_key, iv, ciphertext);

    final_cipher_len =
        ciphertext_len + ITERATION_LEN + SALT_LEN + IV_LEN + TAG_LEN;
    final_cipher = malloc(final_cipher_len + 1);

    memcpy(final_cipher, iteration_bytes, ITERATION_LEN);
    memcpy(final_cipher + ITERATION_LEN, salt, SALT_LEN);
    memcpy(final_cipher + ITERATION_LEN + SALT_LEN, iv, IV_LEN);
    memcpy(final_cipher + ITERATION_LEN + SALT_LEN + IV_LEN, ciphertext,
           ciphertext_len);
    memcpy(final_cipher + ITERATION_LEN + SALT_LEN + IV_LEN + ciphertext_len,
           tag, TAG_LEN + 1);

    FILE *fp2 = fopen((char *)dest_file, "w");
    if (fp2) {
      size_t s = fwrite(final_cipher, 1, final_cipher_len, fp2);
      fclose(fp2);
      free(final_cipher);
      free(buffer);
      free(ciphertext);

      if (s > 0) {
        return 0;
      } else {
        return -1;
      }
    } else {
      return -1;
    }
  } else {
    return -2;
  }
}

void andotp_decrypt(uint8_t *file, uint8_t *password, uint8_t **decrypted_text,
                    long *decrypted_text_len) {

  FILE *fp = fopen((char *)file, "rb");
  int iterations = 0;
  uint8_t salt[SALT_LEN + 1];
  uint8_t pbkdf2_key[KEY_LEN + 1];
  uint8_t iv[IV_LEN + 1];
  uint8_t tag[TAG_LEN + 1];
  uint8_t *encrypted_text = NULL;
  uint8_t *buffer = NULL;

  bzero(salt, SALT_LEN + 1);
  bzero(pbkdf2_key, KEY_LEN + 1);
  bzero(iv, IV_LEN + 1);
  bzero(tag, TAG_LEN + 1);

  if (fp) {

    long len = 0;
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_text = malloc(sizeof(uint8_t *) *
                            (len - (ITERATION_LEN + SALT_LEN + IV_LEN) + 1));
    buffer = malloc(sizeof(uint8_t *) * (len + 1));
    *decrypted_text = malloc(sizeof(uint8_t *) *
                             (len - ITERATION_LEN - SALT_LEN - IV_LEN + 1));
    bzero(buffer, sizeof(uint8_t *) * (len + 1));
    bzero(encrypted_text,
          sizeof(uint8_t *) * (len - (ITERATION_LEN + SALT_LEN + IV_LEN) + 1));
    bzero(*decrypted_text,
          sizeof(uint8_t *) * (len - ITERATION_LEN - SALT_LEN - IV_LEN + 1));

    fread(buffer, 1, len, fp);
    fclose(fp);

    iterations = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) |
                 (buffer[3] << 0);

    memcpy(salt, &buffer[4], SALT_LEN);
    memcpy(iv, &buffer[ITERATION_LEN + SALT_LEN], IV_LEN);
    memcpy(encrypted_text, &buffer[ITERATION_LEN + SALT_LEN + IV_LEN],
           len - 16);
    memcpy(tag, &buffer[len - 16], TAG_LEN);

    PKCS5_PBKDF2_HMAC_SHA1((char *)password, strlen((char *)password), salt,
                           SALT_LEN, iterations, KEY_LEN, pbkdf2_key);

    *decrypted_text_len = aes_gcm_encrypt_decrypt(
        "dec", encrypted_text, len - 44, tag, pbkdf2_key, iv, *decrypted_text);

    free(buffer);
    free(encrypted_text);
  }
}
