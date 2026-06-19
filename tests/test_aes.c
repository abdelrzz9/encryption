#include "encripto.h"
#include <stdio.h>
#include <string.h>

static int failed = 0;

#define TEST(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        failed = 1; \
    } \
} while (0)

static void test_aes256_cbc_encrypt_decrypt(void) {
    uint8_t key[ENCRIPTO_AES256_KEY_SIZE] = {0};
    uint8_t iv[ENCRIPTO_AES256_IV_SIZE] = {0};
    uint8_t pt[32] = {0};
    uint8_t ct[32];
    uint8_t dec[32];
    size_t ct_len = sizeof(ct);
    size_t dec_len = sizeof(dec);

    int ret = encripto_aes256_cbc_encrypt(key, iv, pt, sizeof(pt), ct, &ct_len);
    TEST("aes256_cbc_encrypt_ok", ret == ENCRIPTO_OK);

    ret = encripto_aes256_cbc_decrypt(key, iv, ct, ct_len, dec, &dec_len);
    TEST("aes256_cbc_decrypt_ok", ret == ENCRIPTO_OK);

    TEST("aes256_cbc_roundtrip", dec_len == sizeof(pt) && memcmp(pt, dec, dec_len) == 0);
}

static void test_aes256_gcm_encrypt_decrypt(void) {
    uint8_t key[ENCRIPTO_AES256_KEY_SIZE] = {0};
    uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE] = {0};
    uint8_t pt[32] = {0};
    uint8_t ct[32];
    uint8_t dec[32];
    uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE];

    int ret = encripto_aes256_gcm_encrypt(key, iv, pt, sizeof(pt), ct, tag);
    TEST("aes256_gcm_encrypt_ok", ret == ENCRIPTO_OK);

    ret = encripto_aes256_gcm_decrypt(key, iv, ct, sizeof(pt), tag, dec);
    TEST("aes256_gcm_decrypt_ok", ret == ENCRIPTO_OK);

    TEST("aes256_gcm_roundtrip", memcmp(pt, dec, sizeof(pt)) == 0);
}

int main(void) {
    test_aes256_cbc_encrypt_decrypt();
    test_aes256_gcm_encrypt_decrypt();
    if (failed) {
        printf("AES tests: FAILED\n");
        return 1;
    }
    printf("AES tests: PASSED\n");
    return 0;
}
