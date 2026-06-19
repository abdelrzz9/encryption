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

static void test_aes256_encrypt_decrypt(void) {
    uint8_t key[ENCRIPTO_AES256_KEY_SIZE] = {0};
    uint8_t pt[ENCRIPTO_AES256_BLOCK_SIZE] = {0};
    uint8_t ct[ENCRIPTO_AES256_BLOCK_SIZE];
    uint8_t dec[ENCRIPTO_AES256_BLOCK_SIZE];

    encripto_aes256_ctx *ctx = encripto_aes256_new(key);
    TEST("aes256_ctx_alloc", ctx != NULL);

    encripto_aes256_encrypt(ctx, pt, ct);
    encripto_aes256_decrypt(ctx, ct, dec);
    TEST("aes256_roundtrip", memcmp(pt, dec, ENCRIPTO_AES256_BLOCK_SIZE) == 0);

    encripto_aes256_free(ctx);
}

int main(void) {
    test_aes256_encrypt_decrypt();
    if (failed) {
        printf("AES tests: FAILED\n");
        return 1;
    }
    printf("AES tests: PASSED\n");
    return 0;
}
