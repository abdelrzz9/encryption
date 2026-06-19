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

static void test_chacha20_encrypt_decrypt(void) {
    uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE] = {0};
    uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE] = {0};
    uint8_t pt[32] = {0};
    uint8_t ct[32];
    uint8_t dec[32];

    encripto_chacha20_ctx *ctx = encripto_chacha20_new(key, nonce);
    TEST("chacha20_ctx_alloc", ctx != NULL);

    encripto_chacha20_encrypt(ctx, pt, 32, ct);
    encripto_chacha20_decrypt(ctx, ct, 32, dec);
    TEST("chacha20_roundtrip", memcmp(pt, dec, 32) == 0);

    encripto_chacha20_free(ctx);
}

int main(void) {
    test_chacha20_encrypt_decrypt();
    if (failed) {
        printf("ChaCha20 tests: FAILED\n");
        return 1;
    }
    printf("ChaCha20 tests: PASSED\n");
    return 0;
}
