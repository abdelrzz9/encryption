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

static void test_chacha20_poly1305_encrypt_decrypt(void) {
    uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE] = {0};
    uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE] = {0};
    uint8_t pt[32] = {0};
    uint8_t ct[32];
    uint8_t dec[32];
    uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE];

    int ret = encripto_chacha20_poly1305_encrypt(key, nonce, pt, sizeof(pt), ct, tag);
    TEST("chacha20_poly1305_encrypt_ok", ret == ENCRIPTO_OK);

    ret = encripto_chacha20_poly1305_decrypt(key, nonce, ct, sizeof(pt), tag, dec);
    TEST("chacha20_poly1305_decrypt_ok", ret == ENCRIPTO_OK);

    TEST("chacha20_poly1305_roundtrip", memcmp(pt, dec, sizeof(pt)) == 0);
}

int main(void) {
    test_chacha20_poly1305_encrypt_decrypt();
    if (failed) {
        printf("ChaCha20-Poly1305 tests: FAILED\n");
        return 1;
    }
    printf("ChaCha20-Poly1305 tests: PASSED\n");
    return 0;
}
