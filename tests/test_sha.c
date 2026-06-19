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

static void test_sha256_basic(void) {
    uint8_t out[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256_ctx *ctx = encripto_sha256_new();
    TEST("sha256_ctx_alloc", ctx != NULL);
    encripto_sha256_update(ctx, (const uint8_t *)"hello", 5);
    encripto_sha256_final(ctx, out);
    encripto_sha256_free(ctx);
}

static void test_sha512_basic(void) {
    uint8_t out[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_ctx *ctx = encripto_sha512_new();
    TEST("sha512_ctx_alloc", ctx != NULL);
    encripto_sha512_update(ctx, (const uint8_t *)"hello", 5);
    encripto_sha512_final(ctx, out);
    encripto_sha512_free(ctx);
}

int main(void) {
    test_sha256_basic();
    test_sha512_basic();
    if (failed) {
        printf("SHA tests: FAILED\n");
        return 1;
    }
    printf("SHA tests: PASSED\n");
    return 0;
}
