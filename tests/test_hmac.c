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

static void test_hmac_basic(void) {
    uint8_t key[16] = {0};
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];

    encripto_hmac_ctx *ctx = encripto_hmac_new(key, sizeof(key));
    TEST("hmac_ctx_alloc", ctx != NULL);

    encripto_hmac_update(ctx, (const uint8_t *)"data", 4);
    encripto_hmac_final_sha256(ctx, out);
    encripto_hmac_free(ctx);
}

int main(void) {
    test_hmac_basic();
    if (failed) {
        printf("HMAC tests: FAILED\n");
        return 1;
    }
    printf("HMAC tests: PASSED\n");
    return 0;
}
