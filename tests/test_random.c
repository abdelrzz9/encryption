#include "encripto.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failed = 0;

#define TEST(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        failed = 1; \
    } \
} while (0)

#define SAMPLE_SIZE 8192

static void test_rand_bytes_basic(void) {
    uint8_t buf[256];
    TEST("rand_bytes_basic", encripto_rand_bytes(buf, sizeof(buf)) == 0);
}

static void test_rand_bytes_null(void) {
    int ret = encripto_rand_bytes(NULL, 16);
    TEST("rand_bytes_null", ret == -EINVAL);
}

static void test_rand_bytes_empty(void) {
    uint8_t buf[16];
    int ret = encripto_rand_bytes(buf, 0);
    TEST("rand_bytes_empty", ret == -EINVAL);
}

static void test_rand_key_basic(void) {
    uint8_t key[32];
    TEST("rand_key_basic", encripto_rand_key(key, sizeof(key)) == 0);
}

static void test_rand_key_empty(void) {
    uint8_t key[32];
    int ret = encripto_rand_key(key, 0);
    TEST("rand_key_empty", ret == -EINVAL);
}

static void test_chi_squared(void) {
    uint8_t buf[SAMPLE_SIZE];
    if (encripto_rand_bytes(buf, sizeof(buf)) != 0) {
        TEST("chi_squared_alloc", 0);
        return;
    }

    unsigned long counts[256];
    memset(counts, 0, sizeof(counts));
    for (size_t i = 0; i < SAMPLE_SIZE; i++)
        counts[buf[i]]++;

    double expected = (double)SAMPLE_SIZE / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)counts[i] - expected;
        chi2 += (diff * diff) / expected;
    }

    /* Critical value for 255 df at α = 0.05 is ~293; use 350 for safety */
    TEST("chi_squared_random", chi2 < 350.0);
}

int main(void) {
    test_rand_bytes_basic();
    test_rand_bytes_null();
    test_rand_bytes_empty();
    test_rand_key_basic();
    test_rand_key_empty();
    test_chi_squared();

    if (failed) {
        printf("Random tests: FAILED\n");
        return 1;
    }
    printf("Random tests: PASSED\n");
    return 0;
}
