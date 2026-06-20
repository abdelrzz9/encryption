#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name(void)

#define ASSERT_EQ_HEX(got, expected, len) do { \
    if (memcmp(got, expected, len) != 0) { \
        fprintf(stderr, "  FAIL [%s:%d]: digest mismatch\n", __FILE__, __LINE__); \
        fprintf(stderr, "    got:      "); print_hex(got, len); \
        fprintf(stderr, "    expected: "); print_hex(expected, len); \
        tests_failed++; \
        return; \
    } \
    tests_passed++; \
} while(0)

static void hex_decode(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        uint8_t b = 0;
        if (hi >= '0' && hi <= '9')      b = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') b = (hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') b = (hi - 'A' + 10) << 4;
        if (lo >= '0' && lo <= '9')      b |= (lo - '0');
        else if (lo >= 'a' && lo <= 'f') b |= (lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') b |= (lo - 'A' + 10);
        out[i] = b;
    }
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\n");
}

#endif /* TEST_UTILS_H */
