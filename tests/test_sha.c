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

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        uint8_t b = 0;
        if (hi >= '0' && hi <= '9')      b = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') b = (hi - 'a' + 10) << 4;
        if (lo >= '0' && lo <= '9')      b |= (lo - '0');
        else if (lo >= 'a' && lo <= 'f') b |= (lo - 'a' + 10);
        out[i] = b;
    }
}

static int digest_matches(const uint8_t *digest, const char *expected_hex) {
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    hex_to_bytes(expected_hex, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    return memcmp(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE) == 0;
}

/* ── NIST test vectors ────────────────────────────────────── */

static void test_nist_empty_string(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256(NULL, 0, d);
    TEST("nist_empty",
         digest_matches(d, "e3b0c44298fc1c149afbf4c8996fb924"
                            "27ae41e4649b934ca495991b7852b855"));
}

static void test_nist_abc(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256((const uint8_t *)"abc", 3, d);
    TEST("nist_abc",
         digest_matches(d, "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad"));
}

static void test_nist_long(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    encripto_sha256((const uint8_t *)msg, strlen(msg), d);
    TEST("nist_long",
         digest_matches(d, "248d6a61d20638b8e5c026930c3e6039"
                            "a33ce45964ff2167f6ecedd419db06c1"));
}

static void test_nist_million_a(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256_ctx ctx;
    encripto_sha256_init(&ctx);

    uint8_t buf[4096];
    memset(buf, 'a', sizeof(buf));
    size_t remaining = 1000000;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        encripto_sha256_update(&ctx, buf, chunk);
        remaining -= chunk;
    }
    encripto_sha256_final(&ctx, d);

    TEST("nist_million_a",
         digest_matches(d, "cdc76e5c9914fb9281a1c7e284d73e67"
                            "f1809a48a497200e046d39ccc7112cd0"));
}

/* ── Streaming API tests ──────────────────────────────────── */

static void test_streaming_abc(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256_ctx ctx;
    encripto_sha256_init(&ctx);
    encripto_sha256_update(&ctx, (const uint8_t *)"a", 1);
    encripto_sha256_update(&ctx, (const uint8_t *)"b", 1);
    encripto_sha256_update(&ctx, (const uint8_t *)"c", 1);
    encripto_sha256_final(&ctx, d);
    TEST("stream_abc",
         digest_matches(d, "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad"));
}

static void test_streaming_chunked_long(void) {
    uint8_t d[ENCRIPTO_SHA256_DIGEST_SIZE];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t len = strlen(msg);
    encripto_sha256_ctx ctx;
    encripto_sha256_init(&ctx);

    for (size_t i = 0; i < len; i++)
        encripto_sha256_update(&ctx, (const uint8_t *)msg + i, 1);

    encripto_sha256_final(&ctx, d);
    TEST("stream_chunked_long",
         digest_matches(d, "248d6a61d20638b8e5c026930c3e6039"
                            "a33ce45964ff2167f6ecedd419db06c1"));
}

int main(void) {
    test_nist_empty_string();
    test_nist_abc();
    test_nist_long();
    test_nist_million_a();
    test_streaming_abc();
    test_streaming_chunked_long();

    if (failed) {
        printf("SHA-256 tests: FAILED\n");
        return 1;
    }
    printf("SHA-256 tests: PASSED\n");
    return 0;
}
