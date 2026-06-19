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

static int digest512_matches(const uint8_t *digest, const char *expected_hex) {
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    hex_to_bytes(expected_hex, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    return memcmp(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE) == 0;
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

/* ── SHA-512 NIST test vectors ────────────────────────────── */

static void test_sha512_nist_empty(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512(NULL, 0, d);
    TEST("sha512_nist_empty",
         digest512_matches(d, "cf83e1357eefb8bdf1542850d66d8007"
                               "d620e4050b5715dc83f4a921d36ce9ce"
                               "47d0d13c5d85f2b0ff8318d2877eec2f"
                               "63b931bd47417a81a538327af927da3e"));
}

static void test_sha512_nist_abc(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512((const uint8_t *)"abc", 3, d);
    TEST("sha512_nist_abc",
         digest512_matches(d, "ddaf35a193617abacc417349ae204131"
                               "12e6fa4e89a97ea20a9eeee64b55d39a"
                               "2192992a274fc1a836ba3c23a3feebbd"
                               "454d4423643ce80e2a9ac94fa54ca49f"));
}

static void test_sha512_nist_long(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    encripto_sha512((const uint8_t *)msg, strlen(msg), d);
    TEST("sha512_nist_long",
         digest512_matches(d, "204a8fc6dda82f0a0ced7beb8e08a416"
                               "57c16ef468b228a8279be331a703c335"
                               "96fd15c13b1b07f9aa1d3bea57789ca0"
                               "31ad85c7a71dd70354ec631238ca3445"));
}

static void test_sha512_nist_million_a(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_ctx ctx;
    encripto_sha512_init(&ctx);

    uint8_t buf[4096];
    memset(buf, 'a', sizeof(buf));
    size_t remaining = 1000000;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        encripto_sha512_update(&ctx, buf, chunk);
        remaining -= chunk;
    }
    encripto_sha512_final(&ctx, d);

    TEST("sha512_nist_million_a",
         digest512_matches(d, "e718483d0ce769644e2e42c7bc15b463"
                               "8e1f98b13b2044285632a803afa973eb"
                               "de0ff244877ea60a4cb0432ce577c31b"
                               "eb009c5c2c49aa2e4eadb217ad8cc09b"));
}

/* ── SHA-512 Streaming API tests ──────────────────────────── */

static void test_sha512_stream_abc(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_ctx ctx;
    encripto_sha512_init(&ctx);
    encripto_sha512_update(&ctx, (const uint8_t *)"a", 1);
    encripto_sha512_update(&ctx, (const uint8_t *)"b", 1);
    encripto_sha512_update(&ctx, (const uint8_t *)"c", 1);
    encripto_sha512_final(&ctx, d);
    TEST("sha512_stream_abc",
         digest512_matches(d, "ddaf35a193617abacc417349ae204131"
                               "12e6fa4e89a97ea20a9eeee64b55d39a"
                               "2192992a274fc1a836ba3c23a3feebbd"
                               "454d4423643ce80e2a9ac94fa54ca49f"));
}

static void test_sha512_stream_chunked_long(void) {
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t len = strlen(msg);
    encripto_sha512_ctx ctx;
    encripto_sha512_init(&ctx);

    for (size_t i = 0; i < len; i++)
        encripto_sha512_update(&ctx, (const uint8_t *)msg + i, 1);

    encripto_sha512_final(&ctx, d);
    TEST("sha512_stream_chunked_long",
         digest512_matches(d, "204a8fc6dda82f0a0ced7beb8e08a416"
                               "57c16ef468b228a8279be331a703c335"
                               "96fd15c13b1b07f9aa1d3bea57789ca0"
                               "31ad85c7a71dd70354ec631238ca3445"));
}

static void test_sha512_ctx_zeroed_after_final(void) {
    encripto_sha512_ctx ctx;
    uint8_t d[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_init(&ctx);
    encripto_sha512_update(&ctx, (const uint8_t *)"abc", 3);
    encripto_sha512_final(&ctx, d);

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(ctx); i++) {
        if (((const uint8_t *)&ctx)[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST("sha512_ctx_zeroed", all_zero);
}

/* ── SHA-256 Streaming API tests ──────────────────────────── */

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

    test_sha512_nist_empty();
    test_sha512_nist_abc();
    test_sha512_nist_long();
    test_sha512_nist_million_a();
    test_sha512_stream_abc();
    test_sha512_stream_chunked_long();
    test_sha512_ctx_zeroed_after_final();

    if (failed) {
        printf("SHA-512 tests: FAILED\n");
        return 1;
    }
    printf("SHA-512 tests: PASSED\n");
    return 0;
}
