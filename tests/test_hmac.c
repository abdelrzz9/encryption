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

static int digest_matches(const uint8_t *digest, const char *expected_hex,
                          size_t len) {
    uint8_t expected[len];
    hex_to_bytes(expected_hex, expected, len);
    return encripto_hmac_verify(digest, expected, len) == 0;
}

/* ── RFC 4231 Test Case 1 ─────────────────────────────────── */

static void test_case1_sha256(void) {
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t *data = (const uint8_t *)"Hi There";
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 20, data, 8, out);
    TEST("case1_sha256",
         digest_matches(out,
             "b0344c61d8db38535ca8afceaf0bf12b"
             "881dc200c9833da726e9376c2e32cff7",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case1_sha512(void) {
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t *data = (const uint8_t *)"Hi There";
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 20, data, 8, out);
    TEST("case1_sha512",
         digest_matches(out,
             "87aa7cdea5ef619d4ff0b4241a1d6cb0"
             "2379f4e2ce4ec2787ad0b30545e17cde"
             "daa833b7d6b8a702038b274eaea3f4e4"
             "be9d914eeb61f1702e696c203a126854",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── RFC 4231 Test Case 2 ─────────────────────────────────── */

static void test_case2_sha256(void) {
    const uint8_t *key = (const uint8_t *)"Jefe";
    const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 4, data, 28, out);
    TEST("case2_sha256",
         digest_matches(out,
             "5bdcc146bf60754e6a042426089575c7"
             "5a003f089d2739839dec58b964ec3843",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case2_sha512(void) {
    const uint8_t *key = (const uint8_t *)"Jefe";
    const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 4, data, 28, out);
    TEST("case2_sha512",
         digest_matches(out,
             "164b7a7bfcf819e2e395fbe73b56e0a3"
             "87bd64222e831fd610270cd7ea250554"
             "9758bf75c05a994a6d034f65f8f0e6fd"
             "caeab1a34d4a6b4b636e070a38bce737",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── RFC 4231 Test Case 3 ─────────────────────────────────── */

static void test_case3_sha256(void) {
    uint8_t key[20];
    uint8_t data[50];
    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 20, data, 50, out);
    TEST("case3_sha256",
         digest_matches(out,
             "773ea91e36800e46854db8ebd09181a7"
             "2959098b3ef8c122d9635514ced565fe",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case3_sha512(void) {
    uint8_t key[20];
    uint8_t data[50];
    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 20, data, 50, out);
    TEST("case3_sha512",
         digest_matches(out,
             "fa73b0089d56a284efb0f0756c890be9"
             "b1b5dbdd8ee81a3655f83e33b2279d39"
             "bf3e848279a722c806b485a47e67c807"
             "b946a337bee8942674278859e13292fb",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── RFC 4231 Test Case 4 ─────────────────────────────────── */

static void test_case4_sha256(void) {
    uint8_t key[25];
    uint8_t data[50];
    for (size_t i = 0; i < 25; i++) key[i] = i + 1;
    memset(data, 0xcd, 50);
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 25, data, 50, out);
    TEST("case4_sha256",
         digest_matches(out,
             "82558a389a443c0ea4cc819899f2083a"
             "85f0faa3e578f8077a2e3ff46729665b",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case4_sha512(void) {
    uint8_t key[25];
    uint8_t data[50];
    for (size_t i = 0; i < 25; i++) key[i] = i + 1;
    memset(data, 0xcd, 50);
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 25, data, 50, out);
    TEST("case4_sha512",
         digest_matches(out,
             "b0ba465637458c6990e5a8c5f61d4af7"
             "e576d97ff94b872de76f8050361ee3db"
             "a91ca5c11aa25eb4d679275cc5788063"
             "a5f19741120c4f2de2adebeb10a298dd",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── RFC 4231 Test Case 6 (key > block size) ──────────────── */

static void test_case6_sha256(void) {
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const uint8_t *data = (const uint8_t *)
        "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 131, data, 54, out);
    TEST("case6_sha256",
         digest_matches(out,
             "60e431591ee0b67f0d8a26aacbf5b77f"
             "8e0bc6213728c5140546040f0ee37f54",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case6_sha512(void) {
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const uint8_t *data = (const uint8_t *)
        "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 131, data, 54, out);
    TEST("case6_sha512",
         digest_matches(out,
             "80b24263c7c1a3ebb71493c1dd7be8b4"
             "9b46d1f41b4aeec1121b013783f8f352"
             "6b56d037e05f2598bd0fd2215d6a1e52"
             "95e64f73f63f0aec8b915a985d786598",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── RFC 4231 Test Case 7 (key > block size, long data) ───── */

static void test_case7_sha256(void) {
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const uint8_t *data = (const uint8_t *)
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.";
    uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE];
    encripto_hmac_sha256(key, 131, data, 152, out);
    TEST("case7_sha256",
         digest_matches(out,
             "9b09ffa71b942fcb27635fbcd5b0e944"
             "bfdc63644f0713938a7f51535c3a35e2",
             ENCRIPTO_HMAC_SHA256_DIGEST_SIZE));
}

static void test_case7_sha512(void) {
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const uint8_t *data = (const uint8_t *)
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.";
    uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE];
    encripto_hmac_sha512(key, 131, data, 152, out);
    TEST("case7_sha512",
         digest_matches(out,
             "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
             "debd71f8867289865df5a32d20cdc944"
             "b6022cac3c4982b10d5eeb55c3e4de15"
             "134676fb6de0446065c97440fa8c6a58",
             ENCRIPTO_HMAC_SHA512_DIGEST_SIZE));
}

/* ── Constant-time verify tests ───────────────────────────── */

static void test_verify_match(void) {
    uint8_t a[8] = {1,2,3,4,5,6,7,8};
    uint8_t b[8] = {1,2,3,4,5,6,7,8};
    TEST("verify_match", encripto_hmac_verify(a, b, 8) == 0);
}

static void test_verify_mismatch(void) {
    uint8_t a[8] = {1,2,3,4,5,6,7,8};
    uint8_t b[8] = {1,2,3,4,5,6,7,9};
    TEST("verify_mismatch", encripto_hmac_verify(a, b, 8) != 0);
}

int main(void) {
    test_case1_sha256();
    test_case1_sha512();
    test_case2_sha256();
    test_case2_sha512();
    test_case3_sha256();
    test_case3_sha512();
    test_case4_sha256();
    test_case4_sha512();
    test_case6_sha256();
    test_case6_sha512();
    test_case7_sha256();
    test_case7_sha512();
    test_verify_match();
    test_verify_mismatch();

    if (failed) {
        printf("HMAC tests: FAILED\n");
        return 1;
    }
    printf("HMAC tests: PASSED\n");
    return 0;
}
