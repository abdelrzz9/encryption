#include "encripto.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ_HEX(got, expected, len) do { \
    if (memcmp(got, expected, len) != 0) { \
        fprintf(stderr, "  FAIL [%s:%d]: digest mismatch\n", __FILE__, __LINE__); \
        fprintf(stderr, "    got:      "); \
        for (size_t _i = 0; _i < (len); _i++) fprintf(stderr, "%02x", ((uint8_t*)(got))[_i]); \
        fprintf(stderr, "\n    expected: "); \
        for (size_t _i = 0; _i < (len); _i++) fprintf(stderr, "%02x", ((uint8_t*)(expected))[_i]); \
        fprintf(stderr, "\n"); \
        tests_failed++; \
        return; \
    } \
    tests_passed++; \
} while(0)

/* ── RFC 8439 Section 2.1.1: Quarter Round Test Vector ────── */

static void test_quarter_round(void) {
    uint32_t a = 0x11111111, b = 0x01020304;
    uint32_t c = 0x9b8d6f43, d = 0x01234567;

    /* Manually inline quarter round to test it */
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d <<  8) | (d >> 24);
    c += d; b ^= c; b = (b <<  7) | (b >> 25);

    uint32_t exp_a = 0xea2a92f4, exp_b = 0xcb1cf8ce;
    uint32_t exp_c = 0x4581472e, exp_d = 0x5881c4bb;

    printf("  RFC 8439 Section 2.1.1 quarter round ... ");
    if (a != exp_a || b != exp_b || c != exp_c || d != exp_d) {
        fprintf(stderr, "FAIL: got 0x%08x 0x%08x 0x%08x 0x%08x\n",
                a, b, c, d);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── RFC 8439 Section 2.3.2: ChaCha20 Block Function Test ─── */

static void test_block_function(void) {
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    /* Nonce for Section 2.3.2: 00:00:00:09:00:00:00:4a:00:00:00:00 */
    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00,
    };
    uint32_t counter = 1;

    /* Encrypt 64 zero bytes -> output = keystream */
    uint8_t zeros[64] = {0};
    uint8_t ks[64];
    int ret = encripto_chacha20_encrypt(key, counter, nonce, zeros, 64, ks);
    printf("  RFC 8439 Section 2.3.2 block function ... ");
    if (ret != ENCRIPTO_OK) {
        fprintf(stderr, "FAIL: encrypt returned %d\n", ret);
        tests_failed++;
        return;
    }

    uint8_t expected[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
        0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
        0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
        0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
        0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e,
    };
    ASSERT_EQ_HEX(ks, expected, 64);
    printf("PASS\n");
}

/* ── RFC 8439 Section 2.4.2: Full ChaCha20 Test Vector ────── */

static void test_full_chacha20(void) {
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00,
    };
    /* Plaintext: "Ladies and Gentlemen of the class of '99: ..." */
    const uint8_t pt[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
        0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,
        0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
        0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
        0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,
        0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,
        0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e,
    };
    uint8_t expected_ct[114] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,
        0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
        0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,
        0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
        0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,
        0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
        0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,
        0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
        0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,
        0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
        0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,
        0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
        0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,
        0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
        0x87,0x4d,
    };

    printf("  RFC 8439 Section 2.4.2 full ChaCha20 encrypt ... ");
    uint8_t ct[114];
    int ret = encripto_chacha20_encrypt(key, 1, nonce, pt, 114, ct);
    if (ret != ENCRIPTO_OK) {
        fprintf(stderr, "FAIL: encrypt returned %d\n", ret);
        tests_failed++;
        return;
    }
    ASSERT_EQ_HEX(ct, expected_ct, 114);
    printf("PASS\n");

    printf("  RFC 8439 Section 2.4.2 full ChaCha20 decrypt ... ");
    uint8_t dec[114];
    ret = encripto_chacha20_encrypt(key, 1, nonce, ct, 114, dec);
    if (ret != ENCRIPTO_OK) {
        fprintf(stderr, "FAIL: decrypt returned %d\n", ret);
        tests_failed++;
        return;
    }
    ASSERT_EQ_HEX(dec, pt, 114);
    printf("PASS\n");
}

/* ── Roundtrip tests ──────────────────────────────────────── */

static void test_roundtrips(void) {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t pt[256];
    uint8_t ct[256];
    uint8_t dec[256];
    int ret;

    memset(key, 0, 32);
    memset(nonce, 0, 12);

    printf("  roundtrip 0 bytes ... ");
    ret = encripto_chacha20_encrypt(key, 0, nonce, (const uint8_t *)"", 0, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");

    printf("  roundtrip 1 byte ... ");
    uint8_t one = 0x42;
    ret = encripto_chacha20_encrypt(key, 0, nonce, &one, 1, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_chacha20_encrypt(key, 0, nonce, ct, 1, dec);
    if (ret != ENCRIPTO_OK || dec[0] != 0x42) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");

    printf("  roundtrip 64 bytes (exactly one block) ... ");
    memset(pt, 0xAA, 64);
    ret = encripto_chacha20_encrypt(key, 0, nonce, pt, 64, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_chacha20_encrypt(key, 0, nonce, ct, 64, dec);
    if (ret != ENCRIPTO_OK || memcmp(pt, dec, 64) != 0) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");

    printf("  roundtrip 100 bytes (multi-block) ... ");
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)i;
    ret = encripto_chacha20_encrypt(key, 0, nonce, pt, 100, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_chacha20_encrypt(key, 0, nonce, ct, 100, dec);
    if (ret != ENCRIPTO_OK || memcmp(pt, dec, 100) != 0) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");

    printf("  roundtrip 255 bytes (non-zero key/nonce) ... ");
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 7);
    for (int i = 0; i < 255; i++) pt[i] = (uint8_t)(255 - i);
    ret = encripto_chacha20_encrypt(key, 42, nonce, pt, 255, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_chacha20_encrypt(key, 42, nonce, ct, 255, dec);
    if (ret != ENCRIPTO_OK || memcmp(pt, dec, 255) != 0) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");
}

/* ── Counter overflow test ────────────────────────────────── */

static void test_counter_overflow(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[64] = {0};
    uint8_t ct[64];
    uint8_t dec[64];

    printf("  counter=0xFFFFFFFF encrypt/decrypt ... ");
    int ret = encripto_chacha20_encrypt(key, 0xFFFFFFFF, nonce, pt, 64, ct);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_chacha20_encrypt(key, 0xFFFFFFFF, nonce, ct, 64, dec);
    if (ret != ENCRIPTO_OK || memcmp(pt, dec, 64) != 0) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");
}

/* ── NULL parameter tests ─────────────────────────────────── */

static void test_null_params(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t buf[16] = {0};
    int ok = 1;

    printf("  NULL parameter checks ... ");
    if (encripto_chacha20_encrypt(NULL, 0, nonce, buf, 16, buf) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_chacha20_encrypt(key, 0, NULL, buf, 16, buf) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_chacha20_encrypt(key, 0, nonce, NULL, 16, buf) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_chacha20_encrypt(key, 0, nonce, buf, 16, NULL) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (!ok) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");
}

/* ── Encrypt/Decrypt identity ─────────────────────────────── */

static void test_encrypt_decrypt_identity(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[128];
    uint8_t ct1[128], ct2[128];

    for (int i = 0; i < 128; i++) pt[i] = (uint8_t)(i * 3 + 7);

    printf("  encrypt then decrypt (same as encrypt) returns original ... ");
    encripto_chacha20_encrypt(key, 0, nonce, pt, 128, ct1);
    encripto_chacha20_encrypt(key, 0, nonce, ct1, 128, ct2);
    if (memcmp(pt, ct2, 128) != 0) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");
}

int main(void) {
    printf("ChaCha20 tests:\n");

    printf("  Quarter round:\n");
    test_quarter_round();

    printf("  Block function:\n");
    test_block_function();

    printf("  Full ChaCha20 test vector:\n");
    test_full_chacha20();

    printf("  Roundtrip:\n");
    test_roundtrips();

    printf("  Encrypt/decrypt identity:\n");
    test_encrypt_decrypt_identity();

    printf("  Counter overflow:\n");
    test_counter_overflow();

    printf("  Parameter validation:\n");
    test_null_params();

    if (tests_failed > 0) {
        printf("\nChaCha20: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nChaCha20: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
