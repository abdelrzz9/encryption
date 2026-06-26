#include "encripto.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ_HEX(got, expected, len) do { \
    if (memcmp(got, expected, len) != 0) { \
        fprintf(stderr, "  FAIL [%s:%d]: tag mismatch\n", __FILE__, __LINE__); \
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

/* ── RFC 8439 Section 2.5.2 Poly1305 Test Vector ──────────── */

static void test_rfc8439_vector(void) {
    uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    };
    const uint8_t msg[] = "Cryptographic Forum Research Group";
    uint8_t expected_tag[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9,
    };

    printf("  RFC 8439 Section 2.5.2 test vector ... ");
    encripto_poly1305_ctx ctx;
    uint8_t tag[16];
    int ret;

    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, sizeof(msg) - 1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag, expected_tag, 16);
    printf("PASS\n");
}

/* ── Streaming test (same message, split into small chunks) ─ */

static void test_streaming(void) {
    uint8_t key[32];
    const uint8_t msg[] = "Cryptographic Forum Research Group";
    uint8_t expected_tag[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9,
    };
    size_t msg_len = sizeof(msg) - 1;
    int ret;

    memcpy(key, (uint8_t[]){
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    }, 32);

    printf("  streaming (byte by byte) ... ");
    encripto_poly1305_ctx ctx;
    uint8_t tag[16];
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    for (size_t i = 0; i < msg_len; i++) {
        ret = encripto_poly1305_update(&ctx, msg + i, 1);
        if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    }
    ret = encripto_poly1305_final(&ctx, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag, expected_tag, 16);
    printf("PASS\n");
}

/* ── Empty message ────────────────────────────────────────── */

static void test_empty(void) {
    uint8_t key[32];
    memcpy(key, (uint8_t[]){
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    }, 32);

    printf("  empty message ... ");
    encripto_poly1305_ctx ctx;
    uint8_t tag[16];
    int ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    /* No update call */
    ret = encripto_poly1305_final(&ctx, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    /* Tag for empty message = s = key[16..31] serialized */
    uint8_t expected_tag[16];
    for (int i = 0; i < 16; i++)
        expected_tag[i] = key[16 + i];
    ASSERT_EQ_HEX(tag, expected_tag, 16);
    printf("PASS\n");
}

/* ── Single-block message (exactly 16 bytes) ──────────────── */

static void test_single_block(void) {
    uint8_t key[32] = {0};
    uint8_t msg[16];
    uint8_t tag[16];
    encripto_poly1305_ctx ctx;
    int ret;

    memset(msg, 0x42, 16);

    printf("  single-block (16 bytes) ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 16);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    /* Compute expected manually: block = msg || 0x01 (as le128) = 0x014242...42
       acc = (0 + block) * r mod P = block * r mod P
       With key=0, r=0, s=0: tag = (block * 0) + 0 = 0 */
    uint8_t expected[16] = {0};
    ASSERT_EQ_HEX(tag, expected, 16);
    printf("PASS\n");
}

/* ── Exact multiples of block size (32 and 48 bytes) ──────── */

static void test_multi_block(void) {
    uint8_t key[32];
    uint8_t msg[48];
    uint8_t tag1[16], tag2[16];
    encripto_poly1305_ctx ctx;
    int ret;

    memset(key, 0xAA, 32);
    for (int i = 0; i < 48; i++)
        msg[i] = (uint8_t)i;

    printf("  two-block (32 bytes) same as single update ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 32);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 16);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg + 16, 16);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag1, tag2, 16);
    printf("PASS\n");

    printf("  three-block (48 bytes) streaming ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 48);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    for (int i = 0; i < 3; i++) {
        ret = encripto_poly1305_update(&ctx, msg + i * 16, 16);
        if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    }
    ret = encripto_poly1305_final(&ctx, tag2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag1, tag2, 16);
    printf("PASS\n");
}

/* ── Partial last block (not 16-byte aligned) ─────────────── */

static void test_partial_block(void) {
    uint8_t key[32];
    uint8_t msg[20];
    uint8_t tag1[16], tag2[16];
    encripto_poly1305_ctx ctx;
    int ret;

    memset(key, 0xBB, 32);
    for (int i = 0; i < 20; i++)
        msg[i] = (uint8_t)(i * 3);

    printf("  partial last block (20 bytes) ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 20);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    /* Same result when split as 16 + 4 */
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 16);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg + 16, 4);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag1, tag2, 16);
    printf("PASS\n");
}

/* ── Different keys produce different tags ────────────────── */

static void test_key_dependence(void) {
    uint8_t key1[32] = {0};
    uint8_t key2[32];
    uint8_t msg[] = "Hello, Poly1305!";
    uint8_t tag1[16], tag2[16];
    encripto_poly1305_ctx ctx;
    int ret;

    memset(key2, 0xFF, 32);

    printf("  different keys produce different tags ... ");
    ret = encripto_poly1305_init(&ctx, key1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, sizeof(msg) - 1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    ret = encripto_poly1305_init(&ctx, key2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, sizeof(msg) - 1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    if (memcmp(tag1, tag2, 16) == 0) {
        fprintf(stderr, "FAIL: tags are identical for different keys\n");
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── Context is zeroed after final ─────────────────────────── */

static void test_ctx_zeroed(void) {
    uint8_t key[32] = {0};
    uint8_t msg[] = "test";
    encripto_poly1305_ctx ctx;
    uint8_t tag[16];
    int ret;

    printf("  context zeroed after final() ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, sizeof(msg) - 1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    /* After final(), the context should be zeroed */
    const uint8_t *vp = (const uint8_t *)&ctx;
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(ctx); i++) {
        if (vp[i] != 0) { all_zero = 0; break; }
    }
    if (!all_zero) {
        fprintf(stderr, "FAIL: context not zeroed\n");
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── NULL parameter tests ─────────────────────────────────── */

static void test_null_params(void) {
    encripto_poly1305_ctx ctx;
    uint8_t key[32] = {0};
    uint8_t tag[16];
    uint8_t buf[16] = {0};
    int ok = 1;

    printf("  NULL parameter checks ... ");
    if (encripto_poly1305_init(NULL, key) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_poly1305_init(&ctx, NULL) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_poly1305_update(NULL, buf, 16) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_poly1305_update(&ctx, NULL, 16) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_poly1305_final(NULL, tag) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (encripto_poly1305_final(&ctx, NULL) != ENCRIPTO_ERR_PARAM) ok = 0;
    if (!ok) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");
}

/* ── Large message test (stress test) ──────────────────────── */

static void test_large_message(void) {
    uint8_t key[32];
    uint8_t msg[10000];
    encripto_poly1305_ctx ctx;
    uint8_t tag1[16], tag2[16];
    int ret;

    memset(key, 0x42, 32);
    for (int i = 0; i < 10000; i++)
        msg[i] = (uint8_t)(i * 7 + 11);

    printf("  large message (10000 bytes, one-shot) ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_update(&ctx, msg, 10000);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ret = encripto_poly1305_final(&ctx, tag1);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    tests_passed++; printf("PASS\n");

    printf("  large message (10000 bytes, streamed) ... ");
    ret = encripto_poly1305_init(&ctx, key);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    for (int i = 0; i < 10000; i += 3) {
        size_t chunk = (10000 - i < 3) ? (10000 - i) : 3;
        ret = encripto_poly1305_update(&ctx, msg + i, chunk);
        if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    }
    ret = encripto_poly1305_final(&ctx, tag2);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }
    ASSERT_EQ_HEX(tag1, tag2, 16);
    printf("PASS\n");
}

/* ── RFC 8439 Section 2.8.2 ChaCha20-Poly1305 AEAD Test Vector ── */

static void test_aead_rfc8439(void) {
    uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47,
    };
    uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7,
    };
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
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
        0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
        0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
        0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
        0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
        0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16,
    };
    uint8_t expected_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };

    printf("  RFC 8439 Section 2.8.2 AEAD ... ");
    uint8_t ct[sizeof(pt)];
    uint8_t tag[16];
    int ret = encripto_chacha20_poly1305_encrypt(
        key, nonce, pt, sizeof(pt), aad, sizeof(aad), ct, tag);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: encrypt returned %d\n",ret); tests_failed++; return; }
    ASSERT_EQ_HEX(ct, expected_ct, sizeof(pt));
    ASSERT_EQ_HEX(tag, expected_tag, 16);

    uint8_t decrypted[sizeof(pt)];
    ret = encripto_chacha20_poly1305_decrypt(
        key, nonce, ct, sizeof(ct), aad, sizeof(aad), tag, decrypted);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: decrypt returned %d\n",ret); tests_failed++; return; }
    ASSERT_EQ_HEX(decrypted, pt, sizeof(pt));
    printf("PASS\n");
}

static void test_aead_empty_aad(void) {
    uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47,
    };
    uint8_t pt[3] = {0x01,0x02,0x03};
    uint8_t expected_ct[3];
    uint8_t expected_tag[16];

    printf("  AEAD empty AAD ... ");
    int ret = encripto_chacha20_poly1305_encrypt(
        key, nonce, pt, sizeof(pt), NULL, 0, expected_ct, expected_tag);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: encrypt returned %d\n",ret); tests_failed++; return; }

    uint8_t decrypted[3];
    ret = encripto_chacha20_poly1305_decrypt(
        key, nonce, expected_ct, sizeof(expected_ct), NULL, 0, expected_tag, decrypted);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: decrypt returned %d\n",ret); tests_failed++; return; }
    ASSERT_EQ_HEX(decrypted, pt, sizeof(pt));
    printf("PASS\n");
}

static void test_aead_empty_pt(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[5] = {0x01,0x02,0x03,0x04,0x05};
    uint8_t tag[16];

    printf("  AEAD empty plaintext ... ");
    int ret = encripto_chacha20_poly1305_encrypt(
        key, nonce, (const uint8_t*)"", 0, aad, sizeof(aad), (uint8_t*)"", tag);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: encrypt returned %d\n",ret); tests_failed++; return; }

    uint8_t pt_out;
    ret = encripto_chacha20_poly1305_decrypt(
        key, nonce, (const uint8_t*)"", 0, aad, sizeof(aad), tag, &pt_out);
    if (ret != ENCRIPTO_OK) { fprintf(stderr,"  FAIL: decrypt returned %d\n",ret); tests_failed++; return; }
    printf("PASS\n");
}

static void test_aead_tamper_tag(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[4] = {0xde,0xad,0xbe,0xef};
    uint8_t ct[4];
    uint8_t tag[16];

    printf("  AEAD tampered tag rejected ... ");
    int ret = encripto_chacha20_poly1305_encrypt(
        key, nonce, pt, sizeof(pt), NULL, 0, ct, tag);
    if (ret != ENCRIPTO_OK) { tests_failed++; return; }

    tag[0] ^= 0x01;
    uint8_t decrypted[4];
    ret = encripto_chacha20_poly1305_decrypt(
        key, nonce, ct, sizeof(ct), NULL, 0, tag, decrypted);
    if (ret != ENCRIPTO_ERR_AUTH) {
        fprintf(stderr,"  FAIL: expected ENCRIPTO_ERR_AUTH, got %d\n",ret);
        tests_failed++; return;
    }
    printf("PASS\n");
}

int main(void) {
    printf("Poly1305 / ChaCha20-Poly1305 tests:\n");

    printf("  RFC test vector:\n");
    test_rfc8439_vector();

    printf("  Streaming:\n");
    test_streaming();

    printf("  Edge cases:\n");
    test_empty();
    test_single_block();
    test_multi_block();
    test_partial_block();

    printf("  Key dependence:\n");
    test_key_dependence();

    printf("  Context zeroization:\n");
    test_ctx_zeroed();

    printf("  Parameter validation:\n");
    test_null_params();

    printf("  Large message:\n");
    test_large_message();

    printf("  AEAD:\n");
    test_aead_rfc8439();
    test_aead_empty_aad();
    test_aead_empty_pt();
    test_aead_tamper_tag();

    if (tests_failed > 0) {
        printf("\nPoly1305: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nPoly1305: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
