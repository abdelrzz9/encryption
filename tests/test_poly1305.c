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

int main(void) {
    printf("Poly1305 tests:\n");

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

    if (tests_failed > 0) {
        printf("\nPoly1305: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nPoly1305: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
