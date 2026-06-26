#include "encripto.h"
#include "test_utils.h"
#include <stdio.h>

/* ── FIPS 197 Appendix B: Key Expansion (first 8 key words) ─ */

static void test_key_expansion_fips197(void) {
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    uint32_t rk[60];
    uint32_t expected[60];

    encripto_aes256_key_expand(key, rk);

    expected[0]  = 0x603deb10; expected[1]  = 0x15ca71be;
    expected[2]  = 0x2b73aef0; expected[3]  = 0x857d7781;
    expected[4]  = 0x1f352c07; expected[5]  = 0x3b6108d7;
    expected[6]  = 0x2d9810a3; expected[7]  = 0x0914dff4;
    expected[8]  = 0x9ba35411; expected[9]  = 0x8e6925af;
    expected[10] = 0xa51a8b5f; expected[11] = 0x2067fcde;
    expected[12] = 0xa8b09c1a; expected[13] = 0x93d194cd;
    expected[14] = 0xbe49846e; expected[15] = 0xb75d5b9a;
    expected[16] = 0xd59aecb8; expected[17] = 0x5bf3c917;
    expected[18] = 0xfee94248; expected[19] = 0xde8ebe96;
    expected[20] = 0xb5a9328a; expected[21] = 0x2678a647;
    expected[22] = 0x98312229; expected[23] = 0x2f6c79b3;
    expected[24] = 0x812c81ad; expected[25] = 0xdadf48ba;
    expected[26] = 0x24360af2; expected[27] = 0xfab8b464;
    expected[28] = 0x98c5bfc9; expected[29] = 0xbebd198e;
    expected[30] = 0x268c3ba7; expected[31] = 0x09e04214;
    expected[32] = 0x68007bac; expected[33] = 0xb2df3316;
    expected[34] = 0x96e939e4; expected[35] = 0x6c518d80;
    expected[36] = 0xc814e204; expected[37] = 0x76a9fb8a;
    expected[38] = 0x5025c02d; expected[39] = 0x59c58239;
    expected[40] = 0xde136967; expected[41] = 0x6ccc5a71;
    expected[42] = 0xfa256395; expected[43] = 0x9674ee15;
    expected[44] = 0x5886ca5d; expected[45] = 0x2e2f31d7;
    expected[46] = 0x7e0af1fa; expected[47] = 0x27cf73c3;
    expected[48] = 0x749c47ab; expected[49] = 0x18501dda;
    expected[50] = 0xe2757e4f; expected[51] = 0x7401905a;
    expected[52] = 0xcafaaae3; expected[53] = 0xe4d59b34;
    expected[54] = 0x9adf6ace; expected[55] = 0xbd10190d;
    expected[56] = 0xfe4890d1; expected[57] = 0xe6188d0b;
    expected[58] = 0x046df344; expected[59] = 0x706c631e;

    int ok = 1;
    for (int i = 0; i < 60; i++) {
        if (rk[i] != expected[i]) {
            fprintf(stderr, "  FAIL [%s:%d]: key word W[%d] mismatch: "
                            "got 0x%08x, expected 0x%08x\n",
                    __FILE__, __LINE__, i, rk[i], expected[i]);
            ok = 0;
        }
    }

    if (!ok) {
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");

    encripto_aes256_key_clear(rk);
}

/* ── NIST AES-256 Known-Answer Tests (ECB) ───────────────── */

typedef struct {
    const uint8_t key[32];
    const uint8_t pt[16];
    const uint8_t ct[16];
} aes256_kat;

static const aes256_kat KAT_VECTORS[] = {
    {
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
         0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
         0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
         0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4},
        {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
         0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
        {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
         0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
    },
    {
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
         0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87},
    },
    {
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
         0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f},
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
         0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
         0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89},
    },
};

static void test_encrypt_kat(void) {
    for (size_t i = 0; i < sizeof(KAT_VECTORS) / sizeof(KAT_VECTORS[0]); i++) {
        const aes256_kat *v = &KAT_VECTORS[i];
        uint8_t ct[16];
        uint8_t dec[16];

        printf("  KAT vector[%zu] encrypt ... ", i);
        encripto_aes256_ctx *ctx = encripto_aes256_new(v->key);
        encripto_aes256_encrypt(ctx, v->pt, ct);
        ASSERT_EQ_HEX(ct, v->ct, 16);
        printf("PASS\n");

        printf("  KAT vector[%zu] decrypt ... ", i);
        encripto_aes256_decrypt(ctx, ct, dec);
        ASSERT_EQ_HEX(dec, v->pt, 16);
        printf("PASS\n");

        encripto_aes256_free(ctx);
    }
}

/* ── Encrypt/Decrypt roundtrip tests (ECB) ───────────────── */

static void test_roundtrip(void) {
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t dec[16];

    printf("  all-zeros key and plaintext roundtrip ... ");
    memset(key, 0, 32);
    memset(pt, 0, 16);
    encripto_aes256_ctx *ctx = encripto_aes256_new(key);
    encripto_aes256_encrypt(ctx, pt, ct);
    encripto_aes256_decrypt(ctx, ct, dec);
    ASSERT_EQ_HEX(dec, pt, 16);
    printf("PASS\n");

    printf("  all-0xFF key and plaintext roundtrip ... ");
    memset(key, 0xFF, 32);
    memset(pt, 0xFF, 16);
    encripto_aes256_encrypt(ctx, pt, ct);
    encripto_aes256_decrypt(ctx, ct, dec);
    ASSERT_EQ_HEX(dec, pt, 16);
    printf("PASS\n");

    encripto_aes256_free(ctx);

    printf("  counter key/plaintext roundtrip ... ");
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 17);
    ctx = encripto_aes256_new(key);
    encripto_aes256_encrypt(ctx, pt, ct);
    encripto_aes256_decrypt(ctx, ct, dec);
    ASSERT_EQ_HEX(dec, pt, 16);
    printf("PASS\n");
    encripto_aes256_free(ctx);
}

/* ── Key clear (zeroization) ──────────────────────────────── */

static void test_key_clear(void) {
    uint32_t rk[60];
    memset(rk, 0xAA, sizeof(rk));

    printf("  key zeroization clears all 60 words ... ");
    encripto_aes256_key_clear(rk);

    int all_zero = 1;
    for (int i = 0; i < 60; i++) {
        if (rk[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (!all_zero) {
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── CBC roundtrip helper ─────────────────────────────────── */

static void cbc_roundtrip(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *pt, size_t pt_len,
                           const char *label) {
    printf("  %s ... ", label);
    uint8_t ct[pt_len + 16];
    uint8_t dec[pt_len + 16];
    size_t ct_len = sizeof(ct);
    size_t dec_len = sizeof(dec);

    int ret = encripto_aes256_cbc_encrypt(key, iv, pt, pt_len, ct, &ct_len);
    if (ret != ENCRIPTO_OK) {
        fprintf(stderr, "  FAIL [%s:%d]: encrypt returned %d\n",
                __FILE__, __LINE__, ret);
        tests_failed++;
        return;
    }

    ret = encripto_aes256_cbc_decrypt(key, iv, ct, ct_len, dec, &dec_len);
    if (ret != ENCRIPTO_OK || dec_len != pt_len ||
        memcmp(pt, dec, pt_len) != 0) {
        fprintf(stderr, "  FAIL [%s:%d]: decrypt roundtrip failed "
                        "(ret=%d, dec_len=%zu, pt_len=%zu)\n",
                __FILE__, __LINE__, ret, dec_len, pt_len);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── NIST SP 800-38A Section F.2.3: AES-256 CBC KAT ──────── */

static void test_cbc_nist_kat(void) {
    uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4,
    };
    uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    };
    uint8_t pt[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10,
    };
    uint8_t expected_ct[64] = {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,
        0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,
        0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,
        0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf,
        0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61,
        0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,
        0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b,
    };

    printf("  NIST SP 800-38A F.2.3 CBC encrypt ... ");
    uint8_t ct[80];
    size_t ct_len = sizeof(ct);
    int ret = encripto_aes256_cbc_encrypt(key, iv, pt, sizeof(pt), ct, &ct_len);
    if (ret != ENCRIPTO_OK) {
        fprintf(stderr, "FAIL [%s:%d]: encrypt returned %d\n",
                __FILE__, __LINE__, ret);
        tests_failed++;
        return;
    }
    /* 64 bytes plaintext + 16 bytes PKCS#7 padding = 80 bytes */
    if (ct_len != 80) {
        fprintf(stderr, "FAIL [%s:%d]: ct_len=%zu, expected 80\n",
                __FILE__, __LINE__, ct_len);
        tests_failed++;
        return;
    }
    ASSERT_EQ_HEX(ct, expected_ct, 64);
    tests_passed++;
    printf("PASS\n");

    printf("  NIST SP 800-38A F.2.3 CBC decrypt ... ");
    uint8_t dec[80];
    size_t dec_len = sizeof(dec);
    ret = encripto_aes256_cbc_decrypt(key, iv, ct, ct_len, dec, &dec_len);
    if (ret != ENCRIPTO_OK || dec_len != sizeof(pt) ||
        memcmp(dec, pt, sizeof(pt)) != 0) {
        fprintf(stderr, "FAIL [%s:%d]: decrypt roundtrip failed\n",
                __FILE__, __LINE__);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");
}

/* ── CBC roundtrip tests ──────────────────────────────────── */

static void test_cbc_roundtrips(void) {
    uint8_t key[32];
    uint8_t iv[16];

    memset(key, 0, 32);
    memset(iv, 0, 16);

    cbc_roundtrip(key, iv, (const uint8_t *)"", 0,
                  "zero-length message roundtrip");

    cbc_roundtrip(key, iv, (const uint8_t *)"a", 1,
                  "1-byte message roundtrip");

    cbc_roundtrip(key, iv, (const uint8_t *)"Hello, World!", 13,
                  "13-byte message roundtrip");

    cbc_roundtrip(key, iv, (const uint8_t *)"1234567890123456", 16,
                  "16-byte (exactly 1 block) roundtrip");

    cbc_roundtrip(key, iv,
                  (const uint8_t *)"The quick brown fox jumps over the lazy dog",
                  43, "43-byte message roundtrip");

    memset(key, 0xFF, 32);
    memset(iv, 0xFF, 16);
    cbc_roundtrip(key, iv,
                  (const uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26,
                  "0xFF key/iv, 26-byte msg roundtrip");

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 3);
    uint8_t pt[256];
    for (int i = 0; i < 256; i++) pt[i] = (uint8_t)i;
    cbc_roundtrip(key, iv, pt, 256,
                  "256-byte (16 blocks) roundtrip");
}

/* ── PKCS#7 padding edge cases ────────────────────────────── */

static void test_padding_errors(void) {
    uint8_t key[32] = {0};
    uint8_t iv[16]  = {0};
    uint8_t pt[32]  = {0};
    uint8_t ct[64];
    uint8_t dec[64];
    size_t ct_len, dec_len;
    int ret;

    printf("  invalid ciphertext length (not multiple of 16) ... ");
    ct_len = 10;
    dec_len = sizeof(dec);
    ret = encripto_aes256_cbc_decrypt(key, iv, ct, ct_len, dec, &dec_len);
    if (ret != ENCRIPTO_ERR_PARAM) {
        fprintf(stderr, "FAIL: expected ERR_PARAM, got %d\n", ret);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");

    printf("  invalid ciphertext length (zero, not 16-aligned) ... ");
    ret = encripto_aes256_cbc_decrypt(key, iv, ct, 0, dec, &dec_len);
    if (ret != ENCRIPTO_ERR_PARAM) {
        fprintf(stderr, "FAIL: expected ERR_PARAM, got %d\n", ret);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");

    printf("  invalid padding byte (too large) ... ");
    ct_len = sizeof(ct);
    ret = encripto_aes256_cbc_encrypt(key, iv, pt, 1, ct, &ct_len);
    /* tamper with last byte to make padding invalid */
    ct[ct_len - 1] = 0xAA;
    dec_len = sizeof(dec);
    ret = encripto_aes256_cbc_decrypt(key, iv, ct, ct_len, dec, &dec_len);
    if (ret != ENCRIPTO_ERR_PARAM) {
        fprintf(stderr, "FAIL: expected ERR_PARAM, got %d\n", ret);
        tests_failed++;
        return;
    }
    tests_passed++;
    printf("PASS\n");

    printf("  NULL parameter checks ... ");
    ret = encripto_aes256_cbc_encrypt(NULL, iv, pt, 1, ct, &ct_len);
    if (ret != ENCRIPTO_ERR_PARAM) { tests_failed++; return; }
    ret = encripto_aes256_cbc_encrypt(key, NULL, pt, 1, ct, &ct_len);
    if (ret != ENCRIPTO_ERR_PARAM) { tests_failed++; return; }
    ret = encripto_aes256_cbc_encrypt(key, iv, NULL, 1, ct, &ct_len);
    if (ret != ENCRIPTO_ERR_PARAM) { tests_failed++; return; }
    ret = encripto_aes256_cbc_encrypt(key, iv, pt, 1, NULL, &ct_len);
    if (ret != ENCRIPTO_ERR_PARAM) { tests_failed++; return; }
    ret = encripto_aes256_cbc_encrypt(key, iv, pt, 1, ct, NULL);
    if (ret != ENCRIPTO_ERR_PARAM) { tests_failed++; return; }
    tests_passed++;
    printf("PASS\n");
}

int main(void) {
    printf("AES-256 tests:\n");

    printf("  Key expansion:\n");
    printf("    FIPS 197 Appendix B ... ");
    test_key_expansion_fips197();

    printf("  ECB known-answer tests:\n");
    test_encrypt_kat();

    printf("  ECB roundtrip:\n");
    test_roundtrip();

    printf("  Key zeroization:\n");
    test_key_clear();

    printf("  CBC mode:\n");
    test_cbc_nist_kat();
    test_cbc_roundtrips();
    test_padding_errors();

    if (tests_failed > 0) {
        printf("\nAES-256: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nAES-256: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
