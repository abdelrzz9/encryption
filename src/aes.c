#include "encripto.h"
#include <stdlib.h>
#include <string.h>

/* ── PKCS#7 padding helpers ──────────────────────────────── */

static size_t pkcs7_padded_len(size_t msg_len) {
    return msg_len + 16 - (msg_len % 16);
}

static void pkcs7_pad(uint8_t *buf, size_t msg_len) {
    uint8_t pad = 16 - (uint8_t)(msg_len % 16);
    for (uint8_t i = 0; i < pad; i++)
        buf[msg_len + i] = pad;
}

static int pkcs7_unpad(const uint8_t *buf, size_t len, size_t *out_len) {
    if (len == 0 || len % 16 != 0)
        return -1;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > 16)
        return -1;
    uint8_t bad = 0;
    for (uint8_t i = 1; i <= pad; i++)
        bad |= buf[len - i] ^ pad;
    if (bad)
        return -1;
    *out_len = len - pad;
    return 0;
}

/* ── AES-CBC ──────────────────────────────────────────────── */

int encripto_aes256_cbc_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, size_t *ct_len) {
    if (!key || !iv || !pt || !ct || !ct_len)
        return ENCRIPTO_ERR_PARAM;

    size_t padded_len = pkcs7_padded_len(len);
    if (*ct_len < padded_len)
        return ENCRIPTO_ERR_PARAM;
    *ct_len = padded_len;

    uint8_t padded[padded_len];
    memcpy(padded, pt, len);
    pkcs7_pad(padded, len);

    encripto_aes256_ctx *ctx = encripto_aes256_new(key);
    if (!ctx)
        return ENCRIPTO_ERR_NOMEM;

    const uint8_t *prev = iv;
    for (size_t i = 0; i < padded_len; i += 16) {
        uint8_t tmp[16];
        for (int j = 0; j < 16; j++)
            tmp[j] = padded[i + j] ^ prev[j];
        encripto_aes256_encrypt(ctx, tmp, ct + i);
        prev = ct + i;
    }

    encripto_aes256_free(ctx);
    return ENCRIPTO_OK;
}

int encripto_aes256_cbc_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *pt, size_t *pt_len) {
    if (!key || !iv || !ct || !pt || !pt_len)
        return ENCRIPTO_ERR_PARAM;
    if (ct_len == 0 || ct_len % 16 != 0)
        return ENCRIPTO_ERR_PARAM;
    if (*pt_len < ct_len)
        return ENCRIPTO_ERR_PARAM;

    encripto_aes256_ctx *ctx = encripto_aes256_new(key);
    if (!ctx)
        return ENCRIPTO_ERR_NOMEM;

    uint8_t *dec = pt;
    const uint8_t *prev = iv;
    for (size_t i = 0; i < ct_len; i += 16) {
        encripto_aes256_decrypt(ctx, ct + i, dec + i);
        for (int j = 0; j < 16; j++)
            dec[i + j] ^= prev[j];
        prev = ct + i;
    }

    encripto_aes256_free(ctx);

    size_t unpadded_len;
    if (pkcs7_unpad(dec, ct_len, &unpadded_len) != 0)
        return ENCRIPTO_ERR_PARAM;
    *pt_len = unpadded_len;
    return ENCRIPTO_OK;
}

/* ── AES-GCM stubs (to be implemented) ────────────────────── */

int encripto_aes256_gcm_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE]) {
    (void)key; (void)iv;
    if (!pt || !ct || !tag)
        return ENCRIPTO_ERR_PARAM;
    memcpy(ct, pt, len);
    memset(tag, 0, ENCRIPTO_AES256_GCM_TAG_SIZE);
    return ENCRIPTO_OK;
}

int encripto_aes256_gcm_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *ct, size_t len,
                                 const uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE],
                                 uint8_t *pt) {
    (void)key; (void)iv; (void)tag;
    if (!ct || !pt)
        return ENCRIPTO_ERR_PARAM;
    memcpy(pt, ct, len);
    return ENCRIPTO_OK;
}

/* ── FIPS 197 Section 5.1.1 / Appendix A: S-Box ──────────── */

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t SBOX_INV[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

/* ── Round Constants (FIPS 197 Section 5.2) ───────────────── */

static const uint32_t RCON[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
};

/* ── Key Schedule Helpers ─────────────────────────────────── */

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)SBOX[(w >>  8) & 0xff] <<  8) |
           ((uint32_t)SBOX[(w      ) & 0xff]      );
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* ── AES-256 Key Expansion (FIPS 197 Section 5.2) ─────────── */

int encripto_aes256_key_expand(const uint8_t key[32],
                                uint32_t round_keys[60]) {
    for (int i = 0; i < 8; i++)
        round_keys[i] = read_be32(key + i * 4);

    for (int i = 8; i < 60; i++) {
        uint32_t temp = round_keys[i - 1];

        if (i % 8 == 0)
            temp = sub_word(rot_word(temp)) ^ RCON[i / 8 - 1];
        else if (i % 8 == 4)
            temp = sub_word(temp);

        round_keys[i] = round_keys[i - 8] ^ temp;
    }

    return 0;
}

void encripto_aes256_key_clear(uint32_t round_keys[60]) {
    volatile uint32_t *p = (volatile uint32_t *)round_keys;
    for (int i = 0; i < 60; i++)
        p[i] = 0;
}

/* ── GF(2^8) helpers (for MixColumns) ─────────────────────── */

static uint8_t gf_mul2(uint8_t x) {
    return (uint8_t)((x << 1) ^ (x & 0x80 ? 0x1b : 0x00));
}

static uint8_t gf_mul3(uint8_t x) {
    return gf_mul2(x) ^ x;
}

static uint8_t gf_mul9(uint8_t x) {
    return gf_mul2(gf_mul2(gf_mul2(x))) ^ x;
}

static uint8_t gf_mul11(uint8_t x) {
    return gf_mul2(gf_mul2(gf_mul2(x)) ^ x) ^ x;
}

static uint8_t gf_mul13(uint8_t x) {
    return gf_mul2(gf_mul2(gf_mul2(x) ^ x)) ^ x;
}

static uint8_t gf_mul14(uint8_t x) {
    return gf_mul2(gf_mul2(gf_mul2(x) ^ x) ^ x);
}

/* ── AES State Operations ─────────────────────────────────── */

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = SBOX_INV[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp;

    tmp = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = tmp;
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp;

    tmp = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = tmp;

    tmp = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t s0 = state[i + 0];
        uint8_t s1 = state[i + 1];
        uint8_t s2 = state[i + 2];
        uint8_t s3 = state[i + 3];

        state[i + 0] = gf_mul2(s0) ^ gf_mul3(s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul2(s1) ^ gf_mul3(s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul3(s3);
        state[i + 3] = gf_mul3(s0) ^ s1 ^ s2 ^ gf_mul2(s3);
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t s0 = state[i + 0];
        uint8_t s1 = state[i + 1];
        uint8_t s2 = state[i + 2];
        uint8_t s3 = state[i + 3];

        state[i + 0] = gf_mul14(s0) ^ gf_mul11(s1) ^ gf_mul13(s2) ^ gf_mul9(s3);
        state[i + 1] = gf_mul9(s0) ^ gf_mul14(s1) ^ gf_mul11(s2) ^ gf_mul13(s3);
        state[i + 2] = gf_mul13(s0) ^ gf_mul9(s1) ^ gf_mul14(s2) ^ gf_mul11(s3);
        state[i + 3] = gf_mul11(s0) ^ gf_mul13(s1) ^ gf_mul9(s2) ^ gf_mul14(s3);
    }
}

static void add_round_key(uint8_t state[16], const uint32_t rk[60],
                           int round) {
    int idx = round * 4;
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[idx + c];
        int i = c * 4;
        state[i + 0] ^= (uint8_t)(w >> 24);
        state[i + 1] ^= (uint8_t)(w >> 16);
        state[i + 2] ^= (uint8_t)(w >>  8);
        state[i + 3] ^= (uint8_t)(w);
    }
}

/* ── AES-256 Context ──────────────────────────────────────── */

struct encripto_aes256_ctx {
    uint32_t round_keys[60];
};

encripto_aes256_ctx *encripto_aes256_new(
    const uint8_t key[ENCRIPTO_AES256_KEY_SIZE])
{
    encripto_aes256_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx)
        encripto_aes256_key_expand(key, ctx->round_keys);
    return ctx;
}

void encripto_aes256_free(encripto_aes256_ctx *ctx) {
    if (ctx) {
        encripto_aes256_key_clear(ctx->round_keys);
        free(ctx);
    }
}

void encripto_aes256_encrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE])
{
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, ctx->round_keys, 0);

    for (int r = 1; r <= 13; r++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys, r);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_keys, 14);

    memcpy(out, state, 16);
}

void encripto_aes256_decrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE])
{
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, ctx->round_keys, 14);

    for (int r = 13; r >= 1; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->round_keys, r);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_keys, 0);

    memcpy(out, state, 16);
}
