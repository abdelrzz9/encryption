#include "encripto.h"
#include <string.h>
#include <stddef.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ── Poly1305 (RFC 8439 Section 2.5) ────────────────────────
 *
 * Uses 5-limb radix-2^26 representation to avoid overflow in
 * intermediate products.  Each limb holds at most 26 bits so
 * that sums of five 26×26→52-bit products fit in uint64_t.
 */

#define POLY1305_MASK26  ((uint64_t)0x3FFFFFF)
#define POLY1305_BITS    26U

/* Load a 64-bit little-endian word. */
static uint64_t load64_le(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Store a 64-bit little-endian word. */
static void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/* Clamp the 16-byte key r per RFC 8439 §2.5. */
static void poly1305_clamp(uint8_t r[16]) {
    r[3]  &= 15;
    r[7]  &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4]  &= 252;
    r[8]  &= 252;
    r[12] &= 252;
}

/* ── 5×26-bit scatter ────────────────────────────────────── */

/* Add a 16-byte message block into accumulator limbs (no high bit).
   Correctly decomposes the 128-bit LE value into 5 × 26-bit limbs. */
static void poly1305_load_block(uint64_t h[5], const uint8_t block[16]) {
    uint64_t t0 = load64_le(block);
    uint64_t t1 = load64_le(block + 8);
    h[0] += t0 & POLY1305_MASK26;
    h[1] += (t0 >> POLY1305_BITS) & POLY1305_MASK26;
    h[2] += ((t0 >> 52) & 0xFFF) | ((t1 & 0x3FFF) << 12);
    h[3] += (t1 >> 14) & POLY1305_MASK26;
    h[4] += (t1 >> 40) & POLY1305_MASK26;
}

/* Load the 16-byte key r (pre-clamped) into 5 26-bit limbs.
   Also precompute s[i] = r[i+1] * 5 for i = 0..3. */
static void poly1305_load_r(uint64_t r[5], uint64_t s[4],
                             const uint8_t key16[16]) {
    uint8_t r_bytes[16];
    for (int i = 0; i < 16; i++) r_bytes[i] = key16[i];
    poly1305_clamp(r_bytes);

    uint64_t t0 = load64_le(r_bytes);
    uint64_t t1 = load64_le(r_bytes + 8);

    r[0] = t0 & POLY1305_MASK26;
    r[1] = (t0 >> POLY1305_BITS) & POLY1305_MASK26;
    r[2] = ((t0 >> 52) & 0xFFF) | ((t1 & 0x3FFF) << 12);
    r[3] = (t1 >> 14) & POLY1305_MASK26;
    r[4] = (t1 >> 40) & POLY1305_MASK26;

    s[0] = r[1] * 5;
    s[1] = r[2] * 5;
    s[2] = r[3] * 5;
    s[3] = r[4] * 5;
}

/* ── Carry propagation ────────────────────────────────────── */

/* Propagate carries so each limb < 2^26.
   Overflow from h[4] (bits > 130) is folded via 2^130 ≡ 5. */
static void poly1305_carry(uint64_t h[5]) {
    uint64_t c;
    c = h[0] >> POLY1305_BITS; h[0] &= POLY1305_MASK26; h[1] += c;
    c = h[1] >> POLY1305_BITS; h[1] &= POLY1305_MASK26; h[2] += c;
    c = h[2] >> POLY1305_BITS; h[2] &= POLY1305_MASK26; h[3] += c;
    c = h[3] >> POLY1305_BITS; h[3] &= POLY1305_MASK26; h[4] += c;
    c = h[4] >> POLY1305_BITS; h[4] &= POLY1305_MASK26;
    h[0] += c * 5;
    c = h[0] >> POLY1305_BITS; h[0] &= POLY1305_MASK26; h[1] += c;
    c = h[1] >> POLY1305_BITS; h[1] &= POLY1305_MASK26; h[2] += c;
}

/* ── Multiplication and reduction ─────────────────────────── */

/* h = (h + block_as_limbs) * r  mod (2^130 - 5)
   block is added to h BEFORE calling this function. */
static void poly1305_mul(encripto_poly1305_ctx *ctx) {
    uint64_t h0, h1, h2, h3, h4;
    uint64_t r0, r1, r2, r3, r4;
    uint64_t s1, s2, s3, s4;
    uint64_t d0, d1, d2, d3, d4;
    uint64_t c;

    h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2];
    h3 = ctx->h[3]; h4 = ctx->h[4];
    r0 = ctx->r[0]; r1 = ctx->r[1]; r2 = ctx->r[2];
    r3 = ctx->r[3]; r4 = ctx->r[4];
    s1 = ctx->s[0]; s2 = ctx->s[1]; s3 = ctx->s[2]; s4 = ctx->s[3];

    d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    c = d0 >> POLY1305_BITS; h0 = d0 & POLY1305_MASK26;
    d1 += c;
    c = d1 >> POLY1305_BITS; h1 = d1 & POLY1305_MASK26;
    d2 += c;
    c = d2 >> POLY1305_BITS; h2 = d2 & POLY1305_MASK26;
    d3 += c;
    c = d3 >> POLY1305_BITS; h3 = d3 & POLY1305_MASK26;
    d4 += c;
    c = d4 >> POLY1305_BITS; h4 = d4 & POLY1305_MASK26;
    h0 += c * 5;  /* fold the top carry via 2^130 ≡ 5 */
    c = h0 >> POLY1305_BITS; h0 &= POLY1305_MASK26;
    h1 += c;

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
    ctx->h[3] = h3; ctx->h[4] = h4;
}

/* ── Block processing ─────────────────────────────────────── */

/* Process one full 16-byte block: add message + high bit at 2^128. */
static void poly1305_process_block(encripto_poly1305_ctx *ctx,
                                    const uint8_t block[16]) {
    poly1305_load_block(ctx->h, block);
    ctx->h[4] += (uint64_t)1 << 24;   /* high bit at bit 128 (limb 4) */
    poly1305_carry(ctx->h);
    poly1305_mul(ctx);
}

/* ── Public API ───────────────────────────────────────────── */

int encripto_poly1305_init(encripto_poly1305_ctx *ctx,
                            const uint8_t key[ENCRIPTO_POLY1305_KEY_SIZE]) {
    if (!ctx || !key)
        return ENCRIPTO_ERR_PARAM;

    poly1305_load_r(ctx->r, ctx->s, key);

    ctx->pad[0] = load64_le(key + 16);
    ctx->pad[1] = load64_le(key + 24);

    ctx->h[0] = 0; ctx->h[1] = 0; ctx->h[2] = 0;
    ctx->h[3] = 0; ctx->h[4] = 0;
    ctx->buffer_len = 0;

    return ENCRIPTO_OK;
}

int encripto_poly1305_update(encripto_poly1305_ctx *ctx,
                              const uint8_t *data, size_t len) {
    if (!ctx || (!data && len > 0))
        return ENCRIPTO_ERR_PARAM;

    size_t i = 0;

    if (ctx->buffer_len > 0) {
        size_t take = 16 - ctx->buffer_len;
        if (take > len) take = len;
        for (size_t j = 0; j < take; j++)
            ctx->buffer[ctx->buffer_len + j] = data[i + j];
        ctx->buffer_len += take;
        i += take;
        if (ctx->buffer_len == 16) {
            poly1305_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    while (i + 16 <= len) {
        poly1305_process_block(ctx, data + i);
        i += 16;
    }

    while (i < len) {
        ctx->buffer[ctx->buffer_len++] = data[i++];
    }

    return ENCRIPTO_OK;
}

int encripto_poly1305_final(encripto_poly1305_ctx *ctx,
                             uint8_t tag[ENCRIPTO_POLY1305_TAG_SIZE]) {
    if (!ctx || !tag)
        return ENCRIPTO_ERR_PARAM;

    if (ctx->buffer_len > 0) {
        for (size_t i = ctx->buffer_len; i < 16; i++)
            ctx->buffer[i] = 0;
        poly1305_load_block(ctx->h, ctx->buffer);
        /* High bit at position buffer_len * 8 */
        if (ctx->buffer_len <= 3) {
            ctx->h[0] += (uint64_t)1 << (ctx->buffer_len * 8);
        } else if (ctx->buffer_len <= 6) {
            ctx->h[1] += (uint64_t)1 << (ctx->buffer_len * 8 - 26);
        } else if (ctx->buffer_len <= 9) {
            ctx->h[2] += (uint64_t)1 << (ctx->buffer_len * 8 - 52);
        } else if (ctx->buffer_len <= 12) {
            ctx->h[3] += (uint64_t)1 << (ctx->buffer_len * 8 - 78);
        } else {
            ctx->h[4] += (uint64_t)1 << (ctx->buffer_len * 8 - 104);
        }
        poly1305_carry(ctx->h);
        poly1305_mul(ctx);
        ctx->buffer_len = 0;
    }

    /* Full carry and reduction to < 2^130 */
    poly1305_carry(ctx->h);

    /* Reassemble 128-bit value from 26-bit limbs (bits 0-127). */
    uint64_t acc0 = ctx->h[0] | (ctx->h[1] << 26) |
                    ((ctx->h[2] & 0xFFF) << 52);
    uint64_t acc1 = (ctx->h[2] >> 12) | (ctx->h[3] << 14) |
                    ((ctx->h[4] & 0xFFFFFF) << 40);

    __uint128_t sum = (__uint128_t)acc0 + ctx->pad[0];
    uint64_t tag0 = (uint64_t)sum;
    sum = (__uint128_t)acc1 + ctx->pad[1] + (sum >> 64);
    uint64_t tag1 = (uint64_t)sum;

    store64_le(tag, tag0);
    store64_le(tag + 8, tag1);

    /* Zeroise the context */
    volatile uint64_t *vp = (volatile uint64_t *)ctx;
    for (size_t i = 0; i < sizeof(*ctx) / sizeof(uint64_t); i++)
        vp[i] = 0;

    return ENCRIPTO_OK;
}

/* ── ChaCha20 quarter round (RFC 8439 Section 2.1) ─────────── */

static void quarter_round(uint32_t *a, uint32_t *b,
                           uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d,  8);
    *c += *d; *b ^= *c; *b = ROTL32(*b,  7);
}

/* ── ChaCha20 block function (RFC 8439 Section 2.3) ────────── */

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            uint8_t keystream[64]) {
    uint32_t s[16];

    /* Constants */
    s[0]  = 0x61707865;
    s[1]  = 0x3320646e;
    s[2]  = 0x79622d32;
    s[3]  = 0x6b206574;

    /* Key (8 little-endian words) */
    for (int i = 0; i < 8; i++)
        s[4 + i] = ((uint32_t)key[4*i]      ) |
                   ((uint32_t)key[4*i + 1] << 8) |
                   ((uint32_t)key[4*i + 2] << 16) |
                   ((uint32_t)key[4*i + 3] << 24);

    /* Counter */
    s[12] = counter;

    /* Nonce (3 little-endian words) */
    s[13] = ((uint32_t)nonce[0]      ) |
            ((uint32_t)nonce[1] <<  8) |
            ((uint32_t)nonce[2] << 16) |
            ((uint32_t)nonce[3] << 24);
    s[14] = ((uint32_t)nonce[4]      ) |
            ((uint32_t)nonce[5] <<  8) |
            ((uint32_t)nonce[6] << 16) |
            ((uint32_t)nonce[7] << 24);
    s[15] = ((uint32_t)nonce[8]      ) |
            ((uint32_t)nonce[9] <<  8) |
            ((uint32_t)nonce[10] << 16) |
            ((uint32_t)nonce[11] << 24);

    /* Working copy */
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = s[i];

    /* 20 rounds (10 column + 10 diagonal) */
    for (int r = 0; r < 10; r++) {
        /* Column rounds */
        quarter_round(&x[0], &x[4], &x[8],  &x[12]);
        quarter_round(&x[1], &x[5], &x[9],  &x[13]);
        quarter_round(&x[2], &x[6], &x[10], &x[14]);
        quarter_round(&x[3], &x[7], &x[11], &x[15]);
        /* Diagonal rounds */
        quarter_round(&x[0], &x[5], &x[10], &x[15]);
        quarter_round(&x[1], &x[6], &x[11], &x[12]);
        quarter_round(&x[2], &x[7], &x[8],  &x[13]);
        quarter_round(&x[3], &x[4], &x[9],  &x[14]);
    }

    /* Add working state to initial state */
    for (int i = 0; i < 16; i++)
        x[i] += s[i];

    /* Serialize as little-endian bytes */
    for (int i = 0; i < 16; i++) {
        keystream[4*i]      = (uint8_t)(x[i]);
        keystream[4*i + 1]  = (uint8_t)(x[i] >> 8);
        keystream[4*i + 2]  = (uint8_t)(x[i] >> 16);
        keystream[4*i + 3]  = (uint8_t)(x[i] >> 24);
    }
}

/* ── ChaCha20 encrypt/decrypt (RFC 8439 Section 2.4) ──────── */

int encripto_chacha20_encrypt(const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
                               uint32_t counter,
                               const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
                               const uint8_t *in, size_t len,
                               uint8_t *out) {
    if (!key || !nonce || !in || !out)
        return ENCRIPTO_ERR_PARAM;

    size_t pos = 0;
    while (pos < len) {
        uint8_t keystream[64];
        chacha20_block(key, counter, nonce, keystream);

        size_t chunk = (len - pos < 64) ? len - pos : 64;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];

        pos += chunk;
        counter++;
    }

    return ENCRIPTO_OK;
}

/* ── ChaCha20-Poly1305 stubs (to be implemented) ──────────── */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ── ChaCha20 quarter round (RFC 8439 Section 2.1) ─────────── */

static void quarter_round(uint32_t *a, uint32_t *b,
                           uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d,  8);
    *c += *d; *b ^= *c; *b = ROTL32(*b,  7);
}

/* ── ChaCha20 block function (RFC 8439 Section 2.3) ────────── */

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12],
                            uint8_t keystream[64]) {
    uint32_t s[16];

    /* Constants */
    s[0]  = 0x61707865;
    s[1]  = 0x3320646e;
    s[2]  = 0x79622d32;
    s[3]  = 0x6b206574;

    /* Key (8 little-endian words) */
    for (int i = 0; i < 8; i++)
        s[4 + i] = ((uint32_t)key[4*i]      ) |
                   ((uint32_t)key[4*i + 1] << 8) |
                   ((uint32_t)key[4*i + 2] << 16) |
                   ((uint32_t)key[4*i + 3] << 24);

    /* Counter */
    s[12] = counter;

    /* Nonce (3 little-endian words) */
    s[13] = ((uint32_t)nonce[0]      ) |
            ((uint32_t)nonce[1] <<  8) |
            ((uint32_t)nonce[2] << 16) |
            ((uint32_t)nonce[3] << 24);
    s[14] = ((uint32_t)nonce[4]      ) |
            ((uint32_t)nonce[5] <<  8) |
            ((uint32_t)nonce[6] << 16) |
            ((uint32_t)nonce[7] << 24);
    s[15] = ((uint32_t)nonce[8]      ) |
            ((uint32_t)nonce[9] <<  8) |
            ((uint32_t)nonce[10] << 16) |
            ((uint32_t)nonce[11] << 24);

    /* Working copy */
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = s[i];

    /* 20 rounds (10 column + 10 diagonal) */
    for (int r = 0; r < 10; r++) {
        /* Column rounds */
        quarter_round(&x[0], &x[4], &x[8],  &x[12]);
        quarter_round(&x[1], &x[5], &x[9],  &x[13]);
        quarter_round(&x[2], &x[6], &x[10], &x[14]);
        quarter_round(&x[3], &x[7], &x[11], &x[15]);
        /* Diagonal rounds */
        quarter_round(&x[0], &x[5], &x[10], &x[15]);
        quarter_round(&x[1], &x[6], &x[11], &x[12]);
        quarter_round(&x[2], &x[7], &x[8],  &x[13]);
        quarter_round(&x[3], &x[4], &x[9],  &x[14]);
    }

    /* Add working state to initial state */
    for (int i = 0; i < 16; i++)
        x[i] += s[i];

    /* Serialize as little-endian bytes */
    for (int i = 0; i < 16; i++) {
        keystream[4*i]      = (uint8_t)(x[i]);
        keystream[4*i + 1]  = (uint8_t)(x[i] >> 8);
        keystream[4*i + 2]  = (uint8_t)(x[i] >> 16);
        keystream[4*i + 3]  = (uint8_t)(x[i] >> 24);
    }
}

/* ── ChaCha20 encrypt/decrypt (RFC 8439 Section 2.4) ──────── */

int encripto_chacha20_encrypt(const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
                               uint32_t counter,
                               const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
                               const uint8_t *in, size_t len,
                               uint8_t *out) {
    if (!key || !nonce || !in || !out)
        return ENCRIPTO_ERR_PARAM;

    size_t pos = 0;
    while (pos < len) {
        uint8_t keystream[64];
        chacha20_block(key, counter, nonce, keystream);

        size_t chunk = (len - pos < 64) ? len - pos : 64;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];

        pos += chunk;
        counter++;
    }

    return ENCRIPTO_OK;
}

/* ── ChaCha20-Poly1305 stubs (to be implemented) ──────────── */

int encripto_chacha20_poly1305_encrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *pt, size_t len,
    uint8_t *ct, uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE]) {
    (void)key; (void)nonce;
    if (!pt || !ct || !tag)
        return ENCRIPTO_ERR_PARAM;
    memcpy(ct, pt, len);
    memset(tag, 0, ENCRIPTO_CHACHA20_TAG_SIZE);
    return ENCRIPTO_OK;
}

int encripto_chacha20_poly1305_decrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *ct, size_t len,
    const uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE],
    uint8_t *pt) {
    (void)key; (void)nonce; (void)tag;
    if (!ct || !pt)
        return ENCRIPTO_ERR_PARAM;
    memcpy(pt, ct, len);
    return ENCRIPTO_OK;
}
