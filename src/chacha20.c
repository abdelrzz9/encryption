#include "encripto.h"
#include <string.h>

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
