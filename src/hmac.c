#include "encripto.h"
#include <string.h>

int encripto_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE]) {
    uint8_t k_pad[64] = {0};
    uint8_t inner[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256_ctx ctx;

    if (key_len > 64) {
        encripto_sha256(key, key_len, k_pad);
    } else {
        memcpy(k_pad, key, key_len);
    }

    for (size_t i = 0; i < 64; i++)
        k_pad[i] ^= 0x36;

    encripto_sha256_init(&ctx);
    encripto_sha256_update(&ctx, k_pad, 64);
    encripto_sha256_update(&ctx, msg, msg_len);
    encripto_sha256_final(&ctx, inner);

    for (size_t i = 0; i < 64; i++)
        k_pad[i] ^= 0x36 ^ 0x5c;

    encripto_sha256_init(&ctx);
    encripto_sha256_update(&ctx, k_pad, 64);
    encripto_sha256_update(&ctx, inner, sizeof(inner));
    encripto_sha256_final(&ctx, out);

    return 0;
}

int encripto_hmac_sha512(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE]) {
    uint8_t k_pad[128] = {0};
    uint8_t inner[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_ctx ctx;

    if (key_len > 128) {
        encripto_sha512(key, key_len, k_pad);
    } else {
        memcpy(k_pad, key, key_len);
    }

    for (size_t i = 0; i < 128; i++)
        k_pad[i] ^= 0x36;

    encripto_sha512_init(&ctx);
    encripto_sha512_update(&ctx, k_pad, 128);
    encripto_sha512_update(&ctx, msg, msg_len);
    encripto_sha512_final(&ctx, inner);

    for (size_t i = 0; i < 128; i++)
        k_pad[i] ^= 0x36 ^ 0x5c;

    encripto_sha512_init(&ctx);
    encripto_sha512_update(&ctx, k_pad, 128);
    encripto_sha512_update(&ctx, inner, sizeof(inner));
    encripto_sha512_final(&ctx, out);

    return 0;
}

int encripto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0 ? 0 : -1;
}
