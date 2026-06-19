#include "encripto.h"
#include <stdlib.h>
#include <string.h>

struct encripto_hmac_ctx {
    uint8_t key[64];
    size_t key_len;
};

encripto_hmac_ctx *encripto_hmac_new(const uint8_t *key, size_t key_len) {
    encripto_hmac_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx) {
        size_t cp = key_len < sizeof(ctx->key) ? key_len : sizeof(ctx->key);
        memcpy(ctx->key, key, cp);
        ctx->key_len = cp;
    }
    return ctx;
}

void encripto_hmac_free(encripto_hmac_ctx *ctx) {
    free(ctx);
}

void encripto_hmac_update(encripto_hmac_ctx *ctx,
                           const uint8_t *data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
}

void encripto_hmac_final_sha256(encripto_hmac_ctx *ctx,
                                 uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE]) {
    memset(out, 0, ENCRIPTO_HMAC_SHA256_DIGEST_SIZE);
    (void)ctx;
}

void encripto_hmac_final_sha512(encripto_hmac_ctx *ctx,
                                 uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE]) {
    memset(out, 0, ENCRIPTO_HMAC_SHA512_DIGEST_SIZE);
    (void)ctx;
}
