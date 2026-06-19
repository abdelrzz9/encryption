#include "encripto.h"
#include <stdlib.h>
#include <string.h>

struct encripto_chacha20_ctx {
    uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE];
    uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE];
};

encripto_chacha20_ctx *encripto_chacha20_new(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE]) {
    encripto_chacha20_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx) {
        memcpy(ctx->key, key, ENCRIPTO_CHACHA20_KEY_SIZE);
        memcpy(ctx->nonce, nonce, ENCRIPTO_CHACHA20_NONCE_SIZE);
    }
    return ctx;
}

void encripto_chacha20_free(encripto_chacha20_ctx *ctx) {
    free(ctx);
}

void encripto_chacha20_encrypt(encripto_chacha20_ctx *ctx,
                                const uint8_t *in, size_t in_len,
                                uint8_t *out) {
    (void)ctx;
    memcpy(out, in, in_len);
}

void encripto_chacha20_decrypt(encripto_chacha20_ctx *ctx,
                                const uint8_t *in, size_t in_len,
                                uint8_t *out) {
    (void)ctx;
    memcpy(out, in, in_len);
}
