#include "encripto.h"
#include <stdlib.h>
#include <string.h>

struct encripto_aes256_ctx {
    uint8_t key[ENCRIPTO_AES256_KEY_SIZE];
};

encripto_aes256_ctx *encripto_aes256_new(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE]) {
    encripto_aes256_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx) memcpy(ctx->key, key, ENCRIPTO_AES256_KEY_SIZE);
    return ctx;
}

void encripto_aes256_free(encripto_aes256_ctx *ctx) {
    free(ctx);
}

void encripto_aes256_encrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]) {
    (void)ctx;
    memcpy(out, in, ENCRIPTO_AES256_BLOCK_SIZE);
}

void encripto_aes256_decrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]) {
    (void)ctx;
    memcpy(out, in, ENCRIPTO_AES256_BLOCK_SIZE);
}
