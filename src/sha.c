#include "encripto.h"
#include <stdlib.h>
#include <string.h>

/* ── SHA-256 ─────────────────────────────────────────────── */

struct encripto_sha256_ctx {
    uint64_t count;
    uint8_t buf[ENCRIPTO_SHA256_DIGEST_SIZE];
};

encripto_sha256_ctx *encripto_sha256_new(void) {
    return calloc(1, sizeof(encripto_sha256_ctx));
}

void encripto_sha256_free(encripto_sha256_ctx *ctx) {
    free(ctx);
}

void encripto_sha256_update(encripto_sha256_ctx *ctx,
                             const uint8_t *data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
}

void encripto_sha256_final(encripto_sha256_ctx *ctx,
                            uint8_t out[ENCRIPTO_SHA256_DIGEST_SIZE]) {
    memset(out, 0, ENCRIPTO_SHA256_DIGEST_SIZE);
    (void)ctx;
}

/* ── SHA-512 ─────────────────────────────────────────────── */

struct encripto_sha512_ctx {
    uint64_t count;
    uint8_t buf[ENCRIPTO_SHA512_DIGEST_SIZE];
};

encripto_sha512_ctx *encripto_sha512_new(void) {
    return calloc(1, sizeof(encripto_sha512_ctx));
}

void encripto_sha512_free(encripto_sha512_ctx *ctx) {
    free(ctx);
}

void encripto_sha512_update(encripto_sha512_ctx *ctx,
                             const uint8_t *data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
}

void encripto_sha512_final(encripto_sha512_ctx *ctx,
                            uint8_t out[ENCRIPTO_SHA512_DIGEST_SIZE]) {
    memset(out, 0, ENCRIPTO_SHA512_DIGEST_SIZE);
    (void)ctx;
}
