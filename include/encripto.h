#ifndef ENCRIPTO_H
#define ENCRIPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── AES-256 ─────────────────────────────────────────────── */

#define ENCRIPTO_AES256_KEY_SIZE   32
#define ENCRIPTO_AES256_BLOCK_SIZE 16

typedef struct encripto_aes256_ctx encripto_aes256_ctx;

encripto_aes256_ctx *encripto_aes256_new(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE]);
void                 encripto_aes256_free(encripto_aes256_ctx *ctx);
void                 encripto_aes256_encrypt(encripto_aes256_ctx *ctx,
                                             const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                                             uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]);
void                 encripto_aes256_decrypt(encripto_aes256_ctx *ctx,
                                             const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                                             uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]);

/* ── RSA-4096 ────────────────────────────────────────────── */

#define ENCRIPTO_RSA_KEY_SIZE 4096

typedef struct encripto_rsa_keypair encripto_rsa_keypair;

encripto_rsa_keypair *encripto_rsa_generate(void);
void                  encripto_rsa_free(encripto_rsa_keypair *kp);
int                   encripto_rsa_encrypt(encripto_rsa_keypair *kp,
                                           const uint8_t *in, size_t in_len,
                                           uint8_t *out, size_t *out_len);
int                   encripto_rsa_decrypt(encripto_rsa_keypair *kp,
                                           const uint8_t *in, size_t in_len,
                                           uint8_t *out, size_t *out_len);

/* ── ChaCha20-Poly1305 ───────────────────────────────────── */

#define ENCRIPTO_CHACHA20_KEY_SIZE   32
#define ENCRIPTO_CHACHA20_NONCE_SIZE 12

typedef struct encripto_chacha20_ctx encripto_chacha20_ctx;

encripto_chacha20_ctx *encripto_chacha20_new(const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
                                              const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE]);
void                   encripto_chacha20_free(encripto_chacha20_ctx *ctx);
void                   encripto_chacha20_encrypt(encripto_chacha20_ctx *ctx,
                                                  const uint8_t *in, size_t in_len,
                                                  uint8_t *out);
void                   encripto_chacha20_decrypt(encripto_chacha20_ctx *ctx,
                                                  const uint8_t *in, size_t in_len,
                                                  uint8_t *out);

/* ── SHA-256 (FIPS 180-4) ─────────────────────────────────── */

#define ENCRIPTO_SHA256_DIGEST_SIZE 32
#define ENCRIPTO_SHA512_DIGEST_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[64];
    size_t   buffer_len;
} encripto_sha256_ctx;

int encripto_sha256_init(encripto_sha256_ctx *ctx);
int encripto_sha256_update(encripto_sha256_ctx *ctx,
                            const uint8_t *data, size_t len);
int encripto_sha256_final(encripto_sha256_ctx *ctx,
                           uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);
int encripto_sha256(const uint8_t *data, size_t len,
                     uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);

encripto_sha512_ctx *encripto_sha512_new(void);
void                 encripto_sha512_free(encripto_sha512_ctx *ctx);
void                 encripto_sha512_update(encripto_sha512_ctx *ctx,
                                             const uint8_t *data, size_t len);
void                 encripto_sha512_final(encripto_sha512_ctx *ctx,
                                            uint8_t out[ENCRIPTO_SHA512_DIGEST_SIZE]);

/* ── HMAC ────────────────────────────────────────────────── */

#define ENCRIPTO_HMAC_SHA256_DIGEST_SIZE 32
#define ENCRIPTO_HMAC_SHA512_DIGEST_SIZE 64

typedef struct encripto_hmac_ctx encripto_hmac_ctx;

encripto_hmac_ctx *encripto_hmac_new(const uint8_t *key, size_t key_len);
void               encripto_hmac_free(encripto_hmac_ctx *ctx);
void               encripto_hmac_update(encripto_hmac_ctx *ctx,
                                         const uint8_t *data, size_t len);
void               encripto_hmac_final_sha256(encripto_hmac_ctx *ctx,
                                               uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE]);
void               encripto_hmac_final_sha512(encripto_hmac_ctx *ctx,
                                               uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE]);

/* ── Utilities ───────────────────────────────────────────── */

int  encripto_random_bytes(uint8_t *buf, size_t len);
void encripto_hex_encode(const uint8_t *in, size_t in_len, char *out);
int  encripto_hex_decode(const char *in, uint8_t *out, size_t *out_len);
void encripto_base64_encode(const uint8_t *in, size_t in_len, char *out);
int  encripto_base64_decode(const char *in, uint8_t *out, size_t *out_len);

/* ── Version ─────────────────────────────────────────────── */

#define ENCRIPTO_VERSION "0.1.0"
const char *encripto_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ENCRIPTO_H */
