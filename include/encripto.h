/* ============================================================
 * encripto.h — Public API
 * Encripto — low-level C cryptography library
 * License: MIT
 * ============================================================ */

#ifndef ENCRIPTO_H
#define ENCRIPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────── */

#define ENCRIPTO_OK           0
#define ENCRIPTO_ERR_PARAM   -1
#define ENCRIPTO_ERR_AUTH    -2
#define ENCRIPTO_ERR_KEYGEN  -3
#define ENCRIPTO_ERR_RNG     -4
#define ENCRIPTO_ERR_NOMEM   -5

/* ── SHA-256 (FIPS 180-4) ─────────────────────────────────── */

#define ENCRIPTO_SHA256_DIGEST_SIZE 32
#define ENCRIPTO_SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[ENCRIPTO_SHA256_BLOCK_SIZE];
    size_t   buffer_len;
} encripto_sha256_ctx;

int encripto_sha256_init(encripto_sha256_ctx *ctx);
int encripto_sha256_update(encripto_sha256_ctx *ctx,
                            const uint8_t *data, size_t len);
int encripto_sha256_final(encripto_sha256_ctx *ctx,
                           uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);
int encripto_sha256(const uint8_t *data, size_t len,
                     uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);

/* ── SHA-512 (FIPS 180-4) ─────────────────────────────────── */

#define ENCRIPTO_SHA512_DIGEST_SIZE 64
#define ENCRIPTO_SHA512_BLOCK_SIZE  128

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[ENCRIPTO_SHA512_BLOCK_SIZE];
    size_t   buf_len;
} encripto_sha512_ctx;

int encripto_sha512_init(encripto_sha512_ctx *ctx);
int encripto_sha512_update(encripto_sha512_ctx *ctx,
                            const uint8_t *data, size_t len);
int encripto_sha512_final(encripto_sha512_ctx *ctx,
                           uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE]);
int encripto_sha512(const uint8_t *data, size_t len,
                     uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE]);

/* ── HMAC (RFC 2104) ─────────────────────────────────────── */

#define ENCRIPTO_HMAC_SHA256_DIGEST_SIZE 32
#define ENCRIPTO_HMAC_SHA512_DIGEST_SIZE 64

int encripto_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE]);
int encripto_hmac_sha512(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE]);
int encripto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len);

/* ── AES-256 ─────────────────────────────────────────────── */

#define ENCRIPTO_AES256_KEY_SIZE   32
#define ENCRIPTO_AES256_BLOCK_SIZE 16
#define ENCRIPTO_AES256_IV_SIZE    16
#define ENCRIPTO_AES256_GCM_IV_SIZE  12
#define ENCRIPTO_AES256_GCM_TAG_SIZE 16

int encripto_aes256_cbc_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, size_t *ct_len);
int encripto_aes256_cbc_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *pt, size_t *pt_len);
int encripto_aes256_gcm_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE]);
int encripto_aes256_gcm_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *ct, size_t len,
                                 const uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE],
                                 uint8_t *pt);

/* ── ChaCha20-Poly1305 ───────────────────────────────────── */

#define ENCRIPTO_CHACHA20_KEY_SIZE   32
#define ENCRIPTO_CHACHA20_NONCE_SIZE 12
#define ENCRIPTO_CHACHA20_TAG_SIZE   16

int encripto_chacha20_poly1305_encrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *pt, size_t len,
    uint8_t *ct, uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE]);
int encripto_chacha20_poly1305_decrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *ct, size_t len,
    const uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE],
    uint8_t *pt);

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

/* ── Random number generation ────────────────────────────── */

int encripto_rand_bytes(uint8_t *buf, size_t n);
int encripto_rand_key(uint8_t *key, size_t key_len);

/* ── Encoding helpers ────────────────────────────────────── */

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
