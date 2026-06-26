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

/** Operation completed successfully. */
#define ENCRIPTO_OK           0

/** Invalid parameter (NULL pointer, bad length, etc.). */
#define ENCRIPTO_ERR_PARAM   -1

/** Authentication tag mismatch (AEAD decryption failure). */
#define ENCRIPTO_ERR_AUTH    -2

/** Key generation failure. */
#define ENCRIPTO_ERR_KEYGEN  -3

/** Random number generator failure. */
#define ENCRIPTO_ERR_RNG     -4

/** Memory allocation failure (should never happen). */
#define ENCRIPTO_ERR_NOMEM   -5

/* ── SHA-256 (FIPS 180-4) ─────────────────────────────────── */

/** SHA-256 digest output size in bytes. */
#define ENCRIPTO_SHA256_DIGEST_SIZE 32

/** SHA-256 internal block size in bytes. */
#define ENCRIPTO_SHA256_BLOCK_SIZE  64

/** Streaming SHA-256 context. */
typedef struct {
    uint32_t state[8];             /**< working state */
    uint64_t bit_count;            /**< total bits processed */
    uint8_t  buffer[ENCRIPTO_SHA256_BLOCK_SIZE]; /**< partial block buffer */
    size_t   buffer_len;           /**< bytes used in buffer */
} encripto_sha256_ctx;

/** Initialise a SHA-256 context.
 *  @param ctx  Pointer to context (must not be NULL).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha256_init(encripto_sha256_ctx *ctx);

/** Feed data into a SHA-256 streaming computation.
 *  @param ctx   Initialised context.
 *  @param data  Input bytes.
 *  @param len   Number of bytes.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha256_update(encripto_sha256_ctx *ctx,
                            const uint8_t *data, size_t len);

/** Finalise SHA-256 and produce the digest.  Context is zeroed on exit.
 *  @param ctx    Initialised context.
 *  @param digest Output buffer (ENCRIPTO_SHA256_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha256_final(encripto_sha256_ctx *ctx,
                           uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);

/** Compute SHA-256 digest in a single call (convenience wrapper).
 *  @param data   Input bytes.
 *  @param len    Number of bytes.
 *  @param digest Output buffer (ENCRIPTO_SHA256_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha256(const uint8_t *data, size_t len,
                     uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE]);

/* ── SHA-512 (FIPS 180-4) ─────────────────────────────────── */

/** SHA-512 digest output size in bytes. */
#define ENCRIPTO_SHA512_DIGEST_SIZE 64

/** SHA-512 internal block size in bytes. */
#define ENCRIPTO_SHA512_BLOCK_SIZE  128

/** Streaming SHA-512 context. */
typedef struct {
    uint64_t state[8];            /**< working state */
    uint64_t count[2];            /**< 128-bit bit counter (hi, lo) */
    uint8_t  buf[ENCRIPTO_SHA512_BLOCK_SIZE]; /**< partial block buffer */
    size_t   buf_len;             /**< bytes used in buffer */
} encripto_sha512_ctx;

/** Initialise a SHA-512 context.
 *  @param ctx  Pointer to context (must not be NULL).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha512_init(encripto_sha512_ctx *ctx);

/** Feed data into a SHA-512 streaming computation.
 *  @param ctx   Initialised context.
 *  @param data  Input bytes.
 *  @param len   Number of bytes.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha512_update(encripto_sha512_ctx *ctx,
                            const uint8_t *data, size_t len);

/** Finalise SHA-512 and produce the digest.  Context is zeroed on exit.
 *  @param ctx    Initialised context.
 *  @param digest Output buffer (ENCRIPTO_SHA512_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha512_final(encripto_sha512_ctx *ctx,
                           uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE]);

/** Compute SHA-512 digest in a single call (convenience wrapper).
 *  @param data   Input bytes.
 *  @param len    Number of bytes.
 *  @param digest Output buffer (ENCRIPTO_SHA512_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_sha512(const uint8_t *data, size_t len,
                     uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE]);

/* ── HMAC (RFC 2104) ─────────────────────────────────────── */

/** HMAC-SHA-256 output size in bytes. */
#define ENCRIPTO_HMAC_SHA256_DIGEST_SIZE 32

/** HMAC-SHA-512 output size in bytes. */
#define ENCRIPTO_HMAC_SHA512_DIGEST_SIZE 64

/** Compute HMAC-SHA-256 (RFC 2104).
 *  @param key     HMAC key.
 *  @param key_len Key length in bytes.
 *  @param msg     Message to authenticate.
 *  @param msg_len Message length in bytes.
 *  @param out     Output buffer (ENCRIPTO_HMAC_SHA256_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA256_DIGEST_SIZE]);

/** Compute HMAC-SHA-512 (RFC 2104).
 *  @param key     HMAC key.
 *  @param key_len Key length in bytes.
 *  @param msg     Message to authenticate.
 *  @param msg_len Message length in bytes.
 *  @param out     Output buffer (ENCRIPTO_HMAC_SHA512_DIGEST_SIZE bytes).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_hmac_sha512(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out[ENCRIPTO_HMAC_SHA512_DIGEST_SIZE]);

/** Constant-time HMAC tag comparison.
 *  @param a   First tag.
 *  @param b   Second tag.
 *  @param len Number of bytes to compare.
 *  @return ENCRIPTO_OK if equal, ENCRIPTO_ERR_AUTH if mismatch,
 *          ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len);

/* ── AES-256 ─────────────────────────────────────────────── */

/** AES-256 key size in bytes. */
#define ENCRIPTO_AES256_KEY_SIZE   32

/** AES-256 block size in bytes. */
#define ENCRIPTO_AES256_BLOCK_SIZE 16

/** AES-256 CBC initialisation vector size in bytes. */
#define ENCRIPTO_AES256_IV_SIZE    16

/** AES-256 GCM initialisation vector (nonce) size in bytes. */
#define ENCRIPTO_AES256_GCM_IV_SIZE  12

/** AES-256 GCM authentication tag size in bytes. */
#define ENCRIPTO_AES256_GCM_TAG_SIZE 16

/** Encrypt plaintext with AES-256 in CBC mode (PKCS#7 padding).
 *  Output length is padded to a multiple of block size.
 *  @param key    32-byte key.
 *  @param iv    16-byte initialisation vector.
 *  @param pt     Plaintext input.
 *  @param len    Plaintext length in bytes.
 *  @param ct     Ciphertext output (must be >= len + block_size).
 *  @param ct_len On input: capacity of ct; on output: bytes written.
 *  @return ENCRIPTO_OK on success, or ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_aes256_cbc_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, size_t *ct_len);

/** Decrypt ciphertext with AES-256 in CBC mode (PKCS#7 padding).
 *  @param key    32-byte key.
 *  @param iv    16-byte initialisation vector.
 *  @param ct     Ciphertext input.
 *  @param ct_len Ciphertext length in bytes (must be block-aligned).
 *  @param pt     Plaintext output (must be >= ct_len).
 *  @param pt_len On input: capacity of pt; on output: bytes written.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_aes256_cbc_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *pt, size_t *pt_len);

/** Encrypt and authenticate plaintext with AES-256-GCM.
 *  @param key 32-byte key.
 *  @param iv  12-byte nonce.
 *  @param pt   Plaintext input.
 *  @param len  Plaintext length in bytes.
 *  @param ct   Ciphertext output (same length as pt).
 *  @param tag  16-byte authentication tag output.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_aes256_gcm_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE]);

/** Decrypt and verify authenticity with AES-256-GCM.
 *  @param key 32-byte key.
 *  @param iv  12-byte nonce.
 *  @param ct   Ciphertext input (same length as pt).
 *  @param len  Ciphertext length in bytes.
 *  @param tag  16-byte authentication tag (must match).
 *  @param pt   Plaintext output (same length as ct).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_AUTH on tag mismatch,
 *          ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_aes256_gcm_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *ct, size_t len,
                                 const uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE],
                                 uint8_t *pt);

/** Number of round key words in AES-256 expanded key schedule. */
#define ENCRIPTO_AES256_ROUND_KEYS 60

/** AES-256 opaque context (defined in src/aes.c). */
typedef struct encripto_aes256_ctx encripto_aes256_ctx;

/** Create an AES-256 context and expand the key schedule.
 *  @param key  32-byte key.
 *  @return Pointer to allocated context, or NULL on allocation failure.
 */
encripto_aes256_ctx *encripto_aes256_new(
    const uint8_t key[ENCRIPTO_AES256_KEY_SIZE]);

/** Free an AES-256 context after zeroising sensitive key material.
 *  @param ctx  Context to free (may be NULL).
 */
void encripto_aes256_free(encripto_aes256_ctx *ctx);

/** AES-256 block cipher encryption (ECB).
 *  Encrypts a single block with the expanded key schedule.
 *  @param ctx  Initialised context.
 *  @param in   16-byte plaintext block.
 *  @param out  16-byte ciphertext block.
 */
void encripto_aes256_encrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]);

/** AES-256 block cipher decryption (ECB).
 *  Decrypts a single block with the expanded key schedule.
 *  @param ctx  Initialised context.
 *  @param in   16-byte ciphertext block.
 *  @param out  16-byte plaintext block.
 */
void encripto_aes256_decrypt(encripto_aes256_ctx *ctx,
                              const uint8_t in[ENCRIPTO_AES256_BLOCK_SIZE],
                              uint8_t out[ENCRIPTO_AES256_BLOCK_SIZE]);

/** Expand a 32-byte AES-256 key into 60 round key words (FIPS 197).
 *  @param key         32-byte key.
 *  @param round_keys  Output array (ENCRIPTO_AES256_ROUND_KEYS words).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int  encripto_aes256_key_expand(
    const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
    uint32_t round_keys[ENCRIPTO_AES256_ROUND_KEYS]);

/** Zeroise expanded round keys with a volatile pointer.
 *  @param round_keys  Array to clear (may be NULL).
 */
void encripto_aes256_key_clear(
    uint32_t round_keys[ENCRIPTO_AES256_ROUND_KEYS]);

/* ── ChaCha20 stream cipher (RFC 8439) ────────────────────── */

/** ChaCha20 key size in bytes. */
#define ENCRIPTO_CHACHA20_KEY_SIZE   32

/** ChaCha20 nonce size in bytes. */
#define ENCRIPTO_CHACHA20_NONCE_SIZE 12

/** ChaCha20 block size in bytes (64-byte keystream blocks). */
#define ENCRIPTO_CHACHA20_BLOCK_SIZE 64

/** Encrypt/decrypt with the ChaCha20 stream cipher (RFC 8439).
 *  Encrypt and decrypt are identical (stream cipher XOR).
 *  @param key    32-byte key.
 *  @param counter Initial counter value (typically 0 or 1).
 *  @param nonce  12-byte nonce.
 *  @param in     Input bytes (plaintext for encrypt, ciphertext for decrypt).
 *  @param len    Number of bytes to process.
 *  @param out    Output buffer (same length as in).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_chacha20_encrypt(const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
                               uint32_t counter,
                               const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
                               const uint8_t *in, size_t len,
                               uint8_t *out);

/* ── ChaCha20-Poly1305 ───────────────────────────────────── */

/** ChaCha20-Poly1305 authentication tag size in bytes. */
#define ENCRIPTO_CHACHA20_TAG_SIZE   16

/** Encrypt and authenticate plaintext with ChaCha20-Poly1305 (RFC 8439).
 *  @param key   32-byte key.
 *  @param nonce 12-byte nonce.
 *  @param pt    Plaintext input.
 *  @param len   Plaintext length in bytes.
 *  @param ct    Ciphertext output (same length as pt).
 *  @param tag   16-byte authentication tag output.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_chacha20_poly1305_encrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *pt, size_t len,
    uint8_t *ct, uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE]);

/** Decrypt and verify authenticity with ChaCha20-Poly1305 (RFC 8439).
 *  @param key   32-byte key.
 *  @param nonce 12-byte nonce.
 *  @param ct    Ciphertext input (same length as pt).
 *  @param len   Ciphertext length in bytes.
 *  @param tag   16-byte authentication tag (must match).
 *  @param pt    Plaintext output (same length as ct).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_AUTH on tag mismatch,
 *          ENCRIPTO_ERR_PARAM on invalid args.
 */
int encripto_chacha20_poly1305_decrypt(
    const uint8_t key[ENCRIPTO_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ENCRIPTO_CHACHA20_NONCE_SIZE],
    const uint8_t *ct, size_t len,
    const uint8_t tag[ENCRIPTO_CHACHA20_TAG_SIZE],
    uint8_t *pt);

/* ── Poly1305 one-time MAC (RFC 8439 Section 2.5) ─────────── */

/** Poly1305 key size in bytes. */
#define ENCRIPTO_POLY1305_KEY_SIZE   32

/** Poly1305 authentication tag size in bytes. */
#define ENCRIPTO_POLY1305_TAG_SIZE   16

/** Poly1305 computation context (5-limb radix-2^26 representation). */
typedef struct {
    uint64_t r[5];         /**< clamped key r (0-4) */
    uint64_t s[4];         /**< r[1..4] * 5 (precomputed) */
    uint64_t h[5];         /**< 130-bit accumulator */
    uint64_t pad[2];       /**< pad s loaded as two 64-bit LE words */
    uint8_t  buffer[16];   /**< partial block buffer */
    size_t   buffer_len;   /**< bytes used in buffer */
} encripto_poly1305_ctx;

/** Initialize a Poly1305 MAC computation with a one-time key.
 *  @param ctx  Context to initialize (must not be NULL).
 *  @param key  32-byte one-time key (first 16 bytes = r, last 16 = s).
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_poly1305_init(encripto_poly1305_ctx *ctx,
                            const uint8_t key[ENCRIPTO_POLY1305_KEY_SIZE]);

/** Process arbitrary-length data through Poly1305.
 *  Can be called multiple times. Input is buffered internally.
 *  @param ctx  Initialised Poly1305 context.
 *  @param data Input bytes.
 *  @param len  Number of bytes.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_poly1305_update(encripto_poly1305_ctx *ctx,
                              const uint8_t *data, size_t len);

/** Finalise the Poly1305 MAC and produce the 16-byte tag.
 *  Context is zeroed after this call (safe to reuse with init).
 *  @param ctx  Initialised Poly1305 context.
 *  @param tag  16-byte authentication tag output.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input.
 */
int encripto_poly1305_final(encripto_poly1305_ctx *ctx,
                             uint8_t tag[ENCRIPTO_POLY1305_TAG_SIZE]);

/* ── RSA-4096 ────────────────────────────────────────────── */

/** RSA-4096 key size in bits. */
#define ENCRIPTO_RSA_KEY_SIZE      4096

/** RSA-4096 key size in bits (alias). */
#define ENCRIPTO_RSA4096_KEY_SIZE  4096

/** Opaque RSA-4096 key pair (defined in src/rsa.c). */
typedef struct encripto_rsa_keypair encripto_rsa_keypair;

/** Generate a new RSA-4096 key pair.
 *  @param kp  On success receives pointer to allocated key pair.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL output
 *          pointer, ENCRIPTO_ERR_NOMEM on allocation failure.
 */
int  encripto_rsa4096_keygen(encripto_rsa_keypair **kp);

/** RSA-4096 public-key encryption.
 *  @param kp     Key pair (public key is used).
 *  @param pt     Plaintext input.
 *  @param len    Plaintext length.
 *  @param ct     Ciphertext output.
 *  @param ct_len On input: capacity of ct; on output: bytes written.
 *  @return ENCRIPTO_OK on success, or an error code on failure.
 */
int  encripto_rsa4096_encrypt(const encripto_rsa_keypair *kp,
                               const uint8_t *pt, size_t len,
                               uint8_t *ct, size_t *ct_len);

/** RSA-4096 private-key decryption.
 *  @param kp     Key pair (private key is used).
 *  @param ct     Ciphertext input.
 *  @param len    Ciphertext length.
 *  @param pt     Plaintext output.
 *  @param pt_len On input: capacity of pt; on output: bytes written.
 *  @return ENCRIPTO_OK on success, or an error code on failure.
 */
int  encripto_rsa4096_decrypt(const encripto_rsa_keypair *kp,
                               const uint8_t *ct, size_t len,
                               uint8_t *pt, size_t *pt_len);

/** RSA-4096 signature generation (RSASSA-PKCS1-v1_5 with SHA-256).
 *  @param kp      Key pair (private key is used).
 *  @param msg     Message to sign.
 *  @param len     Message length.
 *  @param sig     Signature output.
 *  @param sig_len On input: capacity of sig; on output: bytes written.
 *  @return ENCRIPTO_OK on success, or an error code on failure.
 */
int  encripto_rsa4096_sign(const encripto_rsa_keypair *kp,
                            const uint8_t *msg, size_t len,
                            uint8_t *sig, size_t *sig_len);

/** RSA-4096 signature verification (RSASSA-PKCS1-v1_5 with SHA-256).
 *  @param kp      Key pair (public key is used).
 *  @param msg     Message that was signed.
 *  @param len     Message length.
 *  @param sig     Signature to verify.
 *  @param sig_len Signature length.
 *  @return ENCRIPTO_OK if signature is valid, ENCRIPTO_ERR_AUTH if
 *          invalid, or another error code on parameter failure.
 */
int  encripto_rsa4096_verify(const encripto_rsa_keypair *kp,
                              const uint8_t *msg, size_t len,
                              const uint8_t *sig, size_t sig_len);

/** Free an RSA key pair allocated by encripto_rsa4096_keygen().
 *  Safe to call with NULL (no-op).
 */
void encripto_rsa_keypair_free(encripto_rsa_keypair *kp);

/* ── Random number generation ────────────────────────────── */

/** Fill a buffer with cryptographically secure random bytes.
 *  @param buf  Output buffer.
 *  @param n    Number of bytes to generate.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on NULL input,
 *          ENCRIPTO_ERR_RNG on system RNG failure.
 */
int encripto_rand_bytes(uint8_t *buf, size_t n);

/** Generate a cryptographically secure random key.
 *  @param key     Output buffer for the key.
 *  @param key_len Key length in bytes.
 *  @return ENCRIPTO_OK on success, or an error code on failure.
 */
int encripto_rand_key(uint8_t *key, size_t key_len);

/* ── Encoding helpers ────────────────────────────────────── */

/** Encode bytes as a lowercase hex string (null-terminated).
 *  @param in     Input bytes.
 *  @param in_len Number of input bytes.
 *  @param out    Output buffer (must be >= 2 * in_len + 1).
 */
void encripto_hex_encode(const uint8_t *in, size_t in_len, char *out);

/** Decode a hex string back to raw bytes.
 *  @param in      Null-terminated hex string.
 *  @param out     Output buffer.
 *  @param out_len On input: capacity of out; on output: bytes written.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on invalid input
 *          or insufficient buffer.
 */
int  encripto_hex_decode(const char *in, uint8_t *out, size_t *out_len);

/** Encode bytes as a base64 string (null-terminated).
 *  @param in     Input bytes.
 *  @param in_len Number of input bytes.
 *  @param out    Output buffer (must be >= 4 * ((in_len + 2) / 3) + 1).
 */
void encripto_base64_encode(const uint8_t *in, size_t in_len, char *out);

/** Decode a base64 string back to raw bytes.
 *  @param in      Null-terminated base64 string.
 *  @param out     Output buffer.
 *  @param out_len On input: capacity of out; on output: bytes written.
 *  @return ENCRIPTO_OK on success, ENCRIPTO_ERR_PARAM on invalid input
 *          or insufficient buffer.
 */
int  encripto_base64_decode(const char *in, uint8_t *out, size_t *out_len);

/* ── Version ─────────────────────────────────────────────── */

/** Library version string (semantic versioning). */
#define ENCRIPTO_VERSION "0.1.0"

/** Return the library version string.
 *  @return Pointer to the version string (never NULL).
 */
const char *encripto_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ENCRIPTO_H */
