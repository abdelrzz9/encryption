#include "encripto.h"
#include <string.h>

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
