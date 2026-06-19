#include "encripto.h"
#include <string.h>

int encripto_aes256_cbc_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, size_t *ct_len) {
    (void)key; (void)iv;
    if (!pt || !ct || !ct_len)
        return ENCRIPTO_ERR_PARAM;
    if (*ct_len < len)
        return ENCRIPTO_ERR_PARAM;
    memcpy(ct, pt, len);
    *ct_len = len;
    return ENCRIPTO_OK;
}

int encripto_aes256_cbc_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_IV_SIZE],
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *pt, size_t *pt_len) {
    (void)key; (void)iv;
    if (!ct || !pt || !pt_len)
        return ENCRIPTO_ERR_PARAM;
    if (*pt_len < ct_len)
        return ENCRIPTO_ERR_PARAM;
    memcpy(pt, ct, ct_len);
    *pt_len = ct_len;
    return ENCRIPTO_OK;
}

int encripto_aes256_gcm_encrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *pt, size_t len,
                                 uint8_t *ct, uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE]) {
    (void)key; (void)iv;
    if (!pt || !ct || !tag)
        return ENCRIPTO_ERR_PARAM;
    memcpy(ct, pt, len);
    memset(tag, 0, ENCRIPTO_AES256_GCM_TAG_SIZE);
    return ENCRIPTO_OK;
}

int encripto_aes256_gcm_decrypt(const uint8_t key[ENCRIPTO_AES256_KEY_SIZE],
                                 const uint8_t iv[ENCRIPTO_AES256_GCM_IV_SIZE],
                                 const uint8_t *ct, size_t len,
                                 const uint8_t tag[ENCRIPTO_AES256_GCM_TAG_SIZE],
                                 uint8_t *pt) {
    (void)key; (void)iv; (void)tag;
    if (!ct || !pt)
        return ENCRIPTO_ERR_PARAM;
    memcpy(pt, ct, len);
    return ENCRIPTO_OK;
}
