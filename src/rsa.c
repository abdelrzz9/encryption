#include "encripto.h"
#include <stdlib.h>
#include <string.h>

struct encripto_rsa_keypair {
    int placeholder;
};

int encripto_rsa4096_keygen(encripto_rsa_keypair **kp) {
    if (!kp)
        return ENCRIPTO_ERR_PARAM;
    *kp = calloc(1, sizeof(encripto_rsa_keypair));
    if (!*kp)
        return ENCRIPTO_ERR_NOMEM;
    return ENCRIPTO_OK;
}

int encripto_rsa4096_encrypt(const encripto_rsa_keypair *kp,
                              const uint8_t *pt, size_t len,
                              uint8_t *ct, size_t *ct_len) {
    (void)kp;
    if (!pt || !ct || !ct_len)
        return ENCRIPTO_ERR_PARAM;
    if (*ct_len < len)
        return ENCRIPTO_ERR_PARAM;
    memcpy(ct, pt, len);
    *ct_len = len;
    return ENCRIPTO_OK;
}

int encripto_rsa4096_decrypt(const encripto_rsa_keypair *kp,
                              const uint8_t *ct, size_t len,
                              uint8_t *pt, size_t *pt_len) {
    (void)kp;
    if (!ct || !pt || !pt_len)
        return ENCRIPTO_ERR_PARAM;
    if (*pt_len < len)
        return ENCRIPTO_ERR_PARAM;
    memcpy(pt, ct, len);
    *pt_len = len;
    return ENCRIPTO_OK;
}

int encripto_rsa4096_sign(const encripto_rsa_keypair *kp,
                           const uint8_t *msg, size_t len,
                           uint8_t *sig, size_t *sig_len) {
    (void)kp;
    if (!msg || !sig || !sig_len)
        return ENCRIPTO_ERR_PARAM;
    if (*sig_len < len)
        return ENCRIPTO_ERR_PARAM;
    memcpy(sig, msg, len);
    *sig_len = len;
    return ENCRIPTO_OK;
}

int encripto_rsa4096_verify(const encripto_rsa_keypair *kp,
                             const uint8_t *msg, size_t len,
                             const uint8_t *sig, size_t sig_len) {
    (void)kp;
    if (!msg || !sig)
        return ENCRIPTO_ERR_PARAM;
    if (len != sig_len)
        return ENCRIPTO_ERR_AUTH;
    if (memcmp(msg, sig, len) != 0)
        return ENCRIPTO_ERR_AUTH;
    return ENCRIPTO_OK;
}

void encripto_rsa_keypair_free(encripto_rsa_keypair *kp) {
    free(kp);
}
