#include "encripto.h"
#include <stdlib.h>
#include <string.h>

struct encripto_rsa_keypair {
    int placeholder;
};

encripto_rsa_keypair *encripto_rsa_generate(void) {
    encripto_rsa_keypair *kp = calloc(1, sizeof(*kp));
    (void)kp;
    return kp;
}

void encripto_rsa_free(encripto_rsa_keypair *kp) {
    free(kp);
}

int encripto_rsa_encrypt(encripto_rsa_keypair *kp,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t *out_len) {
    (void)kp;
    if (*out_len < in_len) return -1;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 0;
}

int encripto_rsa_decrypt(encripto_rsa_keypair *kp,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t *out_len) {
    (void)kp;
    if (*out_len < in_len) return -1;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 0;
}
