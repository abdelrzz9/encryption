#include "encripto.h"
#include <errno.h>
#include <string.h>
#include <sys/random.h>

int encripto_rand_bytes(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0)
        return -EINVAL;

    size_t total = 0;
    while (total < len) {
        ssize_t ret = getrandom(buf + total, len - total, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        total += (size_t)ret;
    }
    return 0;
}

int encripto_rand_key(uint8_t *key, size_t key_len) {
    return encripto_rand_bytes(key, key_len);
}

void encripto_hex_encode(const uint8_t *in, size_t in_len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[in_len * 2] = '\0';
}

int encripto_hex_decode(const char *in, uint8_t *out, size_t *out_len) {
    size_t len = strlen(in) / 2;
    if (*out_len < len) return -1;
    for (size_t i = 0; i < len; i++) {
        char hi = in[i * 2];
        char lo = in[i * 2 + 1];
        uint8_t b = 0;
        if (hi >= '0' && hi <= '9')      b = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') b = (hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') b = (hi - 'A' + 10) << 4;
        else return -1;
        if (lo >= '0' && lo <= '9')      b |= (lo - '0');
        else if (lo >= 'a' && lo <= 'f') b |= (lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') b |= (lo - 'A' + 10);
        else return -1;
        out[i] = b;
    }
    *out_len = len;
    return 0;
}

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void encripto_base64_encode(const uint8_t *in, size_t in_len, char *out) {
    size_t i = 0, j = 0;
    while (in_len - i >= 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j]   = b64[(v >> 18) & 0x3f];
        out[j+1] = b64[(v >> 12) & 0x3f];
        out[j+2] = b64[(v >> 6) & 0x3f];
        out[j+3] = b64[v & 0x3f];
        i += 3; j += 4;
    }
    size_t rem = in_len - i;
    if (rem) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (rem > 1) v |= (uint32_t)in[i+1] << 8;
        out[j]   = b64[(v >> 18) & 0x3f];
        out[j+1] = b64[(v >> 12) & 0x3f];
        if (rem == 2) out[j+2] = b64[(v >> 6) & 0x3f];
        else out[j+2] = '=';
        out[j+3] = '=';
        j += 4;
    }
    out[j] = '\0';
}

int encripto_base64_decode(const char *in, uint8_t *out, size_t *out_len) {
    (void)in;
    (void)out;
    (void)out_len;
    return -1;
}

const char *encripto_version(void) {
    return ENCRIPTO_VERSION;
}
