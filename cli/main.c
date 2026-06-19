#include "encripto.h"
#include <stdio.h>
#include <string.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "Encripto v%s\n", encripto_version());
    fprintf(stderr, "Usage: %s <command> [args]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  encrypt   Encrypt data\n");
    fprintf(stderr, "  decrypt   Decrypt data\n");
    fprintf(stderr, "  hash      Compute SHA-256 hash\n");
    fprintf(stderr, "  version   Show version\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "version") == 0) {
        printf("Encripto %s\n", encripto_version());
        return 0;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        fprintf(stderr, "encrypt: not yet implemented\n");
        return 1;
    }

    if (strcmp(argv[1], "decrypt") == 0) {
        fprintf(stderr, "decrypt: not yet implemented\n");
        return 1;
    }

    if (strcmp(argv[1], "hash") == 0) {
        fprintf(stderr, "hash: not yet implemented\n");
        return 1;
    }

    print_usage(argv[0]);
    return 1;
}
