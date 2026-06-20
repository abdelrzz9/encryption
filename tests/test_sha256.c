#include "encripto.h"
#include "test_utils.h"
#include <stdio.h>

typedef struct {
    const char *input;
    size_t      input_len;
    const char *expected_hex;
} sha256_test_vector;

static const sha256_test_vector VECTORS[] = {
    { "", 0,
      "e3b0c44298fc1c149afbf4c8996fb924"
      "27ae41e4649b934ca495991b7852b855" },
    { "abc", 3,
      "ba7816bf8f01cfea414140de5dae2223"
      "b00361a396177a9cb410ff61f20015ad" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
      "248d6a61d20638b8e5c026930c3e6039"
      "a33ce45964ff2167f6ecedd419db06c1" },
};

static const sha256_test_vector EDGE_VECTORS[] = {
    { "\x00", 1,
      "6e340b9cffb37a989ca544e6bb780a2c"
      "78901d3fb33738768511a30617afa01d" },
    { "\x80", 1,
      "76be8b528d0075f7aae98d6fa57a6d3c"
      "83ae480a8469e668d7b0af968995ac71" },
};

static void test_sha256_oneshot(const sha256_test_vector *tv) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];

    encripto_sha256((const uint8_t *)tv->input, tv->input_len, digest);
    hex_decode(tv->expected_hex, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
}

static void run_vector_tests(void) {
    for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
        printf("  vector[%zu] ... ", i);
        test_sha256_oneshot(&VECTORS[i]);
        printf("PASS\n");
    }
}

static void test_sha256_empty(void) {
    printf("  empty string ... ");
    test_sha256_oneshot(&VECTORS[0]);
    printf("PASS\n");
}

static void test_sha256_single_0x00(void) {
    printf("  single 0x00 byte ... ");
    test_sha256_oneshot(&EDGE_VECTORS[0]);
    printf("PASS\n");
}

static void test_sha256_single_0x80(void) {
    printf("  single 0x80 byte ... ");
    test_sha256_oneshot(&EDGE_VECTORS[1]);
    printf("PASS\n");
}

static void test_sha256_boundary_55(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[55];
    memset(buf, 'a', 55);

    printf("  55 bytes (before padding boundary) ... ");
    encripto_sha256(buf, 55, digest);
    hex_decode("9f4390f8d30c2dd92ec9f095b65e2b9a"
               "e9b0a925a5258e241c9f1e910f734318",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_boundary_56(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[56];
    memset(buf, 'a', 56);

    printf("  56 bytes (at padding boundary, extra block) ... ");
    encripto_sha256(buf, 56, digest);
    hex_decode("b35439a4ac6f0948b6d6f9e3c6af0f5f"
               "590ce20f1bde7090ef7970686ec6738a",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_boundary_64(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[64];
    memset(buf, 'a', 64);

    printf("  64 bytes (exactly one block) ... ");
    encripto_sha256(buf, 64, digest);
    hex_decode("ffe054fe7ae0cb6dc65c3af9b61d5209"
               "f439851db43d0ba5997337df154668eb",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_boundary_65(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[65];
    memset(buf, 'a', 65);

    printf("  65 bytes (one block + 1 byte) ... ");
    encripto_sha256(buf, 65, digest);
    hex_decode("635361c48bb9eab14198e76ea8ab7f1a"
               "41685d6ad62aa9146d301d4f17eb0ae0",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_all_zeros(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[32];
    memset(buf, 0, 32);

    printf("  all zeros (32 bytes) ... ");
    encripto_sha256(buf, 32, digest);
    hex_decode("66687aadf862bd776c8fc18b8e9f8e20"
               "089714856ee233b3902a591d0d5f2925",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_all_ff(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t buf[32];
    memset(buf, 0xFF, 32);

    printf("  all 0xFF bytes (32 bytes) ... ");
    encripto_sha256(buf, 32, digest);
    hex_decode("af9613760f72635fbdb44a5a0a63c39f"
               "12af30f950a6ee5c971be188e89c4051",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_streaming(void) {
    const char *msg = "Hello, world!";
    uint8_t digest_once[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t digest_chunked[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];

    printf("  streaming (one-shot vs chunked) ... ");

    encripto_sha256((const uint8_t *)msg, 13, digest_once);

    encripto_sha256_ctx ctx;
    encripto_sha256_init(&ctx);
    encripto_sha256_update(&ctx, (const uint8_t *)msg, 5);
    encripto_sha256_update(&ctx, (const uint8_t *)msg + 5, 8);
    encripto_sha256_final(&ctx, digest_chunked);

    ASSERT_EQ_HEX(digest_once, digest_chunked, ENCRIPTO_SHA256_DIGEST_SIZE);

    hex_decode("315f5bdb76d078c43b8ac0064e4a0164"
               "612b1fce77c869345bfc94c75894edd3",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest_once, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha256_million_a(void) {
    uint8_t digest[ENCRIPTO_SHA256_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA256_DIGEST_SIZE];
    encripto_sha256_ctx ctx;
    uint8_t buf[4096];

    printf("  1 million 'a' characters ... ");

    memset(buf, 'a', sizeof(buf));
    encripto_sha256_init(&ctx);
    size_t remaining = 1000000;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        encripto_sha256_update(&ctx, buf, chunk);
        remaining -= chunk;
    }
    encripto_sha256_final(&ctx, digest);

    hex_decode("cdc76e5c9914fb9281a1c7e284d73e67"
               "f1809a48a497200e046d39ccc7112cd0",
               expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA256_DIGEST_SIZE);
    printf("PASS\n");
}

int main(void) {
    printf("SHA-256 tests:\n");

    printf("  NIST vectors:\n");
    run_vector_tests();

    printf("  Edge cases:\n");
    test_sha256_empty();
    test_sha256_single_0x00();
    test_sha256_single_0x80();
    test_sha256_boundary_55();
    test_sha256_boundary_56();
    test_sha256_boundary_64();
    test_sha256_boundary_65();
    test_sha256_all_zeros();
    test_sha256_all_ff();

    printf("  Streaming:\n");
    test_sha256_streaming();

    printf("  Large input:\n");
    test_sha256_million_a();

    if (tests_failed > 0) {
        printf("\nSHA-256: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nSHA-256: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
