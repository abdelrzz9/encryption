#include "encripto.h"
#include "test_utils.h"
#include <stdio.h>

typedef struct {
    const char *input;
    size_t      input_len;
    const char *expected_hex;
} sha512_test_vector;

static const sha512_test_vector VECTORS[] = {
    { "", 0,
      "cf83e1357eefb8bdf1542850d66d8007"
      "d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f"
      "63b931bd47417a81a538327af927da3e" },
    { "abc", 3,
      "ddaf35a193617abacc417349ae204131"
      "12e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd"
      "454d4423643ce80e2a9ac94fa54ca49f" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
      "204a8fc6dda82f0a0ced7beb8e08a416"
      "57c16ef468b228a8279be331a703c335"
      "96fd15c13b1b07f9aa1d3bea57789ca0"
      "31ad85c7a71dd70354ec631238ca3445" },
};

static const sha512_test_vector EDGE_VECTORS[] = {
    { "\x00", 1,
      "b8244d028981d693af7b456af8efa4ca"
      "d63d282e19ff14942c246e50d9351d22"
      "704a802a71c3580b6370de4ceb293c32"
      "4a8423342557d4e5c38438f0e36910ee" },
    { "\x80", 1,
      "dfe8ef54110b3324d3b889035c95cfb8"
      "0c92704614bf76f17546ad4f4b08218a"
      "630e16da7df34766a975b3bb85b01df9"
      "e99a4ec0a1d0ec3de6bed7b7a40b2f10" },
};

static void test_sha512_oneshot(const sha512_test_vector *tv) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];

    encripto_sha512((const uint8_t *)tv->input, tv->input_len, digest);
    hex_decode(tv->expected_hex, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
}

static void run_vector_tests(void) {
    for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
        printf("  vector[%zu] ... ", i);
        test_sha512_oneshot(&VECTORS[i]);
        printf("PASS\n");
    }
}

static void test_sha512_empty(void) {
    printf("  empty string ... ");
    test_sha512_oneshot(&VECTORS[0]);
    printf("PASS\n");
}

static void test_sha512_single_0x00(void) {
    printf("  single 0x00 byte ... ");
    test_sha512_oneshot(&EDGE_VECTORS[0]);
    printf("PASS\n");
}

static void test_sha512_single_0x80(void) {
    printf("  single 0x80 byte ... ");
    test_sha512_oneshot(&EDGE_VECTORS[1]);
    printf("PASS\n");
}

static void test_sha512_boundary_55(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[55];
    memset(buf, 'a', 55);

    printf("  55 bytes (before SHA-512 block boundary) ... ");
    encripto_sha512(buf, 55, digest);
    hex_decode("b0220c772cbf6c1822e2cb38a437d0e1"
               "d58772417a4bbb21c961364f8b6143e0"
               "5aa6316dca8d1d7b19e1644841907639"
               "5f6086cb55101fbd6d5497b148e1745f",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_boundary_56(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[56];
    memset(buf, 'a', 56);

    printf("  56 bytes ... ");
    encripto_sha512(buf, 56, digest);
    hex_decode("962b64aae357d2a4fee3ded8b539bdc9"
               "d325081822b0bfc55583133aab44f18b"
               "afe11d72a7ae16c79ce2ba620ae2242d"
               "5144809161945f1367f41b3972e26e04",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_boundary_111(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[111];
    memset(buf, 'a', 111);

    printf("  111 bytes (before SHA-512 padding boundary) ... ");
    encripto_sha512(buf, 111, digest);
    hex_decode("fa9121c7b32b9e01733d034cfc78cbf6"
               "7f926c7ed83e82200ef8681819692176"
               "0b4beff48404df811b95382827446167"
               "3c68d04e297b0eb7b2b4d60fc6b566a2",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_boundary_112(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[112];
    memset(buf, 'a', 112);

    printf("  112 bytes (at SHA-512 padding boundary, extra block) ... ");
    encripto_sha512(buf, 112, digest);
    hex_decode("c01d080efd492776a1c43bd23dd99d0a"
               "2e626d481e16782e75d54c2503b5dc32"
               "bd05f0f1ba33e568b88fd2d970929b71"
               "9ecbb152f58f130a407c8830604b70ca",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_boundary_128(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[128];
    memset(buf, 'a', 128);

    printf("  128 bytes (exactly one SHA-512 block) ... ");
    encripto_sha512(buf, 128, digest);
    hex_decode("b73d1929aa615934e61a871596b3f3b3"
               "3359f42b8175602e89f7e06e5f658a24"
               "3667807ed300314b95cacdd579f3e33a"
               "bdfbe351909519a846d465c59582f321",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_all_zeros(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[64];
    memset(buf, 0, 64);

    printf("  all zeros (64 bytes) ... ");
    encripto_sha512(buf, 64, digest);
    hex_decode("7be9fda48f4179e611c698a73cff09fa"
               "f72869431efee6eaad14de0cb44bbf66"
               "503f752b7a8eb17083355f3ce6eb7d28"
               "06f236b25af96a24e22b887405c20081",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_all_ff(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t buf[64];
    memset(buf, 0xFF, 64);

    printf("  all 0xFF bytes (64 bytes) ... ");
    encripto_sha512(buf, 64, digest);
    hex_decode("c835487ff6669f49f62757e572e7d3f9"
               "561fb6e111566ea086efa37923745966"
               "d6e7ed2220adf68321f89f818fcc8947"
               "fa87138896b3ac63b0504b3cdbd4f1e6",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_streaming(void) {
    const char *msg = "Hello, world!";
    uint8_t digest_once[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t digest_chunked[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];

    printf("  streaming (one-shot vs chunked) ... ");

    encripto_sha512((const uint8_t *)msg, 13, digest_once);

    encripto_sha512_ctx ctx;
    encripto_sha512_init(&ctx);
    encripto_sha512_update(&ctx, (const uint8_t *)msg, 5);
    encripto_sha512_update(&ctx, (const uint8_t *)msg + 5, 8);
    encripto_sha512_final(&ctx, digest_chunked);

    ASSERT_EQ_HEX(digest_once, digest_chunked, ENCRIPTO_SHA512_DIGEST_SIZE);

    hex_decode("c1527cd893c124773d811911970c8fe6"
               "e857d6df5dc9226bd8a160614c0cd963"
               "a4ddea2b94bb7d36021ef9d865d5cea2"
               "94a82dd49a0bb269f51f6e7a57f79421",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest_once, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

static void test_sha512_million_a(void) {
    uint8_t digest[ENCRIPTO_SHA512_DIGEST_SIZE];
    uint8_t expected[ENCRIPTO_SHA512_DIGEST_SIZE];
    encripto_sha512_ctx ctx;
    uint8_t buf[4096];

    printf("  1 million 'a' characters ... ");

    memset(buf, 'a', sizeof(buf));
    encripto_sha512_init(&ctx);
    size_t remaining = 1000000;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        encripto_sha512_update(&ctx, buf, chunk);
        remaining -= chunk;
    }
    encripto_sha512_final(&ctx, digest);

    hex_decode("e718483d0ce769644e2e42c7bc15b463"
               "8e1f98b13b2044285632a803afa973eb"
               "de0ff244877ea60a4cb0432ce577c31b"
               "eb009c5c2c49aa2e4eadb217ad8cc09b",
               expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    ASSERT_EQ_HEX(digest, expected, ENCRIPTO_SHA512_DIGEST_SIZE);
    printf("PASS\n");
}

int main(void) {
    printf("SHA-512 tests:\n");

    printf("  NIST vectors:\n");
    run_vector_tests();

    printf("  Edge cases:\n");
    test_sha512_empty();
    test_sha512_single_0x00();
    test_sha512_single_0x80();
    test_sha512_boundary_55();
    test_sha512_boundary_56();
    test_sha512_boundary_111();
    test_sha512_boundary_112();
    test_sha512_boundary_128();
    test_sha512_all_zeros();
    test_sha512_all_ff();

    printf("  Streaming:\n");
    test_sha512_streaming();

    printf("  Large input:\n");
    test_sha512_million_a();

    if (tests_failed > 0) {
        printf("\nSHA-512: FAILED (%d passed, %d failed)\n",
               tests_passed, tests_failed);
        return 1;
    }
    printf("\nSHA-512: ALL PASSED (%d tests)\n", tests_passed);
    return 0;
}
