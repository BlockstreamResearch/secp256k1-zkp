/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_TEST_
#define _SECP256K1_MODULE_BULLETPROOFS_TEST_

static void test_bulletproofs_generators_api(void) {
    /* The BP generator API requires no precomp */
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    secp256k1_bulletproofs_generators *gens;
    unsigned char gens_ser[330];
    size_t len = sizeof(gens_ser);

    int32_t ecount = 0;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);

    /* Create */
    gens = secp256k1_bulletproofs_generators_create(none, 10);
    CHECK(gens != NULL && ecount == 0);

    /* Serialize */
    ecount = 0;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, NULL, gens_ser, &len));
    CHECK(ecount == 1);
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, NULL, &len));
    CHECK(ecount == 2);
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, NULL));
    CHECK(ecount == 3);
    len = 0;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    len = sizeof(gens_ser) - 1;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    len = sizeof(gens_ser);
    CHECK(secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    CHECK(ecount == 3);

    /* Parse */
    ecount = 0;
    secp256k1_bulletproofs_generators_destroy(none, gens); /* avoid leaking memory */
    gens = secp256k1_bulletproofs_generators_parse(none, NULL, sizeof(gens_ser));
    CHECK(gens == NULL && ecount == 1);
    /* Not a multiple of 33 */
    gens = secp256k1_bulletproofs_generators_parse(none, gens_ser, sizeof(gens_ser) - 1);
    CHECK(gens == NULL && ecount == 1);
    gens = secp256k1_bulletproofs_generators_parse(none, gens_ser, sizeof(gens_ser));
    CHECK(gens != NULL && ecount == 1);

    /* Destroy (we allow destroying a NULL context, it's just a noop. like free().) */
    ecount = 0;
    secp256k1_bulletproofs_generators_destroy(none, NULL);
    secp256k1_bulletproofs_generators_destroy(none, gens);
    CHECK(ecount == 0);

    secp256k1_context_destroy(none);
}

static void test_bulletproofs_generators_fixed(void) {
    secp256k1_bulletproofs_generators *gens = secp256k1_bulletproofs_generators_create(ctx, 3);
    unsigned char gens_ser[330];
    const unsigned char fixed_first_3[99] = {
        0x0b,
        0xb3, 0x4d, 0x5f, 0xa6, 0xb8, 0xf3, 0xd1, 0x38,
        0x49, 0xce, 0x51, 0x91, 0xb7, 0xf6, 0x76, 0x18,
        0xfe, 0x5b, 0xd1, 0x2a, 0x88, 0xb2, 0x0e, 0xac,
        0x33, 0x89, 0x45, 0x66, 0x7f, 0xb3, 0x30, 0x56,
        0x0a,
        0x62, 0x86, 0x15, 0x16, 0x92, 0x42, 0x10, 0x9e,
        0x9e, 0x64, 0xd4, 0xcb, 0x28, 0x81, 0x60, 0x9c,
        0x24, 0xb9, 0x89, 0x51, 0x2a, 0xd9, 0x01, 0xae,
        0xff, 0x75, 0x64, 0x9c, 0x37, 0x5d, 0xbd, 0x79,
        0x0a,
        0xed, 0xe0, 0x6e, 0x07, 0x5e, 0x79, 0xd0, 0xf7,
        0x7b, 0x03, 0x3e, 0xb9, 0xa9, 0x21, 0xa4, 0x5b,
        0x99, 0xf3, 0x9b, 0xee, 0xfe, 0xa0, 0x37, 0xa2,
        0x1f, 0xe9, 0xd7, 0x4f, 0x95, 0x8b, 0x10, 0xe2,
    };
    size_t len;

    len = 99;
    CHECK(secp256k1_bulletproofs_generators_serialize(ctx, gens, gens_ser, &len));
    CHECK(memcmp(gens_ser, fixed_first_3, sizeof(fixed_first_3)) == 0);

    len = sizeof(gens_ser);
    CHECK(secp256k1_bulletproofs_generators_serialize(ctx, gens, gens_ser, &len));
    CHECK(memcmp(gens_ser, fixed_first_3, sizeof(fixed_first_3)) == 0);

    secp256k1_bulletproofs_generators_destroy(ctx, gens);
}

void run_bulletproofs_tests(void) {
    test_bulletproofs_generators_api();
    test_bulletproofs_generators_fixed();
}

#endif
