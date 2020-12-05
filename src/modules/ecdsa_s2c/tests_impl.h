/**********************************************************************
 * Copyright (c) 2019-2020 Marko Bencun, Jonas Nick                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_S2C_TESTS_H
#define SECP256K1_MODULE_ECDSA_S2C_TESTS_H

#include "include/secp256k1_ecdsa_s2c.h"

void run_s2c_opening_test(void) {
    int i = 0;
    unsigned char output[33];
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    unsigned char input[33] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02
    };
    secp256k1_ecdsa_s2c_opening opening;
    int32_t ecount = 0;

    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);

    /* First parsing, then serializing works */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, &opening) == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);
    CHECK(ecount == 0);

    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, NULL, input) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);

    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, NULL, &opening) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, NULL) == 0);

    CHECK(ecount == 4);
    /* Invalid pubkey makes parsing fail */
    input[0] = 0;  /* bad oddness bit */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 0);
    input[0] = 2;
    input[31] = 1; /* point not on the curve */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 0);
    CHECK(ecount == 4); /* neither of the above are API errors */

    /* Try parsing and serializing a bunch of openings */
    for (i = 0; i < count; i++) {
        /* This is expected to fail in about 50% of iterations because the
         * points' x-coordinates are uniformly random */
        if (secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1) {
            CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, &opening) == 1);
            CHECK(memcmp(output, input, sizeof(output)) == 0);
        }
        secp256k1_testrand256(&input[1]);
        /* Set pubkey oddness tag to first bit of input[1] */
        input[0] = (input[1] & 1) + 2;
        i++;
    }

    secp256k1_context_destroy(none);
}


static void run_ecdsa_s2c_tests(void) {
    run_s2c_opening_test();
}

#endif /* SECP256K1_MODULE_ECDSA_S2C_TESTS_H */
