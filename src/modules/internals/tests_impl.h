/***********************************************************************
 * Copyright (c) 2021  Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_INTERNALS_TESTS_H
#define SECP256K1_MODULE_INTERNALS_TESTS_H

#include "internals/secp256k1_scalar.h"

void test_internals_scalar(void) {
    secp256k1_internals_scalar *scalar;
    unsigned char buf_a[32], buf_b[32];

    scalar = malloc(secp256k1_internals_scalar_size());
    CHECK(scalar != NULL);
    memset(buf_a, 0, sizeof(buf_a));
    buf_a[0] = 1;
    secp256k1_internals_scalar_set_b32(scalar, buf_a, NULL);
    secp256k1_internals_scalar_add(scalar, scalar, scalar);
    secp256k1_internals_scalar_get_b32(buf_b, scalar);
    buf_a[0] = 2;
    CHECK(memcmp(buf_a, buf_b, 32) == 0);
    free(scalar);
}

void run_internals_tests(void) {
    test_internals_scalar();
}

#endif /* SECP256K1_MODULE_INTERNALS_TESTS_H */
