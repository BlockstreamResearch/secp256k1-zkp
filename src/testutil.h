/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_TESTUTIL_H
#define SECP256K1_TESTUTIL_H

#include "field.h"
#include "testrand.h"
#include "util.h"

static void random_fe(secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        secp256k1_testrand256(bin);
        if (secp256k1_fe_set_b32_limit(x, bin)) {
            return;
        }
    } while(1);
}

static void random_fe_non_zero(secp256k1_fe *nz) {
    do {
        random_fe(nz);
    } while (secp256k1_fe_is_zero(nz));
}

static void rand_flip_bit(unsigned char *array, size_t n) {
    array[secp256k1_testrand_int(n)] ^= 1 << secp256k1_testrand_int(8);
}

#endif /* SECP256K1_TESTUTIL_H */
