/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_PP_NORM_PRODUCT_
#define _SECP256K1_MODULE_BULLETPROOFS_PP_NORM_PRODUCT_

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "hash.h"

#include "modules/bulletproofs/main.h"
#include "modules/bulletproofs/bulletproofs_util.h"

/* Computes the inner product of two vectors of scalars
 * with elements starting from offset a and offset b
 * skipping elements according to specified step.
 * Returns: Sum_{i=0..len-1}(a[offset_a + i*step] * b[offset_b + i*step]) */
static int secp256k1_scalar_inner_product(
    secp256k1_scalar* res,
    const secp256k1_scalar* a_vec,
    const size_t a_offset,
    const secp256k1_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len
) {
    size_t i;
    secp256k1_scalar_set_int(res, 0);
    for (i = 0; i < len; i++) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        secp256k1_scalar_add(res, res, &term);
    }
    return 1;
}

/* Computes the q-weighted inner product of two vectors of scalars
 * for elements starting from offset a and offset b respectively with the
 * given step.
 * Returns: Sum_{i=0..len-1}(a[offset_a + step*i] * b[offset_b2 + step*i]*q^(i+1)) */
static int secp256k1_weighted_scalar_inner_product(
    secp256k1_scalar* res,
    const secp256k1_scalar* a_vec,
    const size_t a_offset,
    const secp256k1_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len,
    const secp256k1_scalar* q
) {
    secp256k1_scalar q_pow;
    size_t i;
    secp256k1_scalar_set_int(res, 0);
    q_pow = *q;
    for (i = 0; i < len; i++) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        secp256k1_scalar_mul(&term, &term, &q_pow);
        secp256k1_scalar_mul(&q_pow, &q_pow, q);
        secp256k1_scalar_add(res, res, &term);
    }
    return 1;
}

/* Compute the powers of r as r, r^2, r^4 ... r^(2^(n-1)) */
static void secp256k1_bulletproofs_powers_of_r(secp256k1_scalar *powers, const secp256k1_scalar *r, size_t n) {
    size_t i;
    if (n == 0) {
        return;
    }
    powers[0] = *r;
    for (i = 1; i < n; i++) {
        secp256k1_scalar_sqr(&powers[i], &powers[i - 1]);
    }
}
#endif
