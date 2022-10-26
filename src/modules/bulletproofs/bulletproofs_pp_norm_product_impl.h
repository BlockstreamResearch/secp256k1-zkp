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

typedef struct ecmult_bp_commit_cb_data {
    const secp256k1_scalar *n;
    const secp256k1_ge *g;
    const secp256k1_scalar *l;
    size_t g_len;
} ecmult_bp_commit_cb_data;

static int ecmult_bp_commit_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_bp_commit_cb_data *data = (ecmult_bp_commit_cb_data*) cbdata;
    *pt = data->g[idx];
    if (idx < data->g_len) {
        *sc = data->n[idx];
    } else {
        *sc = data->l[idx - data->g_len];
    }
    return 1;
}

/* Create a commitment `commit` = vG + n_vec*G_vec + l_vec*H_vec where
   v = |n_vec*n_vec|_q + <l_vec, c_vec>. |w|_q denotes q-weighted norm of w and
   <l, r> denotes inner product of l and r.
*/
static int secp256k1_bulletproofs_commit(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    secp256k1_ge* commit,
    const secp256k1_bulletproofs_generators* g_vec,
    const secp256k1_scalar* n_vec,
    size_t n_vec_len,
    const secp256k1_scalar* l_vec,
    size_t l_vec_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_scalar* q
) {
    secp256k1_scalar v, l_c;
    /* First n_vec_len generators are Gs, rest are Hs*/
    VERIFY_CHECK(g_vec->n == (n_vec_len + l_vec_len));
    VERIFY_CHECK(l_vec_len == c_vec_len);

    /* It is possible to extend to support n_vec and c_vec to not be power of
    two. For the initial iterations of the code, we stick to powers of two for simplicity.*/
    VERIFY_CHECK(secp256k1_is_power_of_two(n_vec_len));
    VERIFY_CHECK(secp256k1_is_power_of_two(c_vec_len));

    /* Compute v = n_vec*n_vec*q + l_vec*c_vec */
    secp256k1_weighted_scalar_inner_product(&v, n_vec, 0 /*a offset */, n_vec, 0 /*b offset*/, 1 /*step*/, n_vec_len, q);
    secp256k1_scalar_inner_product(&l_c, l_vec, 0 /*a offset */, c_vec, 0 /*b offset*/, 1 /*step*/, l_vec_len);
    secp256k1_scalar_add(&v, &v, &l_c);

    {
        ecmult_bp_commit_cb_data data;
        secp256k1_gej commitj;
        data.g = g_vec->gens;
        data.n = n_vec;
        data.l = l_vec;
        data.g_len = n_vec_len;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &commitj, &v, ecmult_bp_commit_cb, (void*) &data, n_vec_len + l_vec_len)) {
            return 0;
        }
        secp256k1_ge_set_gej_var(commit, &commitj);
    }
    return 1;
}
#endif
