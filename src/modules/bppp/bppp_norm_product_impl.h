/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPPP_PP_NORM_PRODUCT_H
#define SECP256K1_MODULE_BPPP_PP_NORM_PRODUCT_H

#include "../../group.h"
#include "../../scalar.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"
#include "../../hash.h"

#include "../bppp/main.h"
#include "../bppp/bppp_util.h"
#include "../bppp/bppp_transcript_impl.h"

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
 * Returns: Sum_{i=0..len-1}(a[offset_a + step*i] * b[offset_b2 + step*i]*mu^(i+1)) */
static int secp256k1_weighted_scalar_inner_product(
    secp256k1_scalar* res,
    const secp256k1_scalar* a_vec,
    const size_t a_offset,
    const secp256k1_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len,
    const secp256k1_scalar* mu
) {
    secp256k1_scalar mu_pow;
    size_t i;
    secp256k1_scalar_set_int(res, 0);
    mu_pow = *mu;
    for (i = 0; i < len; i++) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        secp256k1_scalar_mul(&term, &term, &mu_pow);
        secp256k1_scalar_mul(&mu_pow, &mu_pow, mu);
        secp256k1_scalar_add(res, res, &term);
    }
    return 1;
}

/* Compute the powers of rho as rho, rho^2, rho^4 ... rho^(2^(n-1)) */
static void secp256k1_bppp_powers_of_rho(secp256k1_scalar *powers, const secp256k1_scalar *rho, size_t n) {
    size_t i;
    if (n == 0) {
        return;
    }
    powers[0] = *rho;
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
   v = |n_vec*n_vec|_mu + <l_vec, c_vec>. |w|_mu denotes mu-weighted norm of w and
   <l, r> denotes inner product of l and r.
*/
static int secp256k1_bppp_commit(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    secp256k1_ge* commit,
    const secp256k1_bppp_generators* g_vec,
    const secp256k1_scalar* n_vec,
    size_t n_vec_len,
    const secp256k1_scalar* l_vec,
    size_t l_vec_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_scalar* mu
) {
    secp256k1_scalar v, l_c;
    /* First n_vec_len generators are Gs, rest are Hs*/
    VERIFY_CHECK(g_vec->n == (n_vec_len + l_vec_len));
#ifdef VERIFY
    VERIFY_CHECK(l_vec_len == c_vec_len);
#else
    (void)c_vec_len;
#endif

    /* Compute v = n_vec*n_vec*mu + l_vec*c_vec */
    secp256k1_weighted_scalar_inner_product(&v, n_vec, 0 /*a offset */, n_vec, 0 /*b offset*/, 1 /*step*/, n_vec_len, mu);
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

typedef struct ecmult_x_cb_data {
    const secp256k1_scalar *n;
    const secp256k1_ge *g;
    const secp256k1_scalar *l;
    const secp256k1_scalar *rho;
    const secp256k1_scalar *rho_inv;
    size_t G_GENS_LEN; /* Figure out initialization syntax so that this can also be const */
    size_t n_len;
} ecmult_x_cb_data;

static int ecmult_x_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_x_cb_data *data = (ecmult_x_cb_data*) cbdata;
    if (idx < data->n_len) {
        if (idx % 2 == 0) {
            secp256k1_scalar_mul(sc, &data->n[idx + 1], data->rho);
            *pt = data->g[idx];
        } else {
            secp256k1_scalar_mul(sc, &data->n[idx - 1], data->rho_inv);
            *pt = data->g[idx];
        }
    } else {
        idx -= data->n_len;
        if (idx % 2 == 0) {
            *sc = data->l[idx + 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        } else {
            *sc = data->l[idx - 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        }
    }
    return 1;
}

typedef struct ecmult_r_cb_data {
    const secp256k1_scalar *n1;
    const secp256k1_ge *g1;
    const secp256k1_scalar *l1;
    size_t G_GENS_LEN;
    size_t n_len;
} ecmult_r_cb_data;

static int ecmult_r_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_r_cb_data *data = (ecmult_r_cb_data*) cbdata;
    if (idx < data->n_len) {
        *sc = data->n1[2*idx + 1];
        *pt = data->g1[2*idx + 1];
    } else {
        idx -= data->n_len;
        *sc = data->l1[2*idx + 1];
        *pt = data->g1[data->G_GENS_LEN + 2*idx + 1];
    }
    return 1;
}

/* Describes how many folding rounds to execute and how many scalars remain in
 * the explicit tail at the end of the proof.
 */
typedef struct secp256k1_bppp_norm_layout {
    size_t rounds;
    size_t g_final_len;
    size_t h_final_len;
    size_t proof_len;
} secp256k1_bppp_norm_layout;

/* Choose between the original singleton-tail proof layout and the shorter
 * variable-tail layout.
 */
typedef enum secp256k1_bppp_norm_layout_policy {
    SECP256K1_BPPP_NORM_LAYOUT_OPTIMAL = 0,
    SECP256K1_BPPP_NORM_LAYOUT_LEGACY = 1
} secp256k1_bppp_norm_layout_policy;

/* The original BP++ implementation in this module always recursed down to a
 * single n scalar and a single l scalar, which fixes the trailer at 64 bytes.
 * This is kept as a separate layout for callers that want the old encoding.
 */
static secp256k1_bppp_norm_layout secp256k1_bppp_norm_layout_compute_legacy(size_t g_len, size_t h_len) {
    secp256k1_bppp_norm_layout ret;
    size_t g_rounds, h_rounds;

    VERIFY_CHECK(g_len > 0 && h_len > 0);
    VERIFY_CHECK(secp256k1_is_power_of_two(g_len));
    VERIFY_CHECK(secp256k1_is_power_of_two(h_len));

    g_rounds = secp256k1_bppp_log2_ceil(g_len);
    h_rounds = secp256k1_bppp_log2_ceil(h_len);
    ret.rounds = g_rounds > h_rounds ? g_rounds : h_rounds;
    ret.g_final_len = 1;
    ret.h_final_len = 1;
    ret.proof_len = 65 * ret.rounds + 64;
    return ret;
}

/* Compute the smallest proof layout under the "stop early and reveal the tail"
 * strategy. After k rounds, the proof has k serialized (X,R) pairs plus the
 * remaining n and l vectors.
 */
static secp256k1_bppp_norm_layout secp256k1_bppp_norm_layout_compute_optimal(size_t g_len, size_t h_len) {
    secp256k1_bppp_norm_layout ret;

    VERIFY_CHECK(g_len > 0 && h_len > 0);

    {
        size_t max_len = g_len > h_len ? g_len : h_len;
        size_t min_len = g_len > h_len ? h_len : g_len;
        size_t rounds_both_fit_3 = secp256k1_bppp_rounds_to_fit(max_len, 3);
        size_t rounds_max_fit_5 = secp256k1_bppp_rounds_to_fit(max_len, 5);
        size_t rounds_min_fit_3 = secp256k1_bppp_rounds_to_fit(min_len, 3);
        size_t rounds_min_fit_1 = secp256k1_bppp_log2_ceil(min_len);

        /* For short-tail proofs, after k rounds the proof size is
         * L(k) = 65*k + 32*(ceil(g/2^k) + ceil(h/2^k)).
         *
         * Another round is beneficial iff it removes at least 3 tail scalars,
         * i.e. floor(G/2) + floor(H/2) >= 3 for G = ceil(g/2^k), H = ceil(h/2^k).
         * Sorting so G >= H, the stopping region is exactly:
         *   1. G <= 3 and H <= 3, or
         *   2. H == 1 and G <= 5.
         *
         * The first stop region is reached once both lengths fit in 3, so
         * rounds_both_fit_3 is max(rounds_to_fit(max_len, 3),
         * rounds_to_fit(min_len, 3)).
         *
         * The second stop region is reached once the smaller side has shrunk to
         * 1 and the larger side fits in 5, so
         * max(rounds_to_fit(max_len, 5), log2_ceil(min_len)).
         *
         * The minimizing round count is the earlier of those two threshold
         * crossings. Once the fold enters either stop region, every further
         * round costs 65 bytes but can save at most 64 bytes of tail.
         */
        if (rounds_min_fit_3 > rounds_both_fit_3) {
            rounds_both_fit_3 = rounds_min_fit_3;
        }
        if (rounds_min_fit_1 > rounds_max_fit_5) {
            rounds_max_fit_5 = rounds_min_fit_1;
        }
        ret.rounds = rounds_both_fit_3 < rounds_max_fit_5 ? rounds_both_fit_3 : rounds_max_fit_5;
    }

    ret.g_final_len = secp256k1_bppp_ceil_div_pow2(g_len, ret.rounds);
    ret.h_final_len = secp256k1_bppp_ceil_div_pow2(h_len, ret.rounds);
    ret.proof_len = 65 * ret.rounds + 32 * (ret.g_final_len + ret.h_final_len);
    return ret;
}

/* Resolve the proof layout selected by the caller. Legacy layout is only
 * defined for power-of-two lengths while the optimal layout works for any
 * positive lengths.
 */
static int secp256k1_bppp_norm_layout_resolve(
    secp256k1_bppp_norm_layout *layout,
    size_t g_len,
    size_t h_len,
    secp256k1_bppp_norm_layout_policy layout_policy
) {
    VERIFY_CHECK(layout != NULL);
    VERIFY_CHECK(g_len > 0 && h_len > 0);

    if (layout_policy == SECP256K1_BPPP_NORM_LAYOUT_LEGACY) {
        if (!secp256k1_is_power_of_two(g_len) || !secp256k1_is_power_of_two(h_len)) {
            return 0;
        }
        *layout = secp256k1_bppp_norm_layout_compute_legacy(g_len, h_len);
        return 1;
    }

    if (layout_policy != SECP256K1_BPPP_NORM_LAYOUT_OPTIMAL) {
        return 0;
    }
    *layout = secp256k1_bppp_norm_layout_compute_optimal(g_len, h_len);
    return 1;
}

/* Recursively compute the norm argument proof satisfying the relation
 * <n_vec, n_vec>_mu + <c_vec, l_vec> = v for some commitment
 * C = v*G + <n_vec, G_vec> + <l_vec, H_vec>. <x, x>_mu is the weighted inner
 * product of x with itself, where the weights are the first n powers of mu.
 * <x, x>_mu = mu*x_1^2 + mu^2*x_2^2 + mu^3*x_3^2 + ... + mu^n*x_n^2.
 * The API computes mu as square of the r challenge (`r^2`).
 *
 * The norm argument is not zero knowledge and does not operate on any secret data.
 * Thus the following code uses variable time operations while computing the proof.
 * This function also modifies the values of n_vec, l_vec, c_vec and g_vec. The caller
 * is expected to copy these values if they need to be preserved.
 *
 * Assumptions: This function is intended to be used in conjunction with the
 * some parent protocol. To use this norm protocol in a standalone manner, the user
 * should add the commitment, generators and initial public data to the transcript hash.
*/
static int secp256k1_bppp_rangeproof_norm_product_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    unsigned char* proof,
    size_t *proof_len,
    secp256k1_sha256* transcript, /* Transcript hash of the parent protocol */
    secp256k1_bppp_norm_layout_policy layout_policy,
    const secp256k1_scalar* rho,
    secp256k1_ge* g_vec,
    size_t g_vec_len,
    secp256k1_scalar* n_vec,
    size_t n_vec_len,
    secp256k1_scalar* l_vec,
    size_t l_vec_len,
    secp256k1_scalar* c_vec,
    size_t c_vec_len
) {
    secp256k1_bppp_norm_layout layout;
    secp256k1_scalar mu_f, rho_f = *rho;
    size_t proof_idx = 0;
    size_t round = 0;
    ecmult_x_cb_data x_cb_data;
    ecmult_r_cb_data r_cb_data;
    size_t g_len = n_vec_len, h_len = l_vec_len;
    const size_t G_GENS_LEN = g_len;

    /* Layout selection is part of the proof format, so the caller chooses it
     * explicitly and the verifier must use the same policy.
     */
    if (!secp256k1_bppp_norm_layout_resolve(&layout, n_vec_len, c_vec_len, layout_policy)) {
        return 0;
    }

#ifdef VERIFY
    {
        VERIFY_CHECK(g_len > 0 && h_len > 0);
        VERIFY_CHECK(*proof_len >= layout.proof_len);
        VERIFY_CHECK(g_vec_len == (n_vec_len + l_vec_len) && l_vec_len == c_vec_len);
    }
#else
    (void)g_vec_len;
    (void)c_vec_len;
#endif

    x_cb_data.n = n_vec;
    x_cb_data.g = g_vec;
    x_cb_data.l = l_vec;
    x_cb_data.G_GENS_LEN = G_GENS_LEN;

    r_cb_data.n1 = n_vec;
    r_cb_data.g1 = g_vec;
    r_cb_data.l1 = l_vec;
    r_cb_data.G_GENS_LEN = G_GENS_LEN;
    secp256k1_scalar_sqr(&mu_f, &rho_f);


    for (round = 0; round < layout.rounds; round++) {
        int fold_g = g_len > 1;
        size_t i, num_points;
        size_t g_pairs = g_len / 2;
        size_t h_pairs = h_len / 2;
        secp256k1_scalar mu_sq, rho_inv, c0_l1, c1_l0, x_v, c1_l1, r_v;
        secp256k1_gej rj, xj;
        secp256k1_ge r_ge, x_ge;
        secp256k1_scalar gamma;

        secp256k1_scalar_inverse_var(&rho_inv, &rho_f);
        secp256k1_scalar_sqr(&mu_sq, &mu_f);

        /* Cross-terms only come from actual pairs. An unmatched last element is
         * carried to the next round as if paired with a zero scalar and the
         * point at infinity.
         */
        secp256k1_scalar_inner_product(&c0_l1, c_vec, 0, l_vec, 1, 2, h_pairs);
        secp256k1_scalar_inner_product(&c1_l0, c_vec, 1, l_vec, 0, 2, h_pairs);
        secp256k1_weighted_scalar_inner_product(&x_v, n_vec, 0, n_vec, 1, 2, g_pairs, &mu_sq);
        secp256k1_scalar_mul(&x_v, &x_v, &rho_inv);
        secp256k1_scalar_add(&x_v, &x_v, &x_v);
        secp256k1_scalar_add(&x_v, &x_v, &c0_l1);
        secp256k1_scalar_add(&x_v, &x_v, &c1_l0);

        x_cb_data.rho = &rho_f;
        x_cb_data.rho_inv = &rho_inv;
        x_cb_data.n_len = 2 * g_pairs;
        num_points = x_cb_data.n_len + 2 * h_pairs;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &xj, &x_v, ecmult_x_cb, (void*)&x_cb_data, num_points)) {
            return 0;
        }

        secp256k1_weighted_scalar_inner_product(&r_v, n_vec, 1, n_vec, 1, 2, g_pairs, &mu_sq);
        secp256k1_scalar_inner_product(&c1_l1, c_vec, 1, l_vec, 1, 2, h_pairs);
        secp256k1_scalar_add(&r_v, &r_v, &c1_l1);

        r_cb_data.n_len = g_pairs;
        num_points = r_cb_data.n_len + h_pairs;
        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &r_v, ecmult_r_cb, (void*)&r_cb_data, num_points)) {
            return 0;
        }

        secp256k1_ge_set_gej_var(&x_ge, &xj);
        secp256k1_ge_set_gej_var(&r_ge, &rj);
        secp256k1_bppp_serialize_points(&proof[proof_idx], &x_ge, &r_ge);
        proof_idx += 65;

        /* Obtain challenge gamma for the the next round */
        secp256k1_sha256_write(transcript, &proof[proof_idx - 65], 65);
        secp256k1_bppp_challenge_scalar(&gamma, transcript, 0);

        if (g_len > 1) {
            for (i = 0; i + 1 < g_len; i = i + 2) {
                secp256k1_scalar nl, nr;
                secp256k1_gej gl, gr;
                secp256k1_scalar_mul(&nl, &n_vec[i], &rho_inv);
                secp256k1_scalar_mul(&nr, &n_vec[i + 1], &gamma);
                secp256k1_scalar_add(&n_vec[i/2], &nl, &nr);

                secp256k1_gej_set_ge(&gl, &g_vec[i]);
                secp256k1_ecmult(&gl, &gl, &rho_f, NULL);
                secp256k1_gej_set_ge(&gr, &g_vec[i + 1]);
                secp256k1_ecmult(&gr, &gr, &gamma, NULL);
                secp256k1_gej_add_var(&gl, &gl, &gr, NULL);
                secp256k1_ge_set_gej_var(&g_vec[i/2], &gl);
            }
            if ((g_len & 1) != 0) {
                secp256k1_gej gl;
                /* The unmatched G-side term survives unchanged except for the
                 * rho-weighting that every left half receives in this round.
                 */
                secp256k1_scalar_mul(&n_vec[g_pairs], &n_vec[g_len - 1], &rho_inv);
                secp256k1_gej_set_ge(&gl, &g_vec[g_len - 1]);
                secp256k1_ecmult(&gl, &gl, &rho_f, NULL);
                secp256k1_ge_set_gej_var(&g_vec[g_pairs], &gl);
            }
        }

        if (h_len > 1) {
            for (i = 0; i + 1 < h_len; i = i + 2) {
                secp256k1_scalar temp1;
                secp256k1_gej grj;
                secp256k1_scalar_mul(&temp1, &c_vec[i + 1], &gamma);
                secp256k1_scalar_add(&c_vec[i/2], &c_vec[i], &temp1);

                secp256k1_scalar_mul(&temp1, &l_vec[i + 1], &gamma);
                secp256k1_scalar_add(&l_vec[i/2], &l_vec[i], &temp1);

                secp256k1_gej_set_ge(&grj, &g_vec[G_GENS_LEN + i + 1]);
                secp256k1_ecmult(&grj, &grj, &gamma, NULL);
                secp256k1_gej_add_ge_var(&grj, &grj, &g_vec[G_GENS_LEN + i], NULL);
                secp256k1_ge_set_gej_var(&g_vec[G_GENS_LEN + i/2], &grj);
            }
            if ((h_len & 1) != 0) {
                /* The unmatched H-side term has no partner, so it is copied
                 * through to the next round unchanged.
                 */
                c_vec[h_pairs] = c_vec[h_len - 1];
                l_vec[h_pairs] = l_vec[h_len - 1];
                g_vec[G_GENS_LEN + h_pairs] = g_vec[G_GENS_LEN + h_len - 1];
            }
        }
        g_len = (g_len + 1) / 2;
        h_len = (h_len + 1) / 2;
        if (fold_g) {
            /* mu_f only changes in rounds that actually fold the weighted norm
             * relation. Once the G-side has length 1, later H-only folds leave
             * the norm parameter unchanged.
             */
            rho_f = mu_f;
            mu_f = mu_sq;
        }
    }

    VERIFY_CHECK(g_len == layout.g_final_len);
    VERIFY_CHECK(h_len == layout.h_final_len);

    {
        size_t i;
        /* The proof ends with the remaining n tail followed by the remaining l
         * tail. In the legacy layout these lengths are both 1.
         */
        for (i = 0; i < g_len; i++) {
            secp256k1_scalar_get_b32(&proof[proof_idx], &n_vec[i]);
            proof_idx += 32;
        }
        for (i = 0; i < h_len; i++) {
            secp256k1_scalar_get_b32(&proof[proof_idx], &l_vec[i]);
            proof_idx += 32;
        }
    }
    VERIFY_CHECK(proof_idx == layout.proof_len);
    *proof_len = proof_idx;
    return 1;
}

typedef struct ec_mult_verify_cb_data1 {
    const unsigned char *proof;
    const secp256k1_ge *commit;
    const secp256k1_scalar *gammas;
} ec_mult_verify_cb_data1;

static int ec_mult_verify_cb1(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ec_mult_verify_cb_data1 *data = (ec_mult_verify_cb_data1*) cbdata;
    if (idx == 0) {
        *pt = *data->commit;
        secp256k1_scalar_set_int(sc, 1);
        return 1;
    }
    idx -= 1;
    if (idx % 2 == 0) {
        idx /= 2;
        *sc = data->gammas[idx];
        if (!secp256k1_bppp_parse_one_of_points(pt, &data->proof[65*idx], 0)) {
            return 0;
        }
    } else {
        secp256k1_scalar neg_one;
        idx /= 2;
        secp256k1_scalar_set_int(&neg_one, 1);
        secp256k1_scalar_negate(&neg_one, &neg_one);
        *sc = data->gammas[idx];
        secp256k1_scalar_sqr(sc, sc);
        secp256k1_scalar_add(sc, sc, &neg_one);
        if (!secp256k1_bppp_parse_one_of_points(pt, &data->proof[65*idx], 1)) {
            return 0;
        }
    }
    return 1;
}

typedef struct ec_mult_verify_cb_data2 {
    const secp256k1_scalar *s_g;
    const secp256k1_scalar *s_h;
    const secp256k1_ge *g_vec;
    size_t g_vec_len;
} ec_mult_verify_cb_data2;

static int ec_mult_verify_cb2(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ec_mult_verify_cb_data2 *data = (ec_mult_verify_cb_data2*) cbdata;
    if (idx < data->g_vec_len) {
        *sc = data->s_g[idx];
    } else {
        *sc = data->s_h[idx - data->g_vec_len];
    }
    *pt = data->g_vec[idx];
    return 1;
}

/* Verify a legacy singleton-tail proof. This follows the original verifier
 * strategy, which derives the final multiexponent coefficients directly from
 * the proof challenges.
 */
static int secp256k1_bppp_rangeproof_norm_product_verify_legacy(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char* proof,
    size_t proof_len,
    secp256k1_sha256* transcript,
    const secp256k1_scalar* rho,
    const secp256k1_bppp_generators* g_vec,
    size_t g_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_ge* commit
) {
    secp256k1_bppp_norm_layout layout;
    secp256k1_scalar rho_f, mu_f, v, n, l, rho_inv, h_c;
    secp256k1_scalar *gammas, *s_g, *s_h, *rho_inv_pows;
    secp256k1_gej res1, res2;
    size_t i = 0, scratch_checkpoint;
    int overflow;
    size_t log_g_len, n_rounds;
    size_t h_len = c_vec_len;

    if (g_len == 0 || c_vec_len == 0) {
        return 0;
    }
    if (secp256k1_scalar_is_zero(rho)) {
        return 0;
    }
    if (!secp256k1_bppp_norm_layout_resolve(&layout, g_len, c_vec_len, SECP256K1_BPPP_NORM_LAYOUT_LEGACY)) {
        return 0;
    }

    log_g_len = secp256k1_bppp_log2(g_len);
    n_rounds = layout.rounds;

    if (g_vec->n != (h_len + g_len) || proof_len != layout.proof_len) {
        return 0;
    }

    secp256k1_scalar_set_b32(&n, &proof[n_rounds*65], &overflow); /* n */
    if (overflow) return 0;
    secp256k1_scalar_set_b32(&l, &proof[n_rounds*65 + 32], &overflow); /* l */
    if (overflow) return 0;

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    gammas = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, n_rounds * sizeof(secp256k1_scalar));
    s_g = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_len * sizeof(secp256k1_scalar));
    s_h = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));
    rho_inv_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, log_g_len * sizeof(secp256k1_scalar));
    if (gammas == NULL || s_g == NULL || s_h == NULL || rho_inv_pows == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* Compute powers of rho_inv. Later used in g_factor computations. */
    secp256k1_scalar_inverse_var(&rho_inv, rho);
    secp256k1_bppp_powers_of_rho(rho_inv_pows, &rho_inv, log_g_len);

    /* Compute rho_f = rho^(2^log_g_len). */
    rho_f = *rho;
    for (i = 0; i < log_g_len; i++) {
        secp256k1_scalar_sqr(&rho_f, &rho_f);
    }

    for (i = 0; i < n_rounds; i++) {
        secp256k1_scalar gamma;
        secp256k1_sha256_write(transcript, &proof[i * 65], 65);
        secp256k1_bppp_challenge_scalar(&gamma, transcript, 0);
        gammas[i] = gamma;
    }
    /* s_g[0] = n * \prod_{j=0}^{log_g_len - 1} rho^(2^j)
     *        = n * rho^(2^log_g_len - 1)
     *        = n * rho_f * rho_inv
     */
    secp256k1_scalar_mul(&s_g[0], &n, &rho_f);
    secp256k1_scalar_mul(&s_g[0], &s_g[0], &rho_inv);
    for (i = 1; i < g_len; i++) {
        size_t log_i = secp256k1_bppp_log2(i);
        size_t nearest_pow_of_two = (size_t)1 << log_i;
        /* This combines the two multiplications of gammas and rho_invs in a
         * single loop.
         * s_g[i] = s_g[i - nearest_pow_of_two]
         *            * e[log_i] * rho_inv^(2^log_i)
         */
        secp256k1_scalar_mul(&s_g[i], &s_g[i - nearest_pow_of_two], &gammas[log_i]);
        secp256k1_scalar_mul(&s_g[i], &s_g[i], &rho_inv_pows[log_i]);
    }
    s_h[0] = l;
    secp256k1_scalar_set_int(&h_c, 0);
    for (i = 1; i < h_len; i++) {
        size_t log_i = secp256k1_bppp_log2(i);
        size_t nearest_pow_of_two = (size_t)1 << log_i;
        secp256k1_scalar_mul(&s_h[i], &s_h[i - nearest_pow_of_two], &gammas[log_i]);
    }
    secp256k1_scalar_inner_product(&h_c, c_vec, 0 /* a_offset */, s_h, 0 /* b_offset */, 1 /* step */, h_len);
    /* Compute v = n*n*mu_f + l*h_c where mu_f = rho_f^2. */
    secp256k1_scalar_sqr(&mu_f, &rho_f);
    secp256k1_scalar_mul(&v, &n, &n);
    secp256k1_scalar_mul(&v, &v, &mu_f);
    secp256k1_scalar_add(&v, &v, &h_c);

    {
        ec_mult_verify_cb_data1 data;
        data.proof = proof;
        data.commit = commit;
        data.gammas = gammas;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &res1, NULL, ec_mult_verify_cb1, &data, 2*n_rounds + 1)) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
    }
    {
        ec_mult_verify_cb_data2 data;
        data.g_vec = g_vec->gens;
        data.g_vec_len = g_len;
        data.s_g = s_g;
        data.s_h = s_h;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &res2, &v, ec_mult_verify_cb2, &data, g_len + h_len)) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
    }

    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);

    return secp256k1_gej_eq_var(&res1, &res2);
}

/* Verify an optimal variable-tail proof by replaying the public folds and then
 * checking the final explicit tail commitment.
 */
static int secp256k1_bppp_rangeproof_norm_product_verify_optimal(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char* proof,
    size_t proof_len,
    secp256k1_sha256* transcript,
    const secp256k1_scalar* rho,
    secp256k1_bppp_generators* g_vec,
    size_t g_len,
    secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_ge* commit
) {
    secp256k1_bppp_norm_layout layout;
    secp256k1_scalar rho_f, mu_f;
    secp256k1_scalar *n_vec, *l_vec;
    secp256k1_ge expected_commit, x_ge, r_ge;
    secp256k1_gej commitj, tmpj, expected_commitj;
    size_t i, round, proof_idx = 0, scratch_checkpoint;
    int overflow;
    size_t h_len = c_vec_len;
    size_t g_work_len = g_len, h_work_len = c_vec_len;
    const size_t G_GENS_LEN = g_len;
    secp256k1_bppp_generators final_gens;

    if (g_len == 0 || c_vec_len == 0) {
        return 0;
    }
    if (secp256k1_scalar_is_zero(rho)) {
        return 0;
    }
    layout = secp256k1_bppp_norm_layout_compute_optimal(g_len, c_vec_len);

    if (g_vec->n != (h_len + g_len) || proof_len != layout.proof_len) {
        return 0;
    }

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    n_vec = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, layout.g_final_len * sizeof(secp256k1_scalar));
    l_vec = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, layout.h_final_len * sizeof(secp256k1_scalar));
    if (n_vec == NULL || l_vec == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* Accumulate the verifier-side commitment updates round by round and then
     * compare against a direct commitment to the final folded tail.
     */
    secp256k1_gej_set_ge(&commitj, commit);
    rho_f = *rho;
    secp256k1_scalar_sqr(&mu_f, &rho_f);

    for (round = 0; round < layout.rounds; round++) {
        int fold_g = g_work_len > 1;
        size_t g_pairs = g_work_len / 2;
        size_t h_pairs = h_work_len / 2;
        secp256k1_scalar gamma, gamma_sq_minus_one, mu_sq;

        if (!secp256k1_bppp_parse_one_of_points(&x_ge, &proof[proof_idx], 0) ||
            !secp256k1_bppp_parse_one_of_points(&r_ge, &proof[proof_idx], 1)) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
        secp256k1_sha256_write(transcript, &proof[proof_idx], 65);
        secp256k1_bppp_challenge_scalar(&gamma, transcript, 0);
        proof_idx += 65;

        secp256k1_gej_set_ge(&tmpj, &x_ge);
        secp256k1_ecmult(&tmpj, &tmpj, &gamma, NULL);
        secp256k1_gej_add_var(&commitj, &commitj, &tmpj, NULL);

        secp256k1_scalar_sqr(&gamma_sq_minus_one, &gamma);
        {
            secp256k1_scalar minus_one;
            secp256k1_scalar_set_int(&minus_one, 1);
            secp256k1_scalar_negate(&minus_one, &minus_one);
            secp256k1_scalar_add(&gamma_sq_minus_one, &gamma_sq_minus_one, &minus_one);
        }
        secp256k1_gej_set_ge(&tmpj, &r_ge);
        secp256k1_ecmult(&tmpj, &tmpj, &gamma_sq_minus_one, NULL);
        secp256k1_gej_add_var(&commitj, &commitj, &tmpj, NULL);

        if (g_work_len > 1) {
            for (i = 0; i + 1 < g_work_len; i = i + 2) {
                secp256k1_gej gl, gr;
                secp256k1_gej_set_ge(&gl, &g_vec->gens[i]);
                secp256k1_ecmult(&gl, &gl, &rho_f, NULL);
                secp256k1_gej_set_ge(&gr, &g_vec->gens[i + 1]);
                secp256k1_ecmult(&gr, &gr, &gamma, NULL);
                secp256k1_gej_add_var(&gl, &gl, &gr, NULL);
                secp256k1_ge_set_gej_var(&g_vec->gens[i/2], &gl);
            }
            if ((g_work_len & 1) != 0) {
                secp256k1_gej gl;
                /* Unmatched G-side generators survive as the left term of the
                 * fold, exactly mirroring the prover.
                 */
                secp256k1_gej_set_ge(&gl, &g_vec->gens[g_work_len - 1]);
                secp256k1_ecmult(&gl, &gl, &rho_f, NULL);
                secp256k1_ge_set_gej_var(&g_vec->gens[g_pairs], &gl);
            }
        }
        if (h_work_len > 1) {
            for (i = 0; i + 1 < h_work_len; i = i + 2) {
                secp256k1_scalar temp1;
                secp256k1_gej grj;
                secp256k1_scalar_mul(&temp1, &c_vec[i + 1], &gamma);
                secp256k1_scalar_add(&c_vec[i/2], &c_vec[i], &temp1);

                secp256k1_gej_set_ge(&grj, &g_vec->gens[G_GENS_LEN + i + 1]);
                secp256k1_ecmult(&grj, &grj, &gamma, NULL);
                secp256k1_gej_add_ge_var(&grj, &grj, &g_vec->gens[G_GENS_LEN + i], NULL);
                secp256k1_ge_set_gej_var(&g_vec->gens[G_GENS_LEN + i/2], &grj);
            }
            if ((h_work_len & 1) != 0) {
                /* Unmatched H-side terms are copied through unchanged. */
                c_vec[h_pairs] = c_vec[h_work_len - 1];
                g_vec->gens[G_GENS_LEN + h_pairs] = g_vec->gens[G_GENS_LEN + h_work_len - 1];
            }
        }

        g_work_len = (g_work_len + 1) / 2;
        h_work_len = (h_work_len + 1) / 2;
        if (fold_g) {
            /* mu_f tracks the weighted norm parameter for the current G-side
             * length. Once the G-side reaches length 1, H-only folds leave it
             * unchanged.
             */
            rho_f = mu_f;
            secp256k1_scalar_sqr(&mu_sq, &mu_f);
            mu_f = mu_sq;
        }
    }

    if (g_work_len != layout.g_final_len || h_work_len != layout.h_final_len) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    for (i = 0; i < layout.g_final_len; i++) {
        secp256k1_scalar_set_b32(&n_vec[i], &proof[proof_idx], &overflow);
        if (overflow) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
        proof_idx += 32;
    }
    for (i = 0; i < layout.h_final_len; i++) {
        secp256k1_scalar_set_b32(&l_vec[i], &proof[proof_idx], &overflow);
        if (overflow) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
        proof_idx += 32;
    }
    if (proof_idx != proof_len) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* secp256k1_bppp_commit expects all remaining G generators followed by all
     * remaining H generators in one contiguous array. Pack the final H tail down
     * into the same caller-owned array.
     */
    memmove(&g_vec->gens[layout.g_final_len], &g_vec->gens[G_GENS_LEN], layout.h_final_len * sizeof(secp256k1_ge));
    final_gens.n = layout.g_final_len + layout.h_final_len;
    final_gens.gens = g_vec->gens;
    if (!secp256k1_bppp_commit(ctx, scratch, &expected_commit, &final_gens, n_vec, layout.g_final_len, l_vec, layout.h_final_len, c_vec, layout.h_final_len, &mu_f)) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    secp256k1_gej_set_ge(&expected_commitj, &expected_commit);

    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);

    return secp256k1_gej_eq_var(&commitj, &expected_commitj);
}

/* Verify the proof. The optimal path folds the supplied generators and c_vec in
 * place while the legacy path only reads them.
 */
static int secp256k1_bppp_rangeproof_norm_product_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char* proof,
    size_t proof_len,
    secp256k1_sha256* transcript,
    secp256k1_bppp_norm_layout_policy layout_policy,
    const secp256k1_scalar* rho,
    secp256k1_bppp_generators* g_vec,
    size_t g_len,
    secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_ge* commit
) {
    if (layout_policy == SECP256K1_BPPP_NORM_LAYOUT_LEGACY) {
        return secp256k1_bppp_rangeproof_norm_product_verify_legacy(ctx, scratch, proof, proof_len, transcript, rho, g_vec, g_len, c_vec, c_vec_len, commit);
    }
    if (layout_policy == SECP256K1_BPPP_NORM_LAYOUT_OPTIMAL) {
        return secp256k1_bppp_rangeproof_norm_product_verify_optimal(ctx, scratch, proof, proof_len, transcript, rho, g_vec, g_len, c_vec, c_vec_len, commit);
    }
    return 0;
}
#endif
