/**********************************************************************
 * Copyright (c) 2022 Sanket Kanjalkar                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_
#define SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_


#include "group.h"
#include "scalar.h"
#include "secp256k1.h"
#include "ecmult_const.h"
#include "field.h"
#include "include/secp256k1_bppp.h"

#include "modules/bppp/bppp_util.h"
#include "modules/bppp/bppp_transcript_impl.h"
#include "modules/bppp/bppp_norm_product_impl.h"

struct secp256k1_bppp_rangeproof_prover_context {

    /* Components committed along G_vec
        d = digits(array of size num_digits)
        m = multiplicities of digits (array of size base)
        r = reciprocals of each digit (array of size num_digits)
        s = random blinding factors (array of size G_vec_len = max(num_digits, base))
    */
    secp256k1_scalar *d, *m, *r, *s;
    /* The blinding value associated with b_i along G */
    secp256k1_scalar r_d_0, r_m_0, r_r_0, r_s_0;
    /* The blinding values associated with m/s along H_vec(array of size 6) */
    secp256k1_scalar *r_m_1_vec, *r_s_1_vec;
    /* Blinding values for r_d[2] and r_d[5] */
    secp256k1_scalar r_d_1_vec_2, r_d_1_vec_5;
    /* The challenges during prover computation
       x here is actually separating the linear constraints, but we don't use lambda here
       as we will use lambda later for aggregation. */
    secp256k1_scalar alpha, mu, x, beta, t, rho, delta;
    /* Pre-computed powers of mu len = max(num_digits, base) */
    secp256k1_scalar *mu_pows, *mu_inv_pows;
    /* The cached values of c_m = x/(alpha+i)*mu^(-i-1) */
    secp256k1_scalar *c_m;
};

/* Compute the powers of mu as mu, mu^2, mu^3, ... */
static void secp256k1_bppp_rangeproof_powers_of_mu(secp256k1_scalar *mu_pows, const secp256k1_scalar *mu, size_t len) {
    size_t i;
    mu_pows[0] = *mu;
    for (i = 1; i < len; i++) {
        secp256k1_scalar_mul(&mu_pows[i], &mu_pows[i - 1], mu);
    }
}

/* Round 1 of the proof. Computes the digits and multiplicities of the values.
 * Uses the value but not the blinding factor. Takes the complete commitment,
 * but only to put it into the hash.
 * Outputs points M and D serialized as 33-byte compressed points.
 * Always succeeds.
 */
static void secp256k1_bppp_rangeproof_prove_round1_impl(
    secp256k1_bppp_rangeproof_prover_context* prover_ctx,
    const secp256k1_bppp_generators* gens,
    const secp256k1_ge* asset_genp,
    unsigned char* output,
    secp256k1_sha256* transcript,
    const size_t num_digits,
    const size_t digit_base,
    uint64_t value,
    const unsigned char* nonce
) {
    size_t log_base = secp256k1_bppp_log2(digit_base);
    size_t i, j;
    size_t log_num_digits = secp256k1_bppp_log2(num_digits);
    size_t g_offset = digit_base > num_digits ? digit_base : num_digits;
    secp256k1_gej d_commj, m_commj;
    uint16_t multiplicities[64]; /* SECP256K1_BPP_MAX_BASE = 64. TODO: Check this in high level API */
    /* Obtain random values for r_m_1_vec. Note the values for indices at 3, 6, 7 should be zero.*/
    secp256k1_scalar_chacha20(&prover_ctx->r_m_1_vec[0], &prover_ctx->r_m_1_vec[1], nonce, 0);
    secp256k1_scalar_chacha20(&prover_ctx->r_m_1_vec[2], &prover_ctx->r_m_1_vec[4], nonce, 1);
    secp256k1_scalar_chacha20(&prover_ctx->r_m_1_vec[5], &prover_ctx->r_m_1_vec[5], nonce, 2);
    /* r_d1_vec needs values at indices of 2 and 5. */
    secp256k1_scalar_chacha20(&prover_ctx->r_d_1_vec_2, &prover_ctx->r_d_1_vec_5, nonce, 3);
    secp256k1_scalar_clear(&prover_ctx->r_m_1_vec[7]);
    /* Obtain the values for r_m_0 and r_d_0 */
    secp256k1_scalar_chacha20(&prover_ctx->r_m_0, &prover_ctx->r_d_0, nonce, 4);

    for (i = 0; i < digit_base; i++) {
        multiplicities[i] = 0;
    }

    /* Commit to the vector d in gens */
    secp256k1_ecmult_const(&d_commj, asset_genp, &prover_ctx->r_d_0, 256);

    for (i = 0; i < num_digits; i++) {
        secp256k1_gej resj;
        secp256k1_ge d_comm;
        unsigned int digit = value & (digit_base - 1);
        value = value >> log_base;
        /* Constant time way to hide conditional access to multiplicities[digit] */
        for (j = 0; j < digit_base; j++) {
            multiplicities[j] += (j == digit);
        }
        secp256k1_scalar_set_int(&prover_ctx->d[i], digit);
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->d[i], log_base + 1); /* (I think ) there should there be +1 here? */
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm); /* d_comm cannot be zero */
    }

    /* Additional t**7 and t**3 term which cannot be cancelled out:
       delta*lm_v[0, 6] + ld_v[0, 5] + lr_v[0, 4] => lm_v[6] = 0 && ld_v[5] = -lr_v[4].
       t^3 term:  delta*lm_v[0, 3] + ld_v[0, 2] + lr_v[0, 1] => lm_v[3] = 0 && ld_v[2] = -lr_v[1] */
    /* There are multiple choices for these values, we choose the simplest one
       where all other blinding values along H for r, d are zero. */
    {
        secp256k1_gej resj;
        secp256k1_ge d_comm;

        secp256k1_scalar_clear(&prover_ctx->r_m_1_vec[3]); /* r_m_1_vec[3] = 0 */
        secp256k1_scalar_clear(&prover_ctx->r_m_1_vec[6]); /* r_m_1_vec[6] = 0 */
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 2], &prover_ctx->r_d_1_vec_2, 256);
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 5], &prover_ctx->r_d_1_vec_5, 256);
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
    }

    /* Compute the m vector as multiplicity of each digit */
    secp256k1_ecmult_const(&m_commj, asset_genp, &prover_ctx->r_m_0, 256);
    for (i = 0; i < digit_base; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_scalar_set_int(&prover_ctx->m[i], multiplicities[i]);
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->m[i], log_num_digits + 1); /* (I think ) there should there be +1 here? */
        secp256k1_ge_set_gej(&m_comm, &m_commj);
        secp256k1_gej_add_ge(&m_commj, &resj, &m_comm); /* m_comm cannot be zero*/
    }

    for (i = 0; i < 8; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + i], &prover_ctx->r_m_1_vec[i], 256);
        secp256k1_ge_set_gej(&m_comm, &m_commj);
        secp256k1_gej_add_ge(&m_commj, &resj, &m_comm); /* m_comm cannot be zero */
    }

    {
        secp256k1_ge m_comm, d_comm;
        /* r_m_1_vec are sampled randomly and two components of l_d are sampled randomly.
         * Improbable to be zero commitment. Safe to serialize. */
        VERIFY_CHECK(!secp256k1_gej_is_infinity(&m_commj));
        VERIFY_CHECK(!secp256k1_gej_is_infinity(&d_commj));

        secp256k1_ge_set_gej_var(&m_comm, &m_commj);
        secp256k1_ge_set_gej_var(&d_comm, &d_commj);
        secp256k1_fe_normalize_var(&m_comm.x);
        secp256k1_fe_normalize_var(&m_comm.y);
        secp256k1_fe_normalize_var(&d_comm.x);
        secp256k1_fe_normalize_var(&d_comm.y);
        secp256k1_bppp_serialize_pt(&output[0], &m_comm);
        secp256k1_bppp_serialize_pt(&output[33], &d_comm);

        secp256k1_sha256_write(transcript, output, 66);
        secp256k1_bppp_challenge_scalar(&prover_ctx->alpha, transcript, 0);
    }
}


/* Round 2 of the proof. Computes the reciprocals of the digits.
 * Serialized as 33 byte compressed point.
 * Always succeeds.
 */
static void secp256k1_bppp_rangeproof_prove_round2_impl(
    secp256k1_bppp_rangeproof_prover_context* prover_ctx,
    const secp256k1_bppp_generators* gens,
    const secp256k1_ge* asset_genp,
    unsigned char* output,
    secp256k1_sha256* transcript,
    const size_t num_digits,
    const size_t digit_base,
    const unsigned char* nonce
) {
    size_t i;
    size_t g_offset = digit_base > num_digits ? digit_base : num_digits;
    secp256k1_gej r_commj;
    secp256k1_scalar mu_inv;

    /* We need only one value in this round, ignore the second value. */
    secp256k1_scalar_chacha20(&prover_ctx->r_r_0, &prover_ctx->r_r_0, nonce, 5);

    /* Commit to the vector d in gens */
    secp256k1_ecmult_const(&r_commj, asset_genp, &prover_ctx->r_r_0, 256);
    for (i = 0; i < num_digits; i++) {
        secp256k1_gej resj;
        secp256k1_ge r_comm;
        secp256k1_scalar_add(&prover_ctx->r[i], &prover_ctx->d[i], &prover_ctx->alpha);
        secp256k1_scalar_inverse(&prover_ctx->r[i], &prover_ctx->r[i]); /* r_i cannot be zero as it added by random value `alpha`*/
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->r[i], 256);
        secp256k1_ge_set_gej(&r_comm, &r_commj);
        secp256k1_gej_add_ge(&r_commj, &resj, &r_comm); /* r_comm cannot be zero */
    }

    /* Additional t**7 term which cannot be cancelled out:
       delta*lm_v[0, 6] + ld_v[0, 5] + lr_v[0, 4] => lm_v[6] = 0 && ld_v[5] = -lr_v[4].
       t^3 term:  delta*lm_v[0, 3] + ld_v[0, 2] + lr_v[0, 1] => lm_v[3] = 0 && ld_v[2] = -lr_v[1] */
    {
        secp256k1_gej resj;
        secp256k1_ge r_comm;
        secp256k1_scalar tmp;

        secp256k1_scalar_negate(&tmp, &prover_ctx->r_d_1_vec_2);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 1], &tmp, 256);
        secp256k1_ge_set_gej(&r_comm, &r_commj);
        secp256k1_gej_add_ge(&r_commj, &resj, &r_comm);

        secp256k1_scalar_negate(&tmp, &prover_ctx->r_d_1_vec_5);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 4], &tmp, 256);
        secp256k1_ge_set_gej(&r_comm, &r_commj);
        secp256k1_gej_add_ge(&r_commj, &resj, &r_comm);
    }

    {
        secp256k1_ge r_comm;
        /* All r values are non-zero(computed by inverse), rcommj must be non-zero */
        VERIFY_CHECK(secp256k1_gej_is_infinity(&r_commj) == 0);
        secp256k1_ge_set_gej_var(&r_comm, &r_commj);
        secp256k1_fe_normalize_var(&r_comm.x);
        secp256k1_fe_normalize_var(&r_comm.y);
        secp256k1_bppp_serialize_pt(&output[0], &r_comm);

        secp256k1_sha256_write(transcript, output, 33);
        secp256k1_bppp_challenge_scalar(&prover_ctx->rho, transcript, 0);
        secp256k1_bppp_challenge_scalar(&prover_ctx->x, transcript, 1);
        secp256k1_bppp_challenge_scalar(&prover_ctx->beta, transcript, 2);
        secp256k1_bppp_challenge_scalar(&prover_ctx->delta, transcript, 3);
        secp256k1_scalar_sqr(&prover_ctx->mu, &prover_ctx->rho);
    }
    /* Pre-compute powers of mu and mu_inv. We will need them in future rounds. */
    secp256k1_bppp_rangeproof_powers_of_mu(prover_ctx->mu_pows, &prover_ctx->mu, g_offset);
    secp256k1_scalar_inverse_var(&mu_inv, &prover_ctx->mu); /* mu cannot be zero */
    secp256k1_bppp_rangeproof_powers_of_mu(prover_ctx->mu_inv_pows, &mu_inv, g_offset);
    /* Compute the values of c_m = (x/(alpha+i)*mu_inv[i]) */
    for (i = 0; i < digit_base; i++) {
        secp256k1_scalar_set_int(&prover_ctx->c_m[i], i); /* digit base is less than 2^32, can directly set*/
        secp256k1_scalar_add(&prover_ctx->c_m[i], &prover_ctx->c_m[i], &prover_ctx->alpha);
        secp256k1_scalar_inverse_var(&prover_ctx->c_m[i], &prover_ctx->c_m[i]);
        secp256k1_scalar_mul(&prover_ctx->c_m[i], &prover_ctx->c_m[i], &prover_ctx->x);
        secp256k1_scalar_mul(&prover_ctx->c_m[i], &prover_ctx->c_m[i], &prover_ctx->mu_inv_pows[i]);
    }
}

#endif
