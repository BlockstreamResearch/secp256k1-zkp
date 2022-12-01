/**********************************************************************
 * Copyright (c) 2022 Sanket Kanjalkar                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_
#define _SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_


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
    secp256k1_scalar b_d, b_m, b_r, b_s;
    /* The blinding values associated with m/s along H_vec(array of size 6) */
    secp256k1_scalar *l_m, *l_s;
    /* The challenges during prover computation */
    secp256k1_scalar e, q, x, y, t, q_sqrt;
    /* Pre-computed powers of q len = max(num_digits, base) */
    secp256k1_scalar *q_pows, *q_inv_pows;
    /* The cached values of alpha_m = x/(e+i)*q^(-i-1) */
    secp256k1_scalar *alpha_m;
};

/* Compute the powers of q as q, q^2, q^3, ... */
static void secp256k1_bppp_rangeproof_powers_of_q(secp256k1_scalar *q_pow, const secp256k1_scalar *q, size_t len) {
    size_t i;
    q_pow[0] = *q;
    for (i = 1; i < len; i++) {
        secp256k1_scalar_mul(&q_pow[i], &q_pow[i - 1], q);
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
    uint16_t multiplicities[64]; /* SECP256K1_BPP_MAX_BASE = 64 */
    secp256k1_scalar neg_ld_i;
    /* Obtain random values for l_m */
    secp256k1_scalar_chacha20(&prover_ctx->l_m[0], &prover_ctx->l_m[1], nonce, 0);
    secp256k1_scalar_chacha20(&prover_ctx->l_m[2], &prover_ctx->l_m[3], nonce, 1);
    secp256k1_scalar_chacha20(&prover_ctx->l_m[4], &prover_ctx->l_m[5], nonce, 2);
    /* Obtain the values for b_m and b_d */
    secp256k1_scalar_chacha20(&prover_ctx->b_m, &prover_ctx->b_d, nonce, 3);

    for (i = 0; i < digit_base; i++) {
        multiplicities[i] = 0;
    }

    /* Commit to the vector d in gens */
    secp256k1_ecmult_const(&d_commj, asset_genp, &prover_ctx->b_d, 256);

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

    /* The blinding vector for d is (0, 0, -l_m3, 0, -l_m5, 0, 0, 0).
       This is required to cancel out some co-effs final polynomials in T that cannot
       be adaptively set by l_s blinding factor. */
    /* There are multiple choices for these values, we choose the simplest one
       where all other blinding values along H for r, d are zero. */
    {
        secp256k1_gej resj;
        secp256k1_ge d_comm;
        secp256k1_scalar_negate(&neg_ld_i, &prover_ctx->l_m[3]);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 2], &neg_ld_i, 256); /* l_d[2] = - l_m[3] */
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
        secp256k1_scalar_negate(&neg_ld_i, &prover_ctx->l_m[5]);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 4], &neg_ld_i, 256); /* l_d[4] = - l_m[5] */
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
    }

    /* Compute the m vector as multiplicity of each digit */
    secp256k1_ecmult_const(&m_commj, asset_genp, &prover_ctx->b_m, 256);
    for (i = 0; i < digit_base; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_scalar_set_int(&prover_ctx->m[i], multiplicities[i]);
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->m[i], log_num_digits + 1); /* (I think ) there should there be +1 here? */
        secp256k1_ge_set_gej(&m_comm, &m_commj);
        secp256k1_gej_add_ge(&m_commj, &resj, &m_comm); /* m_comm cannot be zero*/
    }

    for (i = 0; i < 6; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + i], &prover_ctx->l_m[i], 256);
        secp256k1_ge_set_gej(&m_comm, &m_commj);
        secp256k1_gej_add_ge(&m_commj, &resj, &m_comm); /* m_comm cannot be zero */
    }

    {
        secp256k1_ge m_comm, d_comm;
        /* l_m are sampled randomly and two components of l_d are sampled randomly.
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
        secp256k1_bppp_challenge_scalar(&prover_ctx->e, transcript, 0);
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
    secp256k1_scalar q_inv;

    /* We need only one value in this round, ignore the second value. */
    secp256k1_scalar_chacha20(&prover_ctx->b_r, &prover_ctx->b_r, nonce, 4);

    /* Commit to the vector d in gens */
    secp256k1_ecmult_const(&r_commj, asset_genp, &prover_ctx->b_r, 256);
    for (i = 0; i < num_digits; i++) {
        secp256k1_gej resj;
        secp256k1_ge r_comm;
        secp256k1_scalar_add(&prover_ctx->r[i], &prover_ctx->d[i], &prover_ctx->e);
        secp256k1_scalar_inverse(&prover_ctx->r[i], &prover_ctx->r[i]); /* r_i cannot be zero as it added by random value `e`*/
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->r[i], 256);
        secp256k1_ge_set_gej(&r_comm, &r_commj);
        secp256k1_gej_add_ge(&r_commj, &resj, &r_comm); /* r_comm cannot be zero */
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
        secp256k1_bppp_challenge_scalar(&prover_ctx->q_sqrt, transcript, 0);
        secp256k1_bppp_challenge_scalar(&prover_ctx->x, transcript, 1);
        secp256k1_bppp_challenge_scalar(&prover_ctx->y, transcript, 2);
        secp256k1_scalar_sqr(&prover_ctx->q, &prover_ctx->q_sqrt);
    }
    /* Pre-compute powers of q and q_inv. We will need them in future rounds. */
    secp256k1_bppp_rangeproof_powers_of_q(prover_ctx->q_pows, &prover_ctx->q, g_offset);
    secp256k1_scalar_inverse_var(&q_inv, &prover_ctx->q); /* q cannot be zero */
    secp256k1_bppp_rangeproof_powers_of_q(prover_ctx->q_inv_pows, &q_inv, g_offset);
    /* Compute the values of alpha_m = (x/(e+i)*q_inv[i]) */
    for (i = 0; i < digit_base; i++) {
        secp256k1_scalar_set_int(&prover_ctx->alpha_m[i], i); /* digit base is less than 2^32, can directly set*/
        secp256k1_scalar_add(&prover_ctx->alpha_m[i], &prover_ctx->alpha_m[i], &prover_ctx->e);
        secp256k1_scalar_inverse_var(&prover_ctx->alpha_m[i], &prover_ctx->alpha_m[i]);
        secp256k1_scalar_mul(&prover_ctx->alpha_m[i], &prover_ctx->alpha_m[i], &prover_ctx->x);
        secp256k1_scalar_mul(&prover_ctx->alpha_m[i], &prover_ctx->alpha_m[i], &prover_ctx->q_inv_pows[i]);
    }
}

#endif
