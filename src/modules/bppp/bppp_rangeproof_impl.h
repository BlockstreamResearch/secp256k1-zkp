/**********************************************************************
 * Copyright (c) 2022 Sanket Kanjalkar                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_
#define SECP256K1_MODULE_BPP_RANGEPROOF_IMPL_


#include "../../group.h"
#include "../../scalar.h"
#include "../../../include/secp256k1.h"
#include "../../ecmult_const.h"
#include "../../field.h"
#include "../../../include/secp256k1_bppp.h"

#include "../bppp/bppp_util.h"
#include "../bppp/bppp_transcript_impl.h"
#include "../bppp/bppp_norm_product_impl.h"

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
    secp256k1_ecmult_const(&d_commj, asset_genp, &prover_ctx->r_d_0);

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
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->d[i]); /* should be = log_base + 1 bits here */
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
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 2], &prover_ctx->r_d_1_vec_2);
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 5], &prover_ctx->r_d_1_vec_5);
        secp256k1_ge_set_gej(&d_comm, &d_commj);
        secp256k1_gej_add_ge(&d_commj, &resj, &d_comm);
    }

    /* Compute the m vector as multiplicity of each digit */
    secp256k1_ecmult_const(&m_commj, asset_genp, &prover_ctx->r_m_0);
    for (i = 0; i < digit_base; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_scalar_set_int(&prover_ctx->m[i], multiplicities[i]);
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->m[i]); /* , log_num_digits + 1 (I think ) there should there be +1 here? */
        secp256k1_ge_set_gej(&m_comm, &m_commj);
        secp256k1_gej_add_ge(&m_commj, &resj, &m_comm); /* m_comm cannot be zero*/
    }

    for (i = 0; i < 8; i++) {
        secp256k1_gej resj;
        secp256k1_ge m_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + i], &prover_ctx->r_m_1_vec[i]);
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
    secp256k1_ecmult_const(&r_commj, asset_genp, &prover_ctx->r_r_0);
    for (i = 0; i < num_digits; i++) {
        secp256k1_gej resj;
        secp256k1_ge r_comm;
        secp256k1_scalar_add(&prover_ctx->r[i], &prover_ctx->d[i], &prover_ctx->alpha);
        secp256k1_scalar_inverse(&prover_ctx->r[i], &prover_ctx->r[i]); /* r_i cannot be zero as it added by random value `alpha`*/
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->r[i]);
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
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 1], &tmp);
        secp256k1_ge_set_gej(&r_comm, &r_commj);
        secp256k1_gej_add_ge(&r_commj, &resj, &r_comm);

        secp256k1_scalar_negate(&tmp, &prover_ctx->r_d_1_vec_5);
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + 4], &tmp);
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

/* Choose of the co-effs of poly and len of co-effs w = s + mT + dT^2 + rT^3 */
static const secp256k1_scalar* secp256k1_bppp_w_coeff(
    unsigned int *len,
    size_t idx,
    const secp256k1_scalar *s,
    const secp256k1_scalar *m,
    const secp256k1_scalar *d,
    const secp256k1_scalar *r,
    const secp256k1_scalar *c_m,
    size_t digit_base,
    size_t num_digits
) {
    switch (idx) {
        case 0:
            *len = num_digits > digit_base ? num_digits : digit_base;
            return s;
        case 1:
            *len = digit_base;
            return m;
        case 2:
            *len = num_digits;
            return d;
        case 3:
            *len = num_digits;
            return r;
        case 4:
            *len = digit_base;
            return c_m;
        default:
            VERIFY_CHECK(0);
    }
    return NULL;
}

/* Compute the mu-norm square of w = s/T + m + dT + rT^2 + c_mT^3.
   Note that m here is already scaled by delta.
   Since this is a degree 4 polynomial, we can hard code the expansion
   to get improve performance.
   |w|^2 =
   c_m**2*t**6 +
   2*c_m*r*t**5 +
   t**4*(2*c_m*d + r**2) +
   t**3*(2*c_m*m + 2*d*r) +
   t**2*(2*c_m*s + d**2 + 2*m*r) +
   t**1*(2*d*m + 2*r*s) +
   t**0*(2*d*s + m**2) +
   2*m*s/t +
   s**2/t**2.
   Doing this is left as a future optimization.
   The output vector w[0] represents degree t^-2. w[1] represents degree t^-1...
*/
static void secp256k1_bppp_rangeproof_w_w_q(
    secp256k1_scalar *w, /* size G_len = max(digits_base, num_digits)*/
    const secp256k1_scalar *s, /* size G_len */
    const secp256k1_scalar *m, /* size digits_base */
    const secp256k1_scalar *d, /* size num_digits */
    const secp256k1_scalar *r, /* size num_digits */
    const secp256k1_scalar *c_m, /* size digits_base */
    const secp256k1_scalar* mu_pows, /* size G_len */
    size_t digit_base,
    size_t num_digits
) {
    size_t i, j, k;
    for (i = 0; i < 9; i++) {
        secp256k1_scalar_clear(&w[i]);
    }

    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            /* Can add an optimization to skip the last term if i + j >= 8 */
            unsigned int a_len, b_len;
            const secp256k1_scalar* a_coeffs =
                secp256k1_bppp_w_coeff(&a_len, i, s, m, d, r, c_m, digit_base, num_digits);
            const secp256k1_scalar* b_coeffs =
                secp256k1_bppp_w_coeff(&b_len, j, s, m, d, r, c_m, digit_base, num_digits);
            /* Compute w[i + j] += Sum(a[k] * b[k] * mu_pows[k]) */
            unsigned int len = a_len < b_len ? a_len : b_len;
            for (k = 0; k < len; k++) {
                secp256k1_scalar tmp;
                secp256k1_scalar_mul(&tmp, &a_coeffs[k], &b_coeffs[k]);
                secp256k1_scalar_mul(&tmp, &tmp, &mu_pows[k]);
                secp256k1_scalar_add(&w[i + j], &w[i + j], &tmp);
            }
        }
    }
}

/* Round 3 of the proof. Computes the S value.
 * Serialized as 33 byte compressed point.
 * Always succeeds.
 */
static void secp256k1_bppp_rangeproof_prove_round3_impl(
    secp256k1_bppp_rangeproof_prover_context* prover_ctx,
    const secp256k1_bppp_generators* gens,
    const secp256k1_ge* asset_genp,
    unsigned char* output,
    secp256k1_sha256* transcript,
    const size_t num_digits,
    const size_t digit_base,
    const secp256k1_scalar* gamma,
    const unsigned char* nonce
) {
    size_t i;
    size_t g_offset = digit_base > num_digits ? digit_base : num_digits;
    secp256k1_gej s_commj;

    /* We don't need only one value in this round, ignore the second value. */
    for (i = 0; i < g_offset/2; i++) {
        secp256k1_scalar_chacha20(&prover_ctx->s[2*i], &prover_ctx->s[2*i + 1], nonce, i + 6);
    }

    /* The r_s values must be computed adaptively in order to satisfy the following relation for all Ts. */
    {
        /* Add public values p_r=(-x*delta*mu^-(i + 1) + alpha) to to d */
        secp256k1_scalar tmp, b_pow_i, base;
        for (i = 0; i < num_digits; i++) {
            secp256k1_scalar_negate(&tmp, &prover_ctx->x); /* tmp = -x */
            secp256k1_scalar_mul(&tmp, &tmp, &prover_ctx->delta); /* tmp = -x*delta */
            secp256k1_scalar_mul(&tmp, &tmp, &prover_ctx->mu_inv_pows[i]); /* tmp = -x*delta*mu_inv^(i+1) */
            secp256k1_scalar_add(&tmp, &tmp, &prover_ctx->alpha); /* tmp = -x*delta*mu_inv^(i+1) + alpha */
            secp256k1_scalar_add(&prover_ctx->d[i], &prover_ctx->d[i], &tmp); /* d[i] = d[i] + tmp */
        }

        /* Add public values p_d=(b^i*mu_inv^(i+1)) to to r */
        secp256k1_scalar_set_int(&b_pow_i, 1);
        secp256k1_scalar_set_int(&base, digit_base);
        for (i = 0; i < num_digits; i++) {
            secp256k1_scalar_mul(&tmp, &b_pow_i, &prover_ctx->mu_inv_pows[i]); /* tmp = b^i*mu_inv^(i+1) */
            secp256k1_scalar_add(&prover_ctx->r[i], &prover_ctx->r[i], &tmp); /* r[i] = r[i] + tmp */
            secp256k1_scalar_mul(&b_pow_i, &b_pow_i, &base); /* b_pow_i = b_pow_i * base */
        }
    }

    /* Scale the m values by delta. Scales all of m, r_m_1_vec, r_m_0. */
    {
        for (i = 0; i < digit_base; i++) {
            secp256k1_scalar_mul(&prover_ctx->m[i], &prover_ctx->m[i], &prover_ctx->delta);
        }
        for (i = 0; i < 8; i++) {
            secp256k1_scalar_mul(&prover_ctx->r_m_1_vec[i], &prover_ctx->r_m_1_vec[i], &prover_ctx->delta);
        }
        secp256k1_scalar_mul(&prover_ctx->r_m_0, &prover_ctx->r_m_0, &prover_ctx->delta);
    }

    /* Adaptively compute r_s_1_vec to balance out the w_w_q + <l, c> is zero is
    in all powers of T where c = beta*(T^-1, T, T^2, T^3, T^5, T^6, T^7, 0)
    Note the absence of T**3 in this equation. T^-1 is balanced by r_s_0.
    T^3 is balanced only if all the constraints in the rangeproof are correctly satisfied.
    l = r_s_1_vec/T + r_m_1_vec + r_d*T^1 + r_r*T^2 + 2*gamma*T^3.
    Only the values r_m_vec[i] are sampled randomly.
    */
    {
        secp256k1_scalar w_w_q[9];
        secp256k1_scalar beta_inv, two_gamma;
        secp256k1_bppp_rangeproof_w_w_q(
            w_w_q,
            prover_ctx->s,
            prover_ctx->m,
            prover_ctx->d,
            prover_ctx->r,
            prover_ctx->c_m,
            prover_ctx->mu_pows,
            digit_base,
            num_digits
        );

        secp256k1_scalar_negate(&prover_ctx->r_m_0, &prover_ctx->r_m_0);
        secp256k1_scalar_negate(&prover_ctx->r_d_0, &prover_ctx->r_d_0);
        secp256k1_scalar_negate(&prover_ctx->r_r_0, &prover_ctx->r_r_0);

        #define TPOW(x) (x + 2)

        /* Add b_i values to w_w_q. -r_m_0 - r_d_0*T^1 - r_r_0*T^2 */
        secp256k1_scalar_add(&w_w_q[TPOW(0)], &w_w_q[TPOW(0)], &prover_ctx->r_m_0);
        secp256k1_scalar_add(&w_w_q[TPOW(1)], &w_w_q[TPOW(1)], &prover_ctx->r_d_0);
        secp256k1_scalar_add(&w_w_q[TPOW(2)], &w_w_q[TPOW(2)], &prover_ctx->r_r_0);

        secp256k1_scalar_inverse_var(&beta_inv, &prover_ctx->beta);

        secp256k1_scalar_mul(&prover_ctx->r_s_0, &prover_ctx->r_m_1_vec[0], &prover_ctx->beta);
        secp256k1_scalar_add(&prover_ctx->r_s_0, &prover_ctx->r_s_0, &w_w_q[TPOW(-1)]);
        /* Note the limits on i from 0 to 9.*/
        for (i = 0; i < 9; i++) {
            secp256k1_scalar_mul(&w_w_q[i], &w_w_q[i], &beta_inv);
        }
        secp256k1_scalar_add(&w_w_q[TPOW(6)], &w_w_q[TPOW(6)], &prover_ctx->r_m_1_vec[5]);
        secp256k1_scalar_add(&w_w_q[TPOW(5)], &w_w_q[TPOW(5)], &prover_ctx->r_m_1_vec[4]);
        /* r_m_1_vec[3] maps to T^4 */
        /* secp256k1_scalar_add(&w_w_q[TPOW(3)], &w_w_q[TPOW(3)], &prover_ctx->r_m_1_vec[3]); */
        secp256k1_scalar_add(&w_w_q[TPOW(2)], &w_w_q[TPOW(2)], &prover_ctx->r_m_1_vec[2]);
        secp256k1_scalar_add(&w_w_q[TPOW(1)], &w_w_q[TPOW(1)], &prover_ctx->r_m_1_vec[1]);

        secp256k1_scalar_set_int(&two_gamma, 2);
        secp256k1_scalar_mul(&two_gamma, &two_gamma, gamma);
        secp256k1_scalar_add(&w_w_q[TPOW(2)], &w_w_q[TPOW(2)], &two_gamma);

        /* Set all r_s_1_vec values as negation of w_w_q */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[0], &w_w_q[TPOW(-2)]); /* T^-1 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[1], &w_w_q[TPOW(0)]); /* T^1 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[2], &w_w_q[TPOW(1)]); /* T^2 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[3], &w_w_q[TPOW(2)]); /* T^3 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[4], &w_w_q[TPOW(4)]); /* T^5 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[5], &w_w_q[TPOW(5)]); /* T^6 */
        secp256k1_scalar_negate(&prover_ctx->r_s_1_vec[6], &w_w_q[TPOW(6)]); /* T^7 */
    }
    /* Commit to the vector s in gens, with r_s_0 along asset and l in H_vec */
    secp256k1_ecmult_const(&s_commj, asset_genp, &prover_ctx->r_s_0);
    for (i = 0; i < g_offset; i++) {
        secp256k1_gej resj;
        secp256k1_ge s_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->s[i]);
        secp256k1_ge_set_gej(&s_comm, &s_commj);
        secp256k1_gej_add_ge(&s_commj, &resj, &s_comm); /* s_comm cannot be 0 */
    }

    for (i = 0; i < 7; i++) {
        secp256k1_gej resj;
        secp256k1_ge s_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + i], &prover_ctx->r_s_1_vec[i]);
        secp256k1_ge_set_gej(&s_comm, &s_commj);
        secp256k1_gej_add_ge(&s_commj, &resj, &s_comm); /* s_comm cannot be 0 */
    }

    {
        secp256k1_ge s_comm;
        /* All s values are non-zero(computed by inverse), scommj must be non-zero */
        VERIFY_CHECK(secp256k1_gej_is_infinity(&s_commj) == 0);
        secp256k1_ge_set_gej_var(&s_comm, &s_commj);
        secp256k1_fe_normalize_var(&s_comm.x);
        secp256k1_fe_normalize_var(&s_comm.y);
        secp256k1_bppp_serialize_pt(&output[0], &s_comm);

        secp256k1_sha256_write(transcript, output, 33);
        secp256k1_bppp_challenge_scalar(&prover_ctx->t, transcript, 0);
    }
}

/* Round 4 of the proof. Computes the norm proof on the w and l values.
 * Can fail only when the norm proof fails.
 * This should not happen in our setting because w_vec and l_vec and uniformly
 * distributed and thus norm argument can only fail when the lengths are not a
 * power of two or if the allocated proof size is not enough.
 *
 * We check for both of these conditions beforehand, therefore in practice this
 * function should never fail because it returns point at infinity during some
 * interim calculations. However, since the overall API can fail, we also fail
 * if the norm proofs fails for any reason.
 */
static int secp256k1_bppp_rangeproof_prove_round4_impl(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bppp_generators* gens,
    const secp256k1_ge* asset_genp,
    secp256k1_bppp_rangeproof_prover_context* prover_ctx,
    unsigned char* output,
    size_t *output_len,
    secp256k1_sha256* transcript,
    const secp256k1_scalar* gamma,
    const size_t num_digits,
    const size_t digit_base
) {
    size_t i, scratch_checkpoint, ret;
    size_t g_offset = digit_base > num_digits ? digit_base : num_digits;
    /* Compute w = s/t + m + t*d + t^2*r + t^3*c_m. Store w in s*/
    secp256k1_scalar t_pows[8], c_poly[8], t_inv;
    secp256k1_ge *gs;

    secp256k1_scalar_inverse(&t_inv, &prover_ctx->t);
    secp256k1_bppp_rangeproof_powers_of_mu(&t_pows[0], &prover_ctx->t, 7); /* Computes from t^1 to t^7 */

    for (i = 0; i < g_offset; i++) {
        secp256k1_scalar_mul(&prover_ctx->s[i], &prover_ctx->s[i], &t_inv);
        if (i < num_digits) {
            secp256k1_scalar_mul(&prover_ctx->r[i], &prover_ctx->r[i], &t_pows[1]);
            secp256k1_scalar_add(&prover_ctx->s[i], &prover_ctx->s[i], &prover_ctx->r[i]);

            secp256k1_scalar_mul(&prover_ctx->d[i], &prover_ctx->d[i], &t_pows[0]);
            secp256k1_scalar_add(&prover_ctx->s[i], &prover_ctx->s[i], &prover_ctx->d[i]);
        }
        if (i < digit_base) {
            secp256k1_scalar_add(&prover_ctx->s[i], &prover_ctx->s[i], &prover_ctx->m[i]);

            secp256k1_scalar_mul(&prover_ctx->c_m[i], &prover_ctx->c_m[i], &t_pows[2]);
            secp256k1_scalar_add(&prover_ctx->s[i], &prover_ctx->s[i], &prover_ctx->c_m[i]);
        }
    }
    /* Compute l = l_s/t + r_m_1_vec + t^1*l_d + t^2*l_r. Store l in l_s*/
    for (i = 0; i < 7; i++) {
        secp256k1_scalar_mul(&prover_ctx->r_s_1_vec[i], &prover_ctx->r_s_1_vec[i], &t_inv);
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[i], &prover_ctx->r_s_1_vec[i], &prover_ctx->r_m_1_vec[i]);
    }
    /* Manually add r_d2, r_d5, r_r1 and r_r4 */
    {
        secp256k1_scalar tmp;
        secp256k1_scalar_mul(&tmp, &prover_ctx->r_d_1_vec_2, &t_pows[0]);
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[2], &prover_ctx->r_s_1_vec[2], &tmp);

        secp256k1_scalar_mul(&tmp, &prover_ctx->r_d_1_vec_2, &t_pows[1]);
        secp256k1_scalar_negate(&tmp, &tmp);/* r_r[1] = -r_d_vec[2] */
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[1], &prover_ctx->r_s_1_vec[1], &tmp);

        secp256k1_scalar_mul(&tmp, &prover_ctx->r_d_1_vec_5, &t_pows[0]);
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[5], &prover_ctx->r_s_1_vec[5], &tmp);

        secp256k1_scalar_mul(&tmp, &prover_ctx->r_d_1_vec_5, &t_pows[1]);
        secp256k1_scalar_negate(&tmp, &tmp);/* r_r[4] = -r_m_vec[5] */
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[4], &prover_ctx->r_s_1_vec[4], &tmp);

        /* Add two_gamma * t3 to l_s[0] */
        secp256k1_scalar_add(&tmp, &t_pows[2], &t_pows[2]);
        secp256k1_scalar_mul(&tmp, &tmp, gamma);
        secp256k1_scalar_add(&prover_ctx->r_s_1_vec[0], &prover_ctx->r_s_1_vec[0], &tmp);
    }
    /* Set non used 7th and 8th l_s to 0 */
    secp256k1_scalar_set_int(&prover_ctx->r_s_1_vec[7], 0);

    /* Make c = beta*(T^-1, T, T^2, T^3, T^5, T^6, T^7, 0) */
    c_poly[0] = t_inv;
    c_poly[1] = t_pows[0];
    c_poly[2] = t_pows[1];
    c_poly[3] = t_pows[2];
    c_poly[4] = t_pows[4];
    c_poly[5] = t_pows[5];
    c_poly[6] = t_pows[6];
    secp256k1_scalar_set_int(&c_poly[7], 0);
    for (i = 0; i < 7; i++) {
        secp256k1_scalar_mul(&c_poly[i], &c_poly[i], &prover_ctx->beta);
    }
    /* Call the norm argument on w, l */
    /* We have completed the blinding, none of part that comes from this point on
       needs to constant time. We can safely early return
    */
    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    gs = (secp256k1_ge*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, (gens->n) * sizeof(secp256k1_ge));
    if (gs == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    memcpy(gs, gens->gens, (gens->n) * sizeof(secp256k1_ge));

    ret = secp256k1_bppp_rangeproof_norm_product_prove(
        ctx,
        scratch,
        output,
        output_len,
        transcript,
        &prover_ctx->rho,
        gs,
        gens->n,
        asset_genp,
        prover_ctx->s,
        g_offset,
        prover_ctx->r_s_1_vec,
        8,
        c_poly,
        8
    );
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
    return ret;
}

static int secp256k1_bppp_rangeproof_prove_impl(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bppp_generators* gens,
    secp256k1_ge* asset_genp,
    unsigned char* proof,
    size_t* proof_len,
    const size_t n_bits,
    const size_t digit_base,
    const uint64_t value,
    const uint64_t min_value,
    secp256k1_ge* commitp,
    const secp256k1_scalar* gamma,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    size_t scratch_checkpoint, n_proof_bytes_written, norm_proof_len;
    secp256k1_sha256 transcript;
    size_t num_digits = n_bits / secp256k1_bppp_log2(digit_base);
    size_t h_len = 8;
    size_t g_offset = num_digits > digit_base ? num_digits : digit_base;
    size_t log_n = secp256k1_bppp_log2(g_offset), log_m = secp256k1_bppp_log2(h_len);
    size_t n_rounds = log_n > log_m ? log_n : log_m;
    int res;
    secp256k1_bppp_rangeproof_prover_context prover_ctx;
    /* Check proof sizes*/
    if (*proof_len < 33 * 4 + (65 * n_rounds) + 64) {
        return 0;
    }
    if (gens->n != (g_offset + h_len)) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(digit_base) ||  !secp256k1_is_power_of_two(num_digits)) {
        return 0;
    }
    if (n_bits > 64) {
        return 0;
    }
    if (value < min_value) {
        return 0;
    }
    if (n_bits < 64 && (value - min_value) >= (1ull << n_bits)) {
        return 0;
    }
    if (extra_commit_len > 0 && extra_commit == NULL) {
        return 0;
    }

    /* Compute the base digits representation of the value */
    /* Alloc for prover->ctx */
    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    prover_ctx.s = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));
    prover_ctx.d = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, num_digits * sizeof(secp256k1_scalar));
    prover_ctx.m = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, digit_base * sizeof(secp256k1_scalar));
    prover_ctx.r = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, num_digits * sizeof(secp256k1_scalar));
    prover_ctx.c_m = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, digit_base * sizeof(secp256k1_scalar));

    prover_ctx.r_m_1_vec = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, 8 * sizeof(secp256k1_scalar));
    prover_ctx.r_s_1_vec = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));

    prover_ctx.mu_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));
    prover_ctx.mu_inv_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));

    if ( prover_ctx.s == NULL || prover_ctx.d == NULL || prover_ctx.m == NULL || prover_ctx.r == NULL
        || prover_ctx.c_m == NULL || prover_ctx.r_m_1_vec == NULL || prover_ctx.r_s_1_vec == NULL
        || prover_ctx.mu_pows == NULL || prover_ctx.mu_inv_pows == NULL )
    {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* Initialze the transcript by committing to all the public data */
    secp256k1_bppp_commit_initial_data(
        &transcript,
        num_digits,
        digit_base,
        min_value,
        commitp,
        asset_genp,
        extra_commit,
        extra_commit_len
    );

    n_proof_bytes_written = 0;
    secp256k1_bppp_rangeproof_prove_round1_impl(
        &prover_ctx,
        gens,
        asset_genp,
        &proof[n_proof_bytes_written],
        &transcript,
        num_digits,
        digit_base,
        value - min_value,
        nonce
    );
    n_proof_bytes_written += 33 *2;

    secp256k1_bppp_rangeproof_prove_round2_impl(
        &prover_ctx,
        gens,
        asset_genp,
        &proof[n_proof_bytes_written],
        &transcript,
        num_digits,
        digit_base,
        nonce
    );
    n_proof_bytes_written += 33;

    secp256k1_bppp_rangeproof_prove_round3_impl(
        &prover_ctx,
        gens,
        asset_genp,
        &proof[n_proof_bytes_written],
        &transcript,
        num_digits,
        digit_base,
        gamma,
        nonce
    );
    n_proof_bytes_written += 33;

    /* Calculate the remaining buffer size. We have already checked that buffer is of correct size */
    norm_proof_len = *proof_len - n_proof_bytes_written;
    res = secp256k1_bppp_rangeproof_prove_round4_impl(
        ctx,
        scratch,
        gens,
        asset_genp,
        &prover_ctx,
        &proof[n_proof_bytes_written],
        &norm_proof_len,
        &transcript,
        gamma,
        num_digits,
        digit_base
    );
    /* No need to worry about constant time-ness from this point. All data is public */
    if (res) {
        *proof_len = n_proof_bytes_written + norm_proof_len;
    }
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
    return res;
}

typedef struct secp256k1_bppp_verify_cb_data {
    const unsigned char *proof;
    const secp256k1_scalar *g_vec_pub_deltas;
    const secp256k1_scalar *t_pows;
    const secp256k1_scalar *t_inv;
    const secp256k1_scalar *v;
    const secp256k1_scalar *delta;
    const secp256k1_ge *asset_genp;
    const secp256k1_ge *commit;
    const secp256k1_ge *g_gens;
} secp256k1_bppp_verify_cb_data;

static int secp256k1_bppp_verify_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    secp256k1_bppp_verify_cb_data *data = (secp256k1_bppp_verify_cb_data*) cbdata;
    switch(idx) {
        case 0:  /* v * asset_genp */
            *pt = *data->asset_genp;
            *sc = *data->v;
            break;
        case 1:  /* delta * M */
            if (!secp256k1_eckey_pubkey_parse(pt, data->proof, 33)) {
                return 0;
            }
            *sc = *data->delta;
            break;
        case 2:  /* t * D */
            if (!secp256k1_eckey_pubkey_parse(pt, &data->proof[33], 33)) {
                return 0;
            }
            *sc = data->t_pows[0];
            break;
        case 3:  /* t^2 * R */
            if (!secp256k1_eckey_pubkey_parse(pt, &data->proof[33 * 2], 33)) {
                return 0;
            }
            *sc = data->t_pows[1];
            break;
        case 4:  /* t^-1 * S */
            if (!secp256k1_eckey_pubkey_parse(pt, &data->proof[33 * 3], 33)) {
                return 0;
            }
            *sc = *data->t_inv;
            break;
        case 5:  /* 2t^3 * V(commit) */
            *pt = *data->commit;
            *sc = data->t_pows[2];
            secp256k1_scalar_add(sc, sc, sc);
            break;
        default:
            idx -= 6;
            *pt = data->g_gens[idx];
            *sc = data->g_vec_pub_deltas[idx];
            break;
    }
    return 1;
}

static int secp256k1_bppp_rangeproof_verify_impl(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bppp_generators* gens,
    secp256k1_ge* asset_genp,
    const unsigned char* proof,
    const size_t proof_len,
    const size_t n_bits,
    const size_t digit_base,
    const uint64_t min_value,
    secp256k1_ge* commitp,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    int res;
    size_t scratch_checkpoint;
    secp256k1_sha256 transcript;
    size_t num_digits = n_bits / secp256k1_bppp_log2(digit_base);
    size_t h_len = 8, i;
    size_t g_offset = num_digits > digit_base ? num_digits : digit_base;
    size_t log_n = secp256k1_bppp_log2(g_offset), log_m = secp256k1_bppp_log2(h_len);
    size_t n_rounds = log_n > log_m ? log_n : log_m;
    secp256k1_scalar v_g;
    secp256k1_scalar *mu_pows, *mu_inv_pows, *g_vec_pub_deltas;
    secp256k1_scalar alpha, rho, mu, mu_inv, x, beta, delta, t;
    /* To be re-used as c_vec later */
    secp256k1_scalar t_pows[8];

    /* Check proof sizes*/
    if (proof_len != 33 * 4 + (65 * n_rounds) + 64) {
        return 0;
    }
    if (gens->n != (g_offset + h_len)) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(digit_base) ||  !secp256k1_is_power_of_two(num_digits) || !secp256k1_is_power_of_two(n_bits)) {
        return 0;
    }
    if (n_bits > 64) {
        return 0;
    }
    if (extra_commit_len > 0 && extra_commit == NULL) {
        return 0;
    }

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    mu_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));
    mu_inv_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));
    g_vec_pub_deltas = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_offset * sizeof(secp256k1_scalar));

    if ( mu_pows == NULL || mu_inv_pows == NULL ) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* Obtain the challenges */
    secp256k1_bppp_commit_initial_data(
        &transcript,
        num_digits,
        digit_base,
        min_value,
        commitp,
        asset_genp,
        extra_commit,
        extra_commit_len
    );

    /* Verify round 1 */
    secp256k1_sha256_write(&transcript, proof, 66);
    secp256k1_bppp_challenge_scalar(&alpha, &transcript, 0);

    /* Verify round 2 */
    secp256k1_sha256_write(&transcript, &proof[33*2], 33);
    secp256k1_bppp_challenge_scalar(&rho, &transcript, 0);
    secp256k1_bppp_challenge_scalar(&x, &transcript, 1);
    secp256k1_bppp_challenge_scalar(&beta, &transcript, 2);
    secp256k1_bppp_challenge_scalar(&delta, &transcript, 3);
    secp256k1_scalar_sqr(&mu, &rho);
    secp256k1_scalar_inverse_var(&mu_inv, &mu);

    /* Verify round 3 */
    secp256k1_sha256_write(&transcript, &proof[33*3], 33);
    secp256k1_bppp_challenge_scalar(&t, &transcript, 0);

    secp256k1_bppp_rangeproof_powers_of_mu(mu_pows, &mu, g_offset);
    secp256k1_bppp_rangeproof_powers_of_mu(mu_inv_pows, &mu_inv, g_offset);

    /* Computes from t^1 to t^7, Others unneeded, will be set to 0 later */
    secp256k1_bppp_rangeproof_powers_of_mu(&t_pows[0], &t, 7);
    {
        /* g_vec_pub_delta[i] = (b^i*t^2 + (-x*delta)*t^1 + (x/alpha+i)*t^3)*mu_inv^i + alpha*t^1 */
        secp256k1_scalar b_pow_i_t2, neg_x_delta_t1, x_t3, alpha_t1, base;
        b_pow_i_t2 = t_pows[1];
        secp256k1_scalar_negate(&neg_x_delta_t1, &x);
        secp256k1_scalar_mul(&neg_x_delta_t1, &neg_x_delta_t1, &delta); /* -x */
        secp256k1_scalar_mul(&neg_x_delta_t1, &neg_x_delta_t1, &t_pows[0]); /* -x * delta *t */
        x_t3 = t_pows[2];
        secp256k1_scalar_mul(&x_t3, &x_t3, &x);
        alpha_t1 = t_pows[0];
        secp256k1_scalar_mul(&alpha_t1, &alpha_t1, &alpha);
        secp256k1_scalar_set_int(&base, digit_base);

        for (i = 0; i < g_offset; i++) {
            secp256k1_scalar_clear(&g_vec_pub_deltas[i]);
            if (i < num_digits) {
                secp256k1_scalar_add(&g_vec_pub_deltas[i], &b_pow_i_t2, &neg_x_delta_t1); /* g_vec_pub_delta[i] = b^i*t^2 + (-x * delta)*t^1 */
                secp256k1_scalar_mul(&b_pow_i_t2, &b_pow_i_t2, &base); /* b^i */
            }

            if (i < digit_base) {
                secp256k1_scalar e_plus_i_inv;
                secp256k1_scalar_set_int(&e_plus_i_inv, i); /* digit base is less than 2^32, can directly set*/
                secp256k1_scalar_add(&e_plus_i_inv, &e_plus_i_inv, &alpha); /* (alpha + i)*/
                secp256k1_scalar_inverse_var(&e_plus_i_inv, &e_plus_i_inv); /* 1/(alpha +i)*/
                secp256k1_scalar_mul(&e_plus_i_inv, &e_plus_i_inv, &x_t3); /* xt^3/(alpha+i) */

                secp256k1_scalar_add(&g_vec_pub_deltas[i], &g_vec_pub_deltas[i], &e_plus_i_inv); /* g_vec_pub_delta[i] = b^i*t^2 + (-x * delta)*t^1 + xt^3/(alpha+i) */
            }

            secp256k1_scalar_mul(&g_vec_pub_deltas[i], &g_vec_pub_deltas[i], &mu_inv_pows[i]); /* g_vec_pub_delta[i] = (b^i*t^2 + (-x*delta)*t^1 + (x/alpha+i)*t^3)*mu_inv^i */
            if (i < num_digits) {
                secp256k1_scalar_add(&g_vec_pub_deltas[i], &g_vec_pub_deltas[i], &alpha_t1); /* g_vec_pub_delta[i] = (b^i*t^2 + (-x*delta)*t^1 + (x/alpha+i)*t^3)*mu_inv^i + alpha*t^1 */
            }
        }
    }

    {
        /* v = 2*t3(<one_vec, mu^(i+1)> + <b^i, alpha> + <b^i, -x*mu^-(i+1)>) */
        secp256k1_scalar two_t3, b_pow_i, neg_x_mu_inv_pow_plus_alpha, base, sc_min_v;
        secp256k1_scalar_set_int(&two_t3, 2); /* 2 */
        secp256k1_scalar_mul(&two_t3, &two_t3, &t_pows[2]); /* 2*t^3 */
        secp256k1_scalar_set_int(&b_pow_i, 1); /* b^0 */
        secp256k1_scalar_clear(&v_g); /* v_g = 0 */
        secp256k1_scalar_set_int(&base, digit_base); /* base = digit_base */

        /* Compute v_g = 2*t5(<one_vec, mu^(i+1)> + <b^i, alpha> + <b^i, -x*mu^-(i+1)>) */
        for (i = 0; i < num_digits; i++) {
            secp256k1_scalar_add(&v_g, &v_g, &mu_pows[i]); /* v_g = <mu^(i+1), 1> */
            secp256k1_scalar_mul(&neg_x_mu_inv_pow_plus_alpha, &x, &delta); /* x * delta */
            secp256k1_scalar_negate(&neg_x_mu_inv_pow_plus_alpha, &neg_x_mu_inv_pow_plus_alpha); /* -x *delta*/
            secp256k1_scalar_mul(&neg_x_mu_inv_pow_plus_alpha, &mu_inv_pows[i], &neg_x_mu_inv_pow_plus_alpha); /* -x*mu^-(i+1) */
            secp256k1_scalar_add(&neg_x_mu_inv_pow_plus_alpha, &neg_x_mu_inv_pow_plus_alpha, &alpha); /* -x*mu^-(i+1) + alpha */
            secp256k1_scalar_mul(&neg_x_mu_inv_pow_plus_alpha, &neg_x_mu_inv_pow_plus_alpha, &b_pow_i); /* <b^i, -x*mu^-(i+1) + alpha> */
            secp256k1_scalar_add(&v_g, &v_g, &neg_x_mu_inv_pow_plus_alpha); /* v_g = <mu^(i+1), 1> + <b^i, -x*mu^-(i+1) + alpha> */
            secp256k1_scalar_mul(&b_pow_i, &b_pow_i, &base);
        }
        secp256k1_scalar_set_int(&sc_min_v, min_value);
        secp256k1_scalar_negate(&sc_min_v, &sc_min_v);
        secp256k1_scalar_add(&v_g, &v_g, &sc_min_v); /* v_g = <mu^(i+1), 1> + <b^i, -x*mu^-(i+1) + alpha> - min_value */
        secp256k1_scalar_mul(&v_g, &v_g, &two_t3); /* v_g = 2*t5(<one_vec, mu^(i+1)> + <b^i, alpha> + <b^i, -x*mu^-(i+1)> - min_value) */
    }
    /* Ecmult to compute C = S/T + M*delta + t*D + t^2R + 2t^3V + <g_vec_pub_deltas, G_vec> + v_g*A(asset_genP) */
    {
        secp256k1_bppp_verify_cb_data cb_data;
        secp256k1_gej c_commj;
        secp256k1_ge c_comm;
        secp256k1_scalar c_poly[8], t_inv;
        size_t num_points;
        cb_data.g_vec_pub_deltas = g_vec_pub_deltas;
        cb_data.v = &v_g;
        cb_data.asset_genp = asset_genp;
        cb_data.commit = commitp;
        cb_data.g_gens = gens->gens;
        cb_data.proof = proof;
        cb_data.t_pows = t_pows;
        cb_data.delta = &delta;
        secp256k1_scalar_inverse(&t_inv, &t);
        cb_data.t_inv = &t_inv;
        num_points = 6 + g_offset;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &c_commj, NULL, secp256k1_bppp_verify_cb, (void*) &cb_data, num_points)) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }

        secp256k1_ge_set_gej_var(&c_comm, &c_commj);
        /* Make c = beta*(1/T, T, T^2, T^3, T^5, T^6, T^7, 0) */
        c_poly[0] = t_inv;
        c_poly[1] = t_pows[0];
        c_poly[2] = t_pows[1];
        c_poly[3] = t_pows[2];
        c_poly[4] = t_pows[4];
        c_poly[5] = t_pows[5];
        c_poly[6] = t_pows[6];
        for (i = 0; i < 7; i++) {
            secp256k1_scalar_mul(&c_poly[i], &c_poly[i], &beta);
        }
        secp256k1_scalar_clear(&c_poly[7]);

        res = secp256k1_bppp_rangeproof_norm_product_verify(
            ctx,
            scratch,
            &proof[33*4],
            proof_len - 33*4,
            &transcript,
            &rho,
            gens,
            asset_genp,
            g_offset,
            c_poly,
            8,
            &c_comm
        );
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return res;
    }
}

#endif
