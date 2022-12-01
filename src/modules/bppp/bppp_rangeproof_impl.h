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

/* Choose of the co-effs of poly and len of co-effs w = s + mT + dT^2 + rT^3 */
static const secp256k1_scalar* secp256k1_bppp_w_coeff(
    unsigned int *len,
    size_t idx,
    const secp256k1_scalar *s,
    const secp256k1_scalar *m,
    const secp256k1_scalar *d,
    const secp256k1_scalar *r,
    const secp256k1_scalar *alpha_m,
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
            return alpha_m;
        default:
            VERIFY_CHECK(0);
    }
    return NULL;
}

/* Compute the q-norm square of w = s + mT + dT^2 + rT^3 + alpha_mT^4.
   Since this is a degree 4 polynomial, we can hard code the expansion
   to get improve performance.
   |w|^2 =
   alpha_m**2*t**8 +
   2*alpha_m*r*t**7 +
   t**6*(2*alpha_m*d + r**2) +
   t**5*(2*alpha_m*m + 2*d*r) +
   t**4*(2*alpha_m*s + d**2 + 2*m*r) +
   t**3*(2*d*m + 2*r*s) +
   t**2*(2*d*s + m**2) +
   2*m*s*t +
   s**2
*/
static void secp256k1_bppp_rangeproof_w_w_q(
    secp256k1_scalar *w, /* size G_len = max(digits_base, num_digits)*/
    const secp256k1_scalar *s, /* size G_len */
    const secp256k1_scalar *m, /* size digits_base */
    const secp256k1_scalar *d, /* size num_digits */
    const secp256k1_scalar *r, /* size num_digits */
    const secp256k1_scalar *alpha_m, /* size digits_base */
    const secp256k1_scalar* q_pows, /* size G_len */
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
                secp256k1_bppp_w_coeff(&a_len, i, s, m, d, r, alpha_m, digit_base, num_digits);
            const secp256k1_scalar* b_coeffs =
                secp256k1_bppp_w_coeff(&b_len, j, s, m, d, r, alpha_m, digit_base, num_digits);
            /* Compute w[i + j] += Sum(a[k] * b[k] * q_pows[k]) */
            unsigned int len = a_len < b_len ? a_len : b_len;
            for (k = 0; k < len; k++) {
                secp256k1_scalar tmp;
                secp256k1_scalar_mul(&tmp, &a_coeffs[k], &b_coeffs[k]);
                secp256k1_scalar_mul(&tmp, &tmp, &q_pows[k]);
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
        secp256k1_scalar_chacha20(&prover_ctx->s[2*i], &prover_ctx->s[2*i + 1], nonce, i + 4);
    }

    /* The l values must be computed adaptively in order to satisfy the following relation for all Ts. */
    {
        /* Add public values alpha_r=(-x*q^-(i + 1) + e) to to d */
        secp256k1_scalar tmp, b_pow_i, base;
        for (i = 0; i < num_digits; i++) {
            secp256k1_scalar_negate(&tmp, &prover_ctx->x);
            secp256k1_scalar_mul(&tmp, &tmp, &prover_ctx->q_inv_pows[i]);
            secp256k1_scalar_add(&tmp, &tmp, &prover_ctx->e);
            secp256k1_scalar_add(&prover_ctx->d[i], &prover_ctx->d[i], &tmp);
        }

        /* Add public values alpha_d=(b^i*q_inv^(i+1)) to to r */
        secp256k1_scalar_set_int(&b_pow_i, 1);
        secp256k1_scalar_set_int(&base, digit_base);
        for (i = 0; i < num_digits; i++) {
            secp256k1_scalar_mul(&tmp, &b_pow_i, &prover_ctx->q_inv_pows[i]);
            secp256k1_scalar_add(&prover_ctx->r[i], &prover_ctx->r[i], &tmp);
            secp256k1_scalar_mul(&b_pow_i, &b_pow_i, &base);
        }
    }

    /* Adaptively compute l_s to balance out the w_w_q + Y*<l, c> is zero is
    in all powers of T where c = (T, T^2, T^3, T^4, T^6, T^7).
    Note the absence of T**5 in this equation. T^0 is balanced by b_s.
    T^5 is balanced only if all the constraints in the rangeproof are correctly satisfied.
    l = l_s + l_m*T + l_d*T^2 + l_r*T^3 + 2*gamma*T^5. Only the values l_m_i are sampled randomly.
    All other values but ld4 = -lm5 and lm2 = -lm3 are zero. Therefore, the resultant
    <l-l_s, c> = T**8*(ld4 + lm5) + T**7*lm4 + T**6(2*gamma) + T**5*(ld2 + lm3) + T**4*lm2 + T**3*lm1 + T**2*lm0
             = T**7*lm4 + T**6(2*gamma) + T**4*lm2 + T**3*lm1 + T**2*lm0
    We add these terms times challenge X to respective coeffs in w_w_q. l_s is the obtained by
    w_w_q + y*<l - l_s, c> + y*<l_s, c> = 0
    */
    {
        secp256k1_scalar w_w_q[9];
        secp256k1_scalar y_inv, two_gamma;
        secp256k1_bppp_rangeproof_w_w_q(
            w_w_q,
            prover_ctx->s,
            prover_ctx->m,
            prover_ctx->d,
            prover_ctx->r,
            prover_ctx->alpha_m,
            prover_ctx->q_pows,
            digit_base,
            num_digits
        );

        /* Add b_i values to w_w_q. b_m*T + b_d*T^2 + b_r*T^3 */
        secp256k1_scalar_negate(&prover_ctx->b_m, &prover_ctx->b_m);
        secp256k1_scalar_negate(&prover_ctx->b_d, &prover_ctx->b_d);
        secp256k1_scalar_negate(&prover_ctx->b_r, &prover_ctx->b_r);

        secp256k1_scalar_add(&w_w_q[1], &w_w_q[1], &prover_ctx->b_m);
        secp256k1_scalar_add(&w_w_q[2], &w_w_q[2], &prover_ctx->b_d);
        secp256k1_scalar_add(&w_w_q[3], &w_w_q[3], &prover_ctx->b_r);

        secp256k1_scalar_inverse_var(&y_inv, &prover_ctx->y);

        /* Balance out b_s = q^(i+1)*s[i]*s[i] = w_w_q[0] */
        prover_ctx->b_s = w_w_q[0];
        /* Note the limits on i from 1 to 8.*/
        for (i = 1; i < 8; i++) {
            secp256k1_scalar_mul(&w_w_q[i], &w_w_q[i], &y_inv);
        }
        secp256k1_scalar_add(&w_w_q[7], &w_w_q[7], &prover_ctx->l_m[4]);
        secp256k1_scalar_add(&w_w_q[4], &w_w_q[4], &prover_ctx->l_m[2]);
        secp256k1_scalar_add(&w_w_q[3], &w_w_q[3], &prover_ctx->l_m[1]);
        secp256k1_scalar_add(&w_w_q[2], &w_w_q[2], &prover_ctx->l_m[0]);

        secp256k1_scalar_set_int(&two_gamma, 2);
        secp256k1_scalar_mul(&two_gamma, &two_gamma, gamma);
        secp256k1_scalar_add(&w_w_q[6], &w_w_q[6], &two_gamma);

        /* Set all l_s values as negation of w_w_q */
        secp256k1_scalar_negate(&prover_ctx->l_s[0], &w_w_q[1]);
        secp256k1_scalar_negate(&prover_ctx->l_s[1], &w_w_q[2]);
        secp256k1_scalar_negate(&prover_ctx->l_s[2], &w_w_q[3]);
        secp256k1_scalar_negate(&prover_ctx->l_s[3], &w_w_q[4]);
        secp256k1_scalar_negate(&prover_ctx->l_s[4], &w_w_q[6]);
        secp256k1_scalar_negate(&prover_ctx->l_s[5], &w_w_q[7]);
    }
    /* Commit to the vector s in gens, with b_s along asset and l in H_vec */
    secp256k1_ecmult_const(&s_commj, asset_genp, &prover_ctx->b_s, 256);
    for (i = 0; i < g_offset; i++) {
        secp256k1_gej resj;
        secp256k1_ge s_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[i], &prover_ctx->s[i], 256);
        secp256k1_ge_set_gej(&s_comm, &s_commj);
        secp256k1_gej_add_ge(&s_commj, &resj, &s_comm); /* s_comm cannot be 0 */
    }

    for (i = 0; i < 6; i++) {
        secp256k1_gej resj;
        secp256k1_ge s_comm;
        secp256k1_ecmult_const(&resj, &gens->gens[g_offset + i], &prover_ctx->l_s[i], 256);
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

#endif
