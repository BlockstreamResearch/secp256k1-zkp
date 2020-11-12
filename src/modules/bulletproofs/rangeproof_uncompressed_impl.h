/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_RP_UNCOMPRESSED_
#define _SECP256K1_MODULE_BULLETPROOFS_RP_UNCOMPRESSED_

#include "group.h"
#include "scalar.h"

#include "modules/bulletproofs/bulletproofs_util.h"

/* Prover context data:
 *    bytes 0-32:   x (hash challenge)
 *    bytes 32-64:  y (hash challenge)
 *    bytes 64-96:  z (hash challenge)
 *    bytes 96-160: lr_generator data
 */

/* Step 0 of the proof.
 * Uses the value but not the blinding factor. Takes the complete commitment,
 * but only to put it into the hash.
 * Outputs the points A and S, encoded in 65 bytes (one byte with A's parity
 * in the LSB, S's parity in the second-LSB, 32-byte A.x, 32-byte S.x).
 * Updates the state to include the hashes y and z.
 */
static int secp256k1_bulletproofs_rangeproof_uncompressed_prove_step0_impl(
    const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
    secp256k1_bulletproofs_prover_context* prover_ctx,
    unsigned char* output,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_ge* commitp,
    const secp256k1_ge* asset_genp,
    const secp256k1_bulletproofs_generators* gens,
    const unsigned char* nonce,
    const secp256k1_scalar* enc_data,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    secp256k1_sha256 sha256;
    unsigned char commit[32];
    secp256k1_scalar alpha, rho;
    secp256k1_scalar tmp_l, tmp_r;
    secp256k1_gej gej;
    secp256k1_ge ge;
    size_t i;
    int overflow;

    memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
    memset(output, 0, 65);

    /* Sanity checks */
    if (n_bits > 64) {
        return 0;
    }
    if (gens->n < n_bits * 2) {
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

    /* Commit to all input data: min value, pedersen commit, asset generator, extra_commit
     * Pass the output in as scratch space since we haven't used it yet. */
    secp256k1_bulletproofs_commit_initial_data(commit, output, n_bits, min_value, commitp, asset_genp, extra_commit, extra_commit_len);

    /* Compute alpha and rho, adding encrypted data to alpha (effectively adding
     * it to mu, which is one of the scalars in the final proof) */
    secp256k1_scalar_chacha20(&alpha, &rho, nonce, 0);
    secp256k1_scalar_add(&alpha, &alpha, enc_data);

    /* Compute and output A */
    secp256k1_ecmult_gen(ecmult_gen_ctx, &gej, &alpha);
    for (i = 0; i < n_bits; i++) {
        secp256k1_ge aterm = gens->gens[2 * i + 1];
        size_t al = !!((value - min_value) & (1ull << i));

        secp256k1_ge_neg(&aterm, &aterm);
        secp256k1_fe_cmov(&aterm.x, &gens->gens[2 * i].x, al);
        secp256k1_fe_cmov(&aterm.y, &gens->gens[2 * i].y, al);
        secp256k1_gej_add_ge(&gej, &gej, &aterm);
    }
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_normalize_var(&ge.y);
    output[0] = secp256k1_fe_is_odd(&ge.y) << 1;
    secp256k1_fe_get_b32(&output[1], &ge.x);

    /* Compute and output S */
    secp256k1_ecmult_gen(ecmult_gen_ctx, &gej, &rho);
    for (i = 0; i < n_bits; i++) {
        secp256k1_ge sterm;
        secp256k1_gej stermj;

        secp256k1_scalar_chacha20(&tmp_l, &tmp_r, nonce, i + 2);

        secp256k1_ecmult_const(&stermj, &gens->gens[2 * i], &tmp_l, 256);
        secp256k1_ge_set_gej(&sterm, &stermj);
        secp256k1_gej_add_ge(&gej, &gej, &sterm);
        secp256k1_ecmult_const(&stermj, &gens->gens[2 * i + 1], &tmp_r, 256);
        secp256k1_ge_set_gej(&sterm, &stermj);
        secp256k1_gej_add_ge(&gej, &gej, &sterm);
    }
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_normalize_var(&ge.y);
    output[0] |= secp256k1_fe_is_odd(&ge.y);
    secp256k1_fe_get_b32(&output[33], &ge.x);

    /* get challenges y and z, store them in the prover context */
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_write(&sha256, output, 65);
    secp256k1_sha256_finalize(&sha256, &prover_ctx->data[32]);
    secp256k1_scalar_set_b32(&tmp_l, &prover_ctx->data[32], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&tmp_l)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 65);
        return 0;
    }

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, &prover_ctx->data[32], 32);
    secp256k1_sha256_finalize(&sha256, &prover_ctx->data[64]);
    secp256k1_scalar_set_b32(&tmp_l, &prover_ctx->data[64], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&tmp_l)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 65);
        return 0;
    }

    /* Success */
    return 1;
}

/* Step 1 of the proof.
 * Does not use the Pedersen commitment at all.
 * Outputs the points T1 and T2, encoded in 65 bytes (one byte with T1's parity
 * in the LSB, T2's parity in the second-LSB, 32-byte T1.x, 32-byte T2.x).
 * Updates the state to include the hash x.
 */
static int secp256k1_bulletproofs_rangeproof_uncompressed_prove_step1_impl(
    const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
    secp256k1_bulletproofs_prover_context* prover_ctx,
    unsigned char* output,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_ge* asset_genp,
    const unsigned char* nonce
) {
    secp256k1_bulletproofs_bulletproofs_lrgen lr_gen;
    secp256k1_sha256 sha256;
    secp256k1_scalar tau1, tau2;
    secp256k1_scalar t0, t1, t2;
    secp256k1_scalar y, z;
    secp256k1_scalar tmps;
    secp256k1_gej gej;
    secp256k1_ge ge;
    size_t i;
    int overflow;

    memset(output, 0, 65);

    /* Unpack challenges y and z from step 0 */
    secp256k1_scalar_set_b32(&y, &prover_ctx->data[32], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&y)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        return 0;
    }
    secp256k1_scalar_set_b32(&z, &prover_ctx->data[64], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&z)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 65);
        return 0;
    }

    /* Generate new blinding factors tau1 and tau2 */
    secp256k1_scalar_chacha20(&tau1, &tau2, nonce, 1);

    /* Compute coefficients t0, t1, t2 of the <l, r> polynomial */
    /* t0 = l(0) dot r(0) */
    secp256k1_bulletproofs_lrgen_init(&lr_gen, nonce, &y, &z, value - min_value);
    secp256k1_scalar_clear(&t0);
    secp256k1_scalar_clear(&tmps);
    for (i = 0; i < n_bits; i++) {
        secp256k1_scalar l, r;
        secp256k1_lr_generate(&lr_gen, &l, &r, &tmps);
        secp256k1_scalar_mul(&l, &l, &r);
        secp256k1_scalar_add(&t0, &t0, &l);
    }

    /* A = t0 + t1 + t2 = l(1) dot r(1) */
    secp256k1_bulletproofs_lrgen_init(&lr_gen, nonce, &y, &z, value - min_value);
    secp256k1_scalar_clear(&t1);
    for (i = 0; i < n_bits; i++) {
        secp256k1_scalar one;
        secp256k1_scalar l, r;
        secp256k1_scalar_set_int(&one, 1);
        secp256k1_lr_generate(&lr_gen, &l, &r, &one);
        secp256k1_scalar_mul(&l, &l, &r);
        secp256k1_scalar_add(&t1, &t1, &l);
    }

    /* B = t0 - t1 + t2 = l(-1) dot r(-1) */
    secp256k1_bulletproofs_lrgen_init(&lr_gen, nonce, &y, &z, value - min_value);
    secp256k1_scalar_clear(&t2);
    for (i = 0; i < n_bits; i++) {
        secp256k1_scalar negone;
        secp256k1_scalar l, r;
        secp256k1_scalar_set_int(&negone, 1);
        secp256k1_scalar_negate(&negone, &negone);
        secp256k1_lr_generate(&lr_gen, &l, &r, &negone);
        secp256k1_scalar_mul(&l, &l, &r);
        secp256k1_scalar_add(&t2, &t2, &l);
    }

    /* t1 = (A - B)/2 */
    secp256k1_scalar_set_int(&tmps, 2);
    secp256k1_scalar_inverse_var(&tmps, &tmps);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&t1, &t1, &t2);
    secp256k1_scalar_mul(&t1, &t1, &tmps);

    /* t2 = -(-B + t0) + t1 */
    secp256k1_scalar_add(&t2, &t2, &t0);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&t2, &t2, &t1);

    /* Compute and output Ti = t_i*A + tau_i*G for i = 1 */
    secp256k1_ecmult_const(&gej, asset_genp, &t1, 256);
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_ecmult_gen(ecmult_gen_ctx, &gej, &tau1);
    secp256k1_gej_add_ge(&gej, &gej, &ge);
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_normalize_var(&ge.y);
    output[0] = secp256k1_fe_is_odd(&ge.y) << 1;
    secp256k1_fe_get_b32(&output[1], &ge.x);

    /* Compute and output Ti = t_i*A + tau_i*G for i = 2 */
    secp256k1_ecmult_const(&gej, asset_genp, &t2, 256);
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_ecmult_gen(ecmult_gen_ctx, &gej, &tau2);
    secp256k1_gej_add_ge(&gej, &gej, &ge);
    secp256k1_ge_set_gej(&ge, &gej);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_normalize_var(&ge.y);
    output[0] |= secp256k1_fe_is_odd(&ge.y);
    secp256k1_fe_get_b32(&output[33], &ge.x);

    /* get challenge x */
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, &prover_ctx->data[64], 32); /* y, which commits to all data from before this step */
    secp256k1_sha256_write(&sha256, output, 65);
    secp256k1_sha256_finalize(&sha256, &prover_ctx->data[0]);
    secp256k1_scalar_set_b32(&tmps, &prover_ctx->data[0], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&tmps)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 65);
        return 0;
    }

    /* Success */
    return 1;
}

/* Step 2 of the proof.
 * Only step to use the blinding factor of the commitment.
 * Outputs the scalars tau_x and mu, encoded in 64 bytes (tau_x first then mu).
 * Does not update the state except to zero it out if something goes wrong
 */
static int secp256k1_bulletproofs_rangeproof_uncompressed_prove_step2_impl(
    secp256k1_bulletproofs_prover_context* prover_ctx,
    unsigned char* output,
    const unsigned char* nonce,
    const secp256k1_scalar* blind,
    const secp256k1_scalar* enc_data
) {
    secp256k1_scalar alpha, rho;
    secp256k1_scalar tau1, tau2, taux, mu;
    secp256k1_scalar x, z, xsq, zsq;
    secp256k1_scalar tmps;
    int overflow;

    /* Recompute alpha, rho, tau1, tau2 */
    secp256k1_scalar_chacha20(&alpha, &rho, nonce, 0);
    secp256k1_scalar_add(&alpha, &alpha, enc_data);
    secp256k1_scalar_chacha20(&tau1, &tau2, nonce, 1);

    /* Extract challenges x and z */
    secp256k1_scalar_set_b32(&x, &prover_ctx->data[0], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 64);
        return 0;
    }
    secp256k1_scalar_mul(&xsq, &x, &x);

    secp256k1_scalar_set_b32(&z, &prover_ctx->data[64], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&z)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 64);
        return 0;
    }
    secp256k1_scalar_mul(&zsq, &z, &z);

    /* compute tau_x and mu */
    secp256k1_scalar_mul(&taux, &tau1, &x);
    secp256k1_scalar_mul(&tmps, &tau2, &xsq);
    secp256k1_scalar_add(&taux, &taux, &tmps);

    secp256k1_scalar_mul(&tmps, &zsq, blind);
    secp256k1_scalar_add(&taux, &taux, &tmps);

    secp256k1_scalar_mul(&mu, &rho, &x);
    secp256k1_scalar_add(&mu, &mu, &alpha);

    /* Negate taux and mu so the verifier doesn't have to */
    secp256k1_scalar_negate(&taux, &taux);
    secp256k1_scalar_negate(&mu, &mu);

    /* Success */
    secp256k1_scalar_get_b32(&output[0], &taux);
    secp256k1_scalar_get_b32(&output[32], &mu);
    return 1;
}

/* Step 3 of the proof. Should be called n_bits many times.
 * Only step to use the blinding factor of the commitment.
 * Outputs the scalars tau_x and mu, encoded in 64 bytes (tau_x first then mu).
 * Does not update the state.
 */
static int secp256k1_bulletproofs_rangeproof_uncompressed_prove_step3_impl(
    secp256k1_bulletproofs_prover_context* prover_ctx,
    unsigned char* output,
    size_t idx,
    const uint64_t value,
    const uint64_t min_value,
    const unsigned char* nonce
) {
    secp256k1_bulletproofs_bulletproofs_lrgen lr_gen;
    secp256k1_scalar x, y, z, l, r;
    int overflow;

    /* Extract challenges */
    secp256k1_scalar_set_b32(&x, &prover_ctx->data[0], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 64);
        return 0;
    }
    secp256k1_scalar_set_b32(&y, &prover_ctx->data[32], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&y)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 64);
        return 0;
    }
    secp256k1_scalar_set_b32(&z, &prover_ctx->data[64], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&z)) {
        memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
        memset(output, 0, 64);
        return 0;
    }

    /* Restore lrgen state */
    if (idx == 0) {
        secp256k1_bulletproofs_lrgen_init(&lr_gen, nonce, &y, &z, value - min_value);
    } else {
        if (!secp256k1_bulletproofs_lrgen_deserialize(&lr_gen, &prover_ctx->data[96], idx, nonce, &y, &z, value - min_value)) {
            memset(prover_ctx->data, 0, sizeof(prover_ctx->data));
            memset(output, 0, 64);
            return 0;
        }
    }

    /* Generate l(x) and r(x) */
    secp256k1_lr_generate(&lr_gen, &l, &r, &x);

    /* Success */
    secp256k1_bulletproofs_lrgen_serialize(&prover_ctx->data[96], &lr_gen);
    secp256k1_scalar_get_b32(&output[0], &l);
    secp256k1_scalar_get_b32(&output[32], &r);
    return 1;
}

#endif
