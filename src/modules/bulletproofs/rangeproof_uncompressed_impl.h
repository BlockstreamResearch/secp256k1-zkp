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

#endif
