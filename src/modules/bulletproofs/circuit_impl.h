/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_CIRCUIT_IMPL
#define SECP256K1_MODULE_BULLETPROOF_CIRCUIT_IMPL

#include "modules/bulletproofs/inner_product_impl.h"
#include "modules/bulletproofs/util.h"
#include "group.h"

#include <stdlib.h>

typedef struct {
    secp256k1_scalar x;
    secp256k1_scalar x2;
    const secp256k1_bulletproof_circuit_assignment *assn;
    const secp256k1_bulletproof_pf_compressed_circuit *comp_circ;
} secp256k1_bulletproof_circuit_abgh_data;

static int secp256k1_bulletproof_circuit_abgh_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_circuit_abgh_data *ctx = (secp256k1_bulletproof_circuit_abgh_data *) data;
    const int is_g = idx % 2 == 0;

    (void) pt;
    if (is_g) {
        /* l(x) */
        if (idx / 2 < ctx->assn->n_gates) {
            secp256k1_scalar_mul(sc, &ctx->comp_circ->l3[idx / 2], &ctx->x);
            secp256k1_scalar_add(sc, sc, &ctx->assn->ao[idx / 2]);
            secp256k1_scalar_mul(sc, sc, &ctx->x);
        } else {
            secp256k1_scalar_mul(sc, &ctx->comp_circ->l3[idx / 2], &ctx->x2);
        }
        secp256k1_scalar_add(sc, sc, &ctx->comp_circ->l1[idx / 2]);
        secp256k1_scalar_mul(sc, sc, &ctx->x);
    } else {
        /* r(x) */
        secp256k1_scalar_mul(sc, &ctx->comp_circ->r3[idx / 2], &ctx->x2);
        secp256k1_scalar_add(sc, sc, &ctx->comp_circ->r1[idx / 2]);
        secp256k1_scalar_mul(sc, sc, &ctx->x);
        secp256k1_scalar_add(sc, sc, &ctx->comp_circ->r0[idx / 2]);
    }

    return 1;
}

/* Proof format:
 *
 * Serialized scalars (32 bytes) t, tau_x, mu, a, b
 * Serialized points (bit array of parity followed by 32 bytes): A_I, A_O, S, T_1, T_3, T_4, T_5, T_6, [inner product proof points]
 */
static int secp256k1_bulletproof_relation66_prove_impl(const secp256k1_ecmult_context *ecmult_ctx, secp256k1_scratch *scratch, unsigned char *proof, size_t *plen, const secp256k1_bulletproof_circuit_assignment *assn, const secp256k1_ge *commitp, const secp256k1_scalar *blinds, size_t nc, const secp256k1_ge *value_gen, const secp256k1_bulletproof_circuit *circ, const secp256k1_bulletproof_generators *gens, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len) {
    secp256k1_bulletproof_pf_compressed_circuit *comp_circ;
    secp256k1_bulletproof_circuit_abgh_data abgh_data;
    secp256k1_sha256 sha256;
    unsigned char commit[32] = {0};
    secp256k1_scalar alpha, beta, rho, mu;
    secp256k1_scalar tau1, tau3, tau4, tau5, tau6, taux; /* tau2 missing on purpose */
    secp256k1_scalar t[7];  /* t[1..6] are coefficients; t[0] is the polynomial evaluated at x */
    secp256k1_scalar tauv;  /* <z, WV*gamma> term in eq (73) */
    secp256k1_scalar x, xn, y, yinv, z;
    secp256k1_scalar tmp;
    secp256k1_gej aij, aoj, sj;
    secp256k1_ge tmpge;
    secp256k1_ge out_pt[8];
    int overflow;
    size_t i;

    if (assn->n_gates > circ->n_gates || assn->n_commits > circ->n_commits || nc != circ->n_commits) {
        return 0;
    }
    if (*plen < 64 + 256 + 1) {  /* inner product argument will do a more precise check and assignment */
        return 0;
    }

    /* Commit to all input data */
    if (nc != 0) {
        secp256k1_bulletproof_update_commit_n(commit, commitp, nc);
    }
    secp256k1_bulletproof_update_commit_n(commit, value_gen, 1);
    /* TODO commit to circuit */
    if (extra_commit != NULL) {
        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, commit, 32);
        secp256k1_sha256_write(&sha256, extra_commit, extra_commit_len);
        secp256k1_sha256_finalize(&sha256, commit);
    }

    /* Setup, generate randomness */
    secp256k1_scalar_chacha20(&alpha, &beta, nonce, 0);
    secp256k1_scalar_chacha20(&rho, &tau1, nonce, 1);
    secp256k1_scalar_chacha20(&tau3, &tau4, nonce, 2); /* t2 will be generated deterministically */
    secp256k1_scalar_chacha20(&tau5, &tau6, nonce, 3);

    /* Compute blinding factors in comp_circ.l3 and comp_circ.r3 */
    if (!secp256k1_bulletproof_pf_compressed_circuit_allocate_frame(scratch, circ)) {
        return 0;
    }
    comp_circ = secp256k1_bulletproof_pf_slsr(scratch, circ, nonce);

    /* Compute A_I, A_O, S */
    secp256k1_ecmult_const(&aij, gens->blinding_gen, &alpha, 256);
    for (i = 0; i < circ->n_bits; i++) {
        secp256k1_ge aterm = gens->gens[i + gens->n/2];

        secp256k1_ge_neg(&aterm, &aterm);
        secp256k1_fe_cmov(&aterm.x, &gens->gens[i].x, secp256k1_scalar_is_one(&assn->al[i]));
        secp256k1_fe_cmov(&aterm.y, &gens->gens[i].y, secp256k1_scalar_is_one(&assn->al[i]));
        secp256k1_gej_add_ge(&aij, &aij, &aterm);
    }
    secp256k1_ge_set_gej(&tmpge, &aij);
    secp256k1_bulletproof_vector_commit(&aij, assn->al + circ->n_bits, gens->gens + circ->n_bits, assn->n_gates - circ->n_bits, NULL, NULL);
    secp256k1_gej_add_ge(&aij, &aij, &tmpge);
    secp256k1_ge_set_gej(&tmpge, &aij);
    secp256k1_bulletproof_vector_commit(&aij, assn->ar + circ->n_bits, gens->gens + circ->n_bits + gens->n/2, assn->n_gates - circ->n_bits, NULL, NULL);
    secp256k1_gej_add_ge(&aij, &aij, &tmpge);

    secp256k1_bulletproof_vector_commit(&aoj, assn->ao + circ->n_bits, gens->gens + circ->n_bits, assn->n_gates - circ->n_bits, &beta, gens->blinding_gen);

    secp256k1_ecmult_const(&sj, gens->blinding_gen, &rho, 256);
    for (i = 0; i < circ->n_gates; i++) {
        secp256k1_gej termj;
        secp256k1_ge term;

        secp256k1_ecmult_const(&termj, &gens->gens[i], &comp_circ->l3[i], 256);
        secp256k1_ge_set_gej(&term, &termj);
        secp256k1_gej_add_ge(&sj, &sj, &term);
        secp256k1_ecmult_const(&termj, &gens->gens[i + gens->n/2], &comp_circ->r3[i], 256);
        secp256k1_ge_set_gej(&term, &termj);
        secp256k1_gej_add_ge(&sj, &sj, &term);
    }

    /* get challenges y and z */
    secp256k1_ge_set_gej(&out_pt[0], &aij);
    secp256k1_ge_set_gej(&out_pt[1], &aoj);
    secp256k1_ge_set_gej(&out_pt[2], &sj);

    secp256k1_bulletproof_update_commit_n(commit, &out_pt[0], 3);
    secp256k1_scalar_set_b32(&y, commit, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&y)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }
    secp256k1_bulletproof_update_commit_n(commit, NULL, 0);
    secp256k1_scalar_set_b32(&z, commit, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&z)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }
    secp256k1_scalar_inverse_var(&yinv, &y);

    /* complete circuit compression */
    secp256k1_bulletproof_pf_compress_circuit(comp_circ, circ, assn, &y, &yinv, &z);

    /* Compute coefficients t[1..6] */
    /* Observe that
     *   l = l1 * X          + l2 * X^2 + l3 * X^3
     *   r = r0     + r1 * X            + r3 * X^3
     * with l2 = ao, so that
     *   t1 = <l1, r0>
     *   t2 = <l1, r1> + <ao, r0>
     *   t3 = <ao, r1> + <l3, r0>
     *   t4 = <l3, r1> + <l1, r3>
     *   t5 = <ao, r3>
     *   t6 = <l3, r3>
     * So we compute these terms and add them to t1,t3,etc as running sums.
     */

    for (i = 0; i < 6; i++) {
        secp256k1_scalar_clear(&t[i + 1]);
    }
    for (i = 0; i < circ->n_gates; i++) {
        secp256k1_scalar ao;

        if (i < assn->n_gates) {
            ao = assn->ao[i];
        } else {
            secp256k1_scalar_clear(&ao);
        }

        /* Now that we have the individual coefficients, compute the dot product */
        secp256k1_scalar_mul(&tmp, &comp_circ->l1[i], &comp_circ->r0[i]);
        secp256k1_scalar_add(&t[1], &t[1], &tmp);

        secp256k1_scalar_mul(&tmp, &comp_circ->l1[i], &comp_circ->r1[i]);
        secp256k1_scalar_add(&t[2], &t[2], &tmp);
        secp256k1_scalar_mul(&tmp, &ao, &comp_circ->r0[i]);
        secp256k1_scalar_add(&t[2], &t[2], &tmp);

        secp256k1_scalar_mul(&tmp, &ao, &comp_circ->r1[i]);
        secp256k1_scalar_add(&t[3], &t[3], &tmp);
        secp256k1_scalar_mul(&tmp, &comp_circ->l3[i], &comp_circ->r0[i]);
        secp256k1_scalar_add(&t[3], &t[3], &tmp);

        secp256k1_scalar_mul(&tmp, &comp_circ->l3[i], &comp_circ->r1[i]);
        secp256k1_scalar_add(&t[4], &t[4], &tmp);
        secp256k1_scalar_mul(&tmp, &comp_circ->l1[i], &comp_circ->r3[i]);
        secp256k1_scalar_add(&t[4], &t[4], &tmp);

        secp256k1_scalar_mul(&tmp, &ao, &comp_circ->r3[i]);
        secp256k1_scalar_add(&t[5], &t[5], &tmp);

        secp256k1_scalar_mul(&tmp, &comp_circ->l3[i], &comp_circ->r3[i]);
        secp256k1_scalar_add(&t[6], &t[6], &tmp);
    }

    /* Compute T1, T3, T4, T5, T6 */
    secp256k1_bulletproof_vector_commit(&aij, &t[1], value_gen, 1, &tau1, gens->blinding_gen);
    secp256k1_ge_set_gej(&out_pt[3], &aij);

    secp256k1_bulletproof_vector_commit(&aij, &t[3], value_gen, 1, &tau3, gens->blinding_gen);
    secp256k1_ge_set_gej(&out_pt[4], &aij);

    secp256k1_bulletproof_vector_commit(&aij, &t[4], value_gen, 1, &tau4, gens->blinding_gen);
    secp256k1_ge_set_gej(&out_pt[5], &aij);

    secp256k1_bulletproof_vector_commit(&aij, &t[5], value_gen, 1, &tau5, gens->blinding_gen);
    secp256k1_ge_set_gej(&out_pt[6], &aij);

    secp256k1_bulletproof_vector_commit(&aij, &t[6], value_gen, 1, &tau6, gens->blinding_gen);
    secp256k1_ge_set_gej(&out_pt[7], &aij);

    /* Compute x, tau_x, mu and t */
    secp256k1_bulletproof_update_commit_n(commit, &out_pt[3], 5);
    secp256k1_scalar_set_b32(&x, commit, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }

    secp256k1_scalar_mul(&alpha, &alpha, &x);
    secp256k1_scalar_mul(&tau1, &tau1, &x);

    secp256k1_scalar_sqr(&xn, &x);
    secp256k1_scalar_mul(&beta, &beta, &xn);
    secp256k1_scalar_clear(&tauv);
    for (i = 0; i < circ->n_commits; i++) {
        secp256k1_scalar zwv;
        secp256k1_scalar_mul(&zwv, &comp_circ->wv[i], &blinds[i]);
        secp256k1_scalar_add(&tauv, &tauv, &zwv);
    }
    secp256k1_scalar_mul(&tauv, &tauv, &xn);

    secp256k1_scalar_mul(&xn, &xn, &x);
    secp256k1_scalar_mul(&rho, &rho, &xn);
    secp256k1_scalar_mul(&tau3, &tau3, &xn);

    secp256k1_scalar_mul(&xn, &xn, &x);
    secp256k1_scalar_mul(&tau4, &tau4, &xn);

    secp256k1_scalar_mul(&xn, &xn, &x);
    secp256k1_scalar_mul(&tau5, &tau5, &xn);

    secp256k1_scalar_mul(&xn, &xn, &x);
    secp256k1_scalar_mul(&tau6, &tau6, &xn);

    secp256k1_scalar_add(&taux, &tau1, &tauv);
    secp256k1_scalar_add(&taux, &taux, &tau3);
    secp256k1_scalar_add(&taux, &taux, &tau4);
    secp256k1_scalar_add(&taux, &taux, &tau5);
    secp256k1_scalar_add(&taux, &taux, &tau6);

    secp256k1_scalar_add(&mu, &alpha, &beta);
    secp256k1_scalar_add(&mu, &mu, &rho);

    /* Negate taux and mu so verifier doesn't have to */
    secp256k1_scalar_negate(&mu, &mu);
    secp256k1_scalar_negate(&taux, &taux);

    /* Encode circuit stuff */
    secp256k1_scalar_get_b32(&proof[0], &taux);
    secp256k1_scalar_get_b32(&proof[32], &mu);
    secp256k1_bulletproof_serialize_points(&proof[64], out_pt, 8);

    /* Mix these scalars into the hash so the input to the inner product proof is fixed */
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_write(&sha256, proof, 64);
    secp256k1_sha256_finalize(&sha256, commit);

    /* Compute l and r, do inner product proof */
    abgh_data.x = x;
    secp256k1_scalar_sqr(&abgh_data.x2, &x);
    abgh_data.comp_circ = comp_circ;
    abgh_data.assn = assn;
    *plen -= 64 + 256 + 1;
    if (secp256k1_bulletproof_inner_product_prove_impl(ecmult_ctx, scratch, &proof[64 + 256 + 1], plen, gens, &yinv, circ->n_gates, secp256k1_bulletproof_circuit_abgh_callback, (void *) &abgh_data, commit) == 0) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }
    *plen += 64 + 256 + 1;

    secp256k1_scratch_deallocate_frame(scratch);
    return 1;
}

typedef struct  {
    secp256k1_scalar x;
    secp256k1_scalar y;
    secp256k1_scalar yinv;
    secp256k1_scalar z;
    const secp256k1_bulletproof_vfy_compressed_circuit *comp_circ;
    /* state tracking */
    size_t count;
    /* eq 83 */
    secp256k1_ge age[3];
    /* eq 82 */
    secp256k1_scalar randomizer82;
    secp256k1_ge tge[5];
    secp256k1_scalar t;
    const secp256k1_ge *value_gen;
    const secp256k1_ge *commits;
    size_t n_gates;
    size_t n_commits;
} secp256k1_bulletproof_circuit_vfy_ecmult_context;

static int secp256k1_bulletproof_circuit_vfy_callback(secp256k1_scalar *sc, secp256k1_ge *pt, secp256k1_scalar *randomizer, size_t idx, void *data) {
    secp256k1_bulletproof_circuit_vfy_ecmult_context *ctx = (secp256k1_bulletproof_circuit_vfy_ecmult_context *) data;

    if (idx < ctx->n_gates) { /* Gi */
        secp256k1_scalar_mul(sc, &ctx->comp_circ->wr[idx], &ctx->x);
        secp256k1_scalar_mul(sc, sc, randomizer);
    } else if (idx < 2 * ctx->n_gates) { /* Hi */
        secp256k1_scalar dot;
        idx -= ctx->n_gates;

        secp256k1_scalar_set_int(&dot, 1);
        secp256k1_scalar_negate(&dot, &dot);
        secp256k1_scalar_add(sc, &ctx->comp_circ->wl_wo[idx], &dot);

        secp256k1_scalar_mul(sc, sc, randomizer);
    /* return a (scalar, point) pair to add to the multiexp */
    } else {
        switch(ctx->count) {
        /* g^(x^2(k + <z^Q, c>) - t) (82) */
        case 0: {
            secp256k1_scalar_negate(sc, &ctx->t);
            secp256k1_scalar_add(sc, sc, &ctx->comp_circ->c_sum);
            secp256k1_scalar_mul(sc, sc, &ctx->randomizer82);
            *pt = *ctx->value_gen;
            break;
        }
        /* A_I^x (83) */
        case 1:
            *sc = ctx->x;
            *pt = ctx->age[0];
            break;
        /* A_O^(x^2) (83) */
        case 2:
            secp256k1_scalar_sqr(sc, &ctx->x);
            *pt = ctx->age[1];
            break;
        /* S^(x^3) (83) */
        case 3:
            secp256k1_scalar_sqr(sc, &ctx->x); /* TODO cache previous squaring */
            secp256k1_scalar_mul(sc, sc, &ctx->x);
            *pt = ctx->age[2];
            break;
        /* T_1^x (82) */
        case 4:
            secp256k1_scalar_mul(sc, &ctx->x, &ctx->randomizer82);
            *pt = ctx->tge[0];
            break;
        default:
            if (ctx->count < 9) {
                size_t i;
                secp256k1_scalar_mul(sc, &ctx->x, &ctx->randomizer82);
                for (i = 0; i < ctx->count - 3; i++) {
                    secp256k1_scalar_mul(sc, sc, &ctx->x);
                }
                *pt = ctx->tge[ctx->count - 4];
            } else if (ctx->count < 9 + ctx->n_commits) {
                /* V^(x^2 . (z^Q . W_V)) (82) */
                secp256k1_scalar_mul(sc, &ctx->comp_circ->wv[ctx->count - 9], &ctx->randomizer82);
                *pt = ctx->commits[ctx->count - 9];
            } else {
                VERIFY_CHECK(!"bulletproof: too many points added by circuit_verify_impl to inner_product_verify_impl");
            }
        }
        secp256k1_scalar_mul(sc, sc, randomizer);
        ctx->count++;
    }
    return 1;
}

static int secp256k1_bulletproof_relation66_verify_impl(const secp256k1_ecmult_context *ecmult_ctx, secp256k1_scratch *scratch, const unsigned char* const* proof, size_t n_proofs, size_t plen, const secp256k1_ge* const* commitp, size_t *nc, const secp256k1_ge *value_gen, const secp256k1_bulletproof_circuit* const* circ, const secp256k1_bulletproof_generators *gens, const unsigned char **extra_commit, size_t *extra_commit_len) {
    int ret;
    secp256k1_bulletproof_circuit_vfy_ecmult_context *ecmult_data;
    secp256k1_bulletproof_innerproduct_context *innp_ctx;
    size_t i;

    /* sanity-check input */
    if (plen < 64 + 256 + 1) {  /* inner product argument will do a more precise check */
        return 0;
    }
    if (plen > SECP256K1_BULLETPROOF_MAX_PROOF) {
        return 0;
    }

    if (!secp256k1_scratch_allocate_frame(scratch, n_proofs * (sizeof(*ecmult_data) + sizeof(*innp_ctx)), 2)) {
        return 0;
    }
    ecmult_data = (secp256k1_bulletproof_circuit_vfy_ecmult_context *)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*ecmult_data));
    innp_ctx = (secp256k1_bulletproof_innerproduct_context *)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*innp_ctx));
    if (!secp256k1_bulletproof_vfy_compressed_circuit_allocate_frame(scratch, circ[0], n_proofs)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }

    for (i = 0; i < n_proofs; i++) {
        secp256k1_sha256 sha256;
        unsigned char randomizer82[32] = {0};  /* randomizer for eq (82) so we can add it to eq (83) to save a separate multiexp */
        unsigned char commit[32] = {0};
        secp256k1_scalar taux, mu;
        secp256k1_scalar y;
        int overflow;

        /* Commit to all input data: pedersen commit, asset generator, extra_commit */
        if (nc != NULL) {
            secp256k1_bulletproof_update_commit_n(commit, commitp[i], nc[i]);
        }
        secp256k1_bulletproof_update_commit_n(commit, value_gen, 1);
        if (extra_commit != NULL && extra_commit[i] != NULL) {
            secp256k1_sha256_initialize(&sha256);
            secp256k1_sha256_write(&sha256, commit, 32);
            secp256k1_sha256_write(&sha256, extra_commit[i], extra_commit_len[i]);
            secp256k1_sha256_finalize(&sha256, commit);
        }

        /* Deserialize everything */
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].age[0], &proof[i][64], 0, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].age[1], &proof[i][64], 1, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].age[2], &proof[i][64], 2, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].tge[0], &proof[i][64], 3, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].tge[1], &proof[i][64], 4, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].tge[2], &proof[i][64], 5, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].tge[3], &proof[i][64], 6, 8);
        secp256k1_bulletproof_deserialize_point(&ecmult_data[i].tge[4], &proof[i][64], 7, 8);

        /* Compute y, z, x */
        secp256k1_bulletproof_update_commit_n(commit, ecmult_data[i].age, 3);
        secp256k1_scalar_set_b32(&y, commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&y)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        ecmult_data[i].y = y;
        secp256k1_scalar_inverse_var(&ecmult_data[i].yinv, &y);  /* TODO batch this into another inverse */
        secp256k1_bulletproof_update_commit_n(commit, NULL, 0);
        secp256k1_scalar_set_b32(&ecmult_data[i].z, commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&ecmult_data[i].z)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }

        secp256k1_bulletproof_update_commit_n(commit, ecmult_data[i].tge, 5);
        secp256k1_scalar_set_b32(&ecmult_data[i].x, commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&ecmult_data[i].x)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }

        ecmult_data[i].comp_circ = secp256k1_bulletproof_vfy_compress_circuit(scratch, circ[i], &ecmult_data[i].x, &ecmult_data[i].y, &ecmult_data[i].yinv, &ecmult_data[i].z);

        /* Extract scalars */
        secp256k1_scalar_set_b32(&taux, &proof[i][0], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&taux)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        secp256k1_scalar_set_b32(&mu, &proof[i][32], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&mu)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        /* A little sketchy, we read t (l(x) . r(x)) off the front of the inner product proof,
         * which we otherwise treat as a black box */
        secp256k1_scalar_set_b32(&ecmult_data[i].t, &proof[i][64 + 256 + 1], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&ecmult_data[i].t)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }

        /* Mix these scalars into the hash so the input to the inner product proof is fixed */
        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, commit, 32);
        secp256k1_sha256_write(&sha256, proof[i], 64);
        secp256k1_sha256_finalize(&sha256, commit);

        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, commit, 32);
        secp256k1_sha256_finalize(&sha256, randomizer82);
        secp256k1_scalar_set_b32(&ecmult_data[i].randomizer82, randomizer82, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&ecmult_data[i].randomizer82)) {
            secp256k1_scratch_deallocate_frame(scratch);
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }

        /* compute exponent offsets */
        ecmult_data[i].count = 0;

        ecmult_data[i].value_gen = value_gen;
        if (nc == NULL) {
            ecmult_data[i].commits = NULL;
        } else {
            ecmult_data[i].commits = commitp[i];
        }
        ecmult_data[i].n_gates = circ[i]->n_gates;
        if (nc == NULL) {
            ecmult_data[i].n_commits = 0;
        } else {
            ecmult_data[i].n_commits = nc[i];
        }

        secp256k1_scalar_mul(&taux, &taux, &ecmult_data[i].randomizer82);
        secp256k1_scalar_add(&mu, &mu, &taux);

        innp_ctx[i].proof = &proof[i][64 + 256 + 1];
        innp_ctx[i].p_offs = mu;
        innp_ctx[i].yinv = ecmult_data[i].yinv;
        memcpy(innp_ctx[i].commit, commit, 32);
        innp_ctx[i].rangeproof_cb = secp256k1_bulletproof_circuit_vfy_callback;
        innp_ctx[i].rangeproof_cb_data = (void *) &ecmult_data[i];
        innp_ctx[i].n_extra_rangeproof_points = 9 + ecmult_data[i].n_commits;
    }
    ret = secp256k1_bulletproof_inner_product_verify_impl(ecmult_ctx, scratch, gens, circ[0]->n_gates, innp_ctx, n_proofs, plen - (64 + 256 + 1), 1);
    secp256k1_scratch_deallocate_frame(scratch);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

#endif
