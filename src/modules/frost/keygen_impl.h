/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_IMPL_H
#define SECP256K1_MODULE_FROST_KEYGEN_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "keygen.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"

/* Computes indexhash = tagged_hash(pk) */
static int secp256k1_frost_compute_indexhash(secp256k1_scalar *indexhash, const unsigned char *id33) {
    secp256k1_sha256 sha;
    unsigned char buf[32];

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/index", sizeof("FROST/index") - 1);
    secp256k1_sha256_write(&sha, id33, 33);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(indexhash, buf, NULL);
    /* The x-coordinate must not be zero (see
     * draft-irtf-cfrg-frost-08#section-4.2.2) */
    if (secp256k1_scalar_is_zero(indexhash)) {
        return 0;
    }

    return 1;
}

static const unsigned char secp256k1_frost_share_magic[4] = { 0xa1, 0x6a, 0x42, 0x03 };

static void secp256k1_frost_share_save(secp256k1_frost_share* share, secp256k1_scalar *s) {
    memcpy(&share->data[0], secp256k1_frost_share_magic, 4);
    secp256k1_scalar_get_b32(&share->data[4], s);
}

static int secp256k1_frost_share_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_frost_share* share) {
    int overflow;

    /* The magic is non-secret so it can be declassified to allow branching. */
    secp256k1_declassify(ctx, &share->data[0], 4);
    ARG_CHECK(secp256k1_memcmp_var(&share->data[0], secp256k1_frost_share_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &share->data[4], &overflow);
    /* Parsed shares cannot overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

int secp256k1_frost_share_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_frost_share* share) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(share != NULL);
    memcpy(out32, &share->data[4], 32);
    return 1;
}

int secp256k1_frost_share_parse(const secp256k1_context* ctx, secp256k1_frost_share* share, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(in32 != NULL);

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_frost_share_save(share, &tmp);
    return 1;
}

static void secp256k1_frost_derive_coeff(secp256k1_scalar *coeff, const unsigned char *polygen32, size_t i) {
    secp256k1_sha256 sha;
    unsigned char buf[32];

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/coeffgen", sizeof("FROST/coeffgen") - 1);
    secp256k1_sha256_write(&sha, polygen32, 32);
    secp256k1_write_be64(&buf[0], i);
    secp256k1_sha256_write(&sha, buf, 8);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(coeff, buf, NULL);
}

static int secp256k1_frost_vss_gen(const secp256k1_context *ctx, secp256k1_pubkey *vss_commitment, const unsigned char *polygen32, size_t threshold) {
    secp256k1_gej rj;
    secp256k1_ge rp;
    size_t i;
    int ret = 1;

    /* Compute commitment to each coefficient */
    for (i = 0; i < threshold; i++) {
        secp256k1_scalar coeff_i;

        secp256k1_frost_derive_coeff(&coeff_i, polygen32, i);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &coeff_i);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&vss_commitment[threshold - i - 1], &rp);
    }
    return ret;
}

static int secp256k1_frost_share_gen(secp256k1_frost_share *share, const unsigned char *polygen32, size_t threshold, const unsigned char *id33) {
    secp256k1_scalar idx;
    secp256k1_scalar share_i;
    size_t i;
    int ret = 1;

    /* Derive share */
    /* See RFC 9591, appendix C.1 */
    secp256k1_scalar_set_int(&share_i, 0);
    if (!secp256k1_frost_compute_indexhash(&idx, id33)) {
        return 0;
    }
    for (i = 0; i < threshold; i++) {
        secp256k1_scalar coeff_i;

        secp256k1_frost_derive_coeff(&coeff_i, polygen32, i);
        /* Horner's method to evaluate polynomial to derive shares */
        secp256k1_scalar_add(&share_i, &share_i, &coeff_i);
        if (i < threshold - 1) {
            secp256k1_scalar_mul(&share_i, &share_i, &idx);
        }
    }
    secp256k1_frost_share_save(share, &share_i);

    return ret;
}

int secp256k1_frost_shares_gen(const secp256k1_context *ctx, secp256k1_frost_share *shares, secp256k1_pubkey *vss_commitment, const unsigned char *seed32, size_t threshold, size_t n_participants, const unsigned char * const* ids33) {
    secp256k1_sha256 sha;
    unsigned char polygen[32];
    size_t i;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shares != NULL);
    for (i = 0; i < n_participants; i++) {
        memset(&shares[i], 0, sizeof(shares[i]));
    }
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(seed32 != NULL);
    ARG_CHECK(ids33 != NULL);
    ARG_CHECK(threshold > 1);
    ARG_CHECK(n_participants >= threshold);

    /* Commit to all inputs */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seed32, 32);
    secp256k1_write_be64(&polygen[0], threshold);
    secp256k1_write_be64(&polygen[8], n_participants);
    secp256k1_sha256_write(&sha, polygen, 16);
    for (i = 0; i < n_participants; i++) {
        secp256k1_sha256_write(&sha, ids33[i], 33);
    }
    secp256k1_sha256_finalize(&sha, polygen);

    ret &= secp256k1_frost_vss_gen(ctx, vss_commitment, polygen, threshold);

    for (i = 0; i < n_participants; i++) {
        ret &= secp256k1_frost_share_gen(&shares[i], polygen, threshold, ids33[i]);
    }

    return ret;
}

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey *vss_commitment;
} secp256k1_frost_evaluate_vss_ecmult_data;

static int secp256k1_frost_evaluate_vss_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_evaluate_vss_ecmult_data *ctx = (secp256k1_frost_evaluate_vss_ecmult_data *) data;
    if (!secp256k1_pubkey_load(ctx->ctx, pt, &ctx->vss_commitment[idx])) {
        return 0;
    }
    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int secp256k1_frost_evaluate_vss(const secp256k1_context* ctx, secp256k1_gej *share, size_t threshold, const unsigned char *id33, const secp256k1_pubkey *vss_commitment) {
    secp256k1_frost_evaluate_vss_ecmult_data evaluate_vss_ecmult_data;

    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    /* Use an EC multi-multiplication to verify the following equation:
     *   0 = - share_i*G + idx^0*vss_commitment[0]
     *                   + ...
     *                   + idx^(threshold - 1)*vss_commitment[threshold - 1]*/
    evaluate_vss_ecmult_data.ctx = ctx;
    evaluate_vss_ecmult_data.vss_commitment = vss_commitment;
    /* Evaluate the public polynomial at the idx */
    if (!secp256k1_frost_compute_indexhash(&evaluate_vss_ecmult_data.idx, id33)) {
        return 0;
    }
    secp256k1_scalar_set_int(&evaluate_vss_ecmult_data.idxn, 1);
    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, share, NULL, secp256k1_frost_evaluate_vss_ecmult_callback, (void *) &evaluate_vss_ecmult_data, threshold)) {
        return 0;
    }

    return 1;
}

/* See RFC 9591, appendix C.2 */
int secp256k1_frost_share_verify(const secp256k1_context* ctx, size_t threshold, const unsigned char *id33, const secp256k1_frost_share *share, const secp256k1_pubkey *vss_commitment) {
    secp256k1_scalar share_i;
    secp256k1_scalar share_neg;
    secp256k1_gej tmpj, snj;
    secp256k1_ge sng;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(id33 != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(threshold > 1);

    if (!secp256k1_frost_share_load(ctx, &share_i, share)) {
        return 0;
    }

    if (!secp256k1_frost_evaluate_vss(ctx, &tmpj, threshold, id33, vss_commitment)) {
        return 0;
    }

    secp256k1_scalar_negate(&share_neg, &share_i);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &snj, &share_neg);
    secp256k1_ge_set_gej(&sng, &snj);
    secp256k1_gej_add_ge(&tmpj, &tmpj, &sng);
    return secp256k1_gej_is_infinity(&tmpj);
}

/* See RFC 9591, appendix C.2 */
int secp256k1_frost_compute_pubshare(const secp256k1_context* ctx, secp256k1_pubkey *pubshare, size_t threshold, const unsigned char *id33, const secp256k1_pubkey *vss_commitment) {
    secp256k1_gej pkj;
    secp256k1_ge tmp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubshare != NULL);
    memset(pubshare, 0, sizeof(*pubshare));
    ARG_CHECK(id33 != NULL);
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(threshold > 1);

    if (!secp256k1_frost_evaluate_vss(ctx, &pkj, threshold, id33, vss_commitment)) {
        return 0;
    }
    secp256k1_ge_set_gej(&tmp, &pkj);
    secp256k1_pubkey_save(pubshare, &tmp);

    return 1;
}

#endif
