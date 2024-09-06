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

static const unsigned char secp256k1_frost_keygen_cache_magic[4] = { 0x40, 0x25, 0x2e, 0x41 };

/* A tweak cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity. */
static void secp256k1_keygen_cache_save(secp256k1_frost_keygen_cache *cache, secp256k1_keygen_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, secp256k1_frost_keygen_cache_magic, 4);
    ptr += 4;
    secp256k1_ge_to_bytes(ptr, &cache_i->pk);
    ptr += 64;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, &cache_i->tweak);
}

static int secp256k1_keygen_cache_load(const secp256k1_context* ctx, secp256k1_keygen_cache_internal *cache_i, const secp256k1_frost_keygen_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_frost_keygen_cache_magic, 4) == 0);
    ptr += 4;
    secp256k1_ge_from_bytes(&cache_i->pk, ptr);
    ptr += 64;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    secp256k1_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

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

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_pubkey * const* pubshares;
    const unsigned char * const *ids33;
    size_t n_pubshares;
} secp256k1_frost_interpolate_pubkey_ecmult_data;

static int secp256k1_frost_evaluate_vss_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_evaluate_vss_ecmult_data *ctx = (secp256k1_frost_evaluate_vss_ecmult_data *) data;
    if (!secp256k1_pubkey_load(ctx->ctx, pt, &ctx->vss_commitment[idx])) {
        return 0;
    }
    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int secp256k1_frost_interpolate_pubkey_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_interpolate_pubkey_ecmult_data *ctx = (secp256k1_frost_interpolate_pubkey_ecmult_data *) data;
    secp256k1_scalar l;

    if (!secp256k1_pubkey_load(ctx->ctx, pt, ctx->pubshares[idx])) {
        return 0;
    }

    if (!secp256k1_frost_lagrange_coefficient(&l, ctx->ids33, ctx->n_pubshares, ctx->ids33[idx])) {
        return 0;
    }

    *sc = l;

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

int secp256k1_frost_pubkey_get(const secp256k1_context* ctx, secp256k1_pubkey *agg_pk, const secp256k1_frost_keygen_cache *keyagg_cache) {
    secp256k1_keygen_cache_internal cache_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(keyagg_cache != NULL);

    if(!secp256k1_keygen_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    secp256k1_pubkey_save(agg_pk, &cache_i.pk);
    return 1;
}

int secp256k1_frost_pubkey_gen(const secp256k1_context* ctx, secp256k1_frost_keygen_cache *cache, const secp256k1_pubkey * const *pubshares, size_t n_pubshares, const unsigned char * const *ids33) {
    secp256k1_gej pkj;
    secp256k1_frost_interpolate_pubkey_ecmult_data interpolate_pubkey_ecmult_data;
    secp256k1_keygen_cache_internal cache_i = { 0 };

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(cache != NULL);
    ARG_CHECK(pubshares != NULL);
    ARG_CHECK(ids33 != NULL);
    ARG_CHECK(n_pubshares > 1);

    interpolate_pubkey_ecmult_data.ctx = ctx;
    interpolate_pubkey_ecmult_data.pubshares = pubshares;
    interpolate_pubkey_ecmult_data.ids33 = ids33;
    interpolate_pubkey_ecmult_data.n_pubshares = n_pubshares;

    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_frost_interpolate_pubkey_ecmult_callback, (void *) &interpolate_pubkey_ecmult_data, n_pubshares)) {
        return 0;
    }
    secp256k1_ge_set_gej(&cache_i.pk, &pkj);
    secp256k1_keygen_cache_save(cache, &cache_i);

    return 1;
}

static int secp256k1_frost_pubkey_tweak_add_internal(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_keygen_cache *keygen_cache, const unsigned char *tweak32, int xonly) {
    secp256k1_keygen_cache_internal cache_i;
    int overflow = 0;
    secp256k1_scalar tweak;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(keygen_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }
    if (xonly && secp256k1_extrakeys_ge_even_y(&cache_i.pk)) {
        cache_i.parity_acc ^= 1;
        secp256k1_scalar_negate(&cache_i.tweak, &cache_i.tweak);
    }
    secp256k1_scalar_add(&cache_i.tweak, &cache_i.tweak, &tweak);
    if (!secp256k1_eckey_pubkey_tweak_add(&cache_i.pk, &tweak)) {
        return 0;
    }
    /* eckey_pubkey_tweak_add fails if cache_i.pk is infinity */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&cache_i.pk));
    secp256k1_keygen_cache_save(keygen_cache, &cache_i);
    if (output_pubkey != NULL) {
        secp256k1_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

int secp256k1_frost_pubkey_ec_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_keygen_cache *keygen_cache, const unsigned char *tweak32) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, keygen_cache, tweak32, 0);
}

int secp256k1_frost_pubkey_xonly_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_keygen_cache *keygen_cache, const unsigned char *tweak32) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, keygen_cache, tweak32, 1);
}

static int secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, const unsigned char * const *ids33, size_t n_participants, const unsigned char *my_id33) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar party_idx;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    if (!secp256k1_frost_compute_indexhash(&party_idx, my_id33)) {
        return 0;
    }
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar mul;

        if (!secp256k1_frost_compute_indexhash(&mul, ids33[i])) {
            return 0;
        }
        if (secp256k1_scalar_eq(&mul, &party_idx)) {
            continue;
        }

        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);
        secp256k1_scalar_add(&mul, &mul, &party_idx);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);

    return 1;
}

#endif
