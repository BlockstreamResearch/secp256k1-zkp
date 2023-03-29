/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
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

static const unsigned char secp256k1_frost_tweak_cache_magic[4] = { 0x40, 0x25, 0x2e, 0x41 };

/* A tweak cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity. */
static void secp256k1_tweak_cache_save(secp256k1_frost_tweak_cache *cache, secp256k1_tweak_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, secp256k1_frost_tweak_cache_magic, 4);
    ptr += 4;
    secp256k1_point_save(ptr, &cache_i->pk);
    ptr += 64;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, &cache_i->tweak);
}

static int secp256k1_tweak_cache_load(const secp256k1_context* ctx, secp256k1_tweak_cache_internal *cache_i, const secp256k1_frost_tweak_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_frost_tweak_cache_magic, 4) == 0);
    ptr += 4;
    secp256k1_point_load(&cache_i->pk, ptr);
    ptr += 64;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    secp256k1_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Computes indexhash = tagged_hash(pk || idx) */
static int secp256k1_frost_compute_indexhash(const secp256k1_context *ctx, secp256k1_scalar *indexhash, const secp256k1_xonly_pubkey *pk) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    const unsigned char zerobyte[1] = { 0 };

    if (!secp256k1_xonly_pubkey_serialize(ctx, buf, pk)) {
        return 0;
    }
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/index", sizeof("FROST/index") - 1);
    secp256k1_sha256_write(&sha, buf, sizeof(buf));
    /* TODO: add sub_indices for weights > 1 */
    secp256k1_sha256_write(&sha, zerobyte, 1);
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

int secp256k1_frost_share_gen(const secp256k1_context *ctx, secp256k1_pubkey *vss_commitment, secp256k1_frost_share *share, const unsigned char *session_id, const secp256k1_keypair *keypair, const secp256k1_xonly_pubkey *recipient_pk, size_t threshold) {
    secp256k1_sha256 sha;
    secp256k1_scalar idx;
    secp256k1_scalar sk;
    secp256k1_scalar share_i;
    secp256k1_ge sender_pk;
    unsigned char buf[32];
    unsigned char rngseed[32];
    secp256k1_scalar rand[2];
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(share != NULL);
    memset(share, 0, sizeof(*share));
    ARG_CHECK(session_id != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(recipient_pk != NULL);
    ARG_CHECK(threshold > 1);

    if (!secp256k1_keypair_load(ctx, &sk, &sender_pk, keypair)) {
        return 0;
    }
    /* The first coefficient is the secret key, and thus the first commitment
     * is the public key. */
    if (vss_commitment != NULL) {
        secp256k1_pubkey_save(&vss_commitment[0], &sender_pk);
    }
    /* Compute seed which commits to threshold and session ID */
    secp256k1_scalar_get_b32(buf, &sk);
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, session_id, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i] = threshold / (1ull << (i * 8));
    }
    secp256k1_sha256_write(&sha, rngseed, 8);
    secp256k1_sha256_finalize(&sha, rngseed);

    /* Derive share */
    /* See draft-irtf-cfrg-frost-08#appendix-C.1 */
    secp256k1_scalar_clear(&share_i);
    if (!secp256k1_frost_compute_indexhash(ctx, &idx, recipient_pk)) {
        return 0;
    }
    for (i = 0; i < threshold - 1; i++) {
        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        /* Horner's method to evaluate polynomial to derive shares */
        secp256k1_scalar_add(&share_i, &share_i, &rand[i % 2]);
        secp256k1_scalar_mul(&share_i, &share_i, &idx);
        /* Derive coefficients commitments from the seed */
        if (vss_commitment != NULL) {
            secp256k1_gej rj;
            secp256k1_ge rp;

            /* Compute commitment to each coefficient */
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
            secp256k1_ge_set_gej(&rp, &rj);
            secp256k1_pubkey_save(&vss_commitment[threshold - i - 1], &rp);
        }
    }
    secp256k1_scalar_add(&share_i, &share_i, &sk);
    secp256k1_frost_share_save(share, &share_i);

    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("VSS list")||SHA256("VSS list"). */
static void secp256k1_frost_vsslist_sha256(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x3c261fccul;
    sha->s[1] = 0xeeec1555ul;
    sha->s[2] = 0x6bb6cfc8ul;
    sha->s[3] = 0x678ade57ul;
    sha->s[4] = 0xfb4b11f9ul;
    sha->s[5] = 0x9627b131ul;
    sha->s[6] = 0xbf978156ul;
    sha->s[7] = 0xfc1263cdul;
    sha->bytes = 64;
}

/* Computes vss_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int secp256k1_frost_compute_vss_hash(const secp256k1_context *ctx, unsigned char *vss_hash, const secp256k1_pubkey * const* pk, size_t np, size_t t) {
    secp256k1_sha256 sha;
    size_t i, j;
    size_t size = 33;

    secp256k1_frost_vsslist_sha256(&sha);
    for (i = 0; i < np; i++) {
        for (j = 0; j < t; j++) {
            unsigned char ser[33];
            if (!secp256k1_ec_pubkey_serialize(ctx, ser, &size, &pk[i][j], SECP256K1_EC_COMPRESSED)) {
                return 0;
            }
            secp256k1_sha256_write(&sha, ser, 33);
        }
    }
    secp256k1_sha256_finalize(&sha, vss_hash);

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey * const* vss_commitment;
} secp256k1_frost_verify_share_ecmult_data;

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey * const* vss_commitments;
    size_t threshold;
} secp256k1_frost_compute_pubshare_ecmult_data;

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_pubkey * const* pks;
    size_t threshold;
} secp256k1_frost_pubkey_combine_ecmult_data;

static int secp256k1_frost_verify_share_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_verify_share_ecmult_data *ctx = (secp256k1_frost_verify_share_ecmult_data *) data;
    if (!secp256k1_pubkey_load(ctx->ctx, pt, *(ctx->vss_commitment)+idx)) {
        return 0;
    }
    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int secp256k1_frost_compute_pubshare_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_compute_pubshare_ecmult_data *ctx = (secp256k1_frost_compute_pubshare_ecmult_data *) data;

    if (!secp256k1_pubkey_load(ctx->ctx, pt, &ctx->vss_commitments[idx/ctx->threshold][idx % ctx->threshold])) {
        return 0;
    }
    if (idx != 0 && idx % ctx->threshold == 0) {
        secp256k1_scalar_set_int(&ctx->idxn, 1);
    }
    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int secp256k1_frost_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;

    secp256k1_scalar_set_int(sc, 1);
    /* the public key is the first index of each set of coefficients */
    return secp256k1_pubkey_load(ctx->ctx, pt, &ctx->pks[idx][0]);
}

/* See draft-irtf-cfrg-frost-08#appendix-C.2 */
static int secp256k1_frost_vss_verify_internal(const secp256k1_context* ctx, size_t threshold, const secp256k1_xonly_pubkey *pk, const secp256k1_scalar *share, const secp256k1_pubkey * const* vss_commitment) {
    secp256k1_scalar share_neg;
    secp256k1_gej tmpj;
    secp256k1_frost_verify_share_ecmult_data verify_share_ecmult_data;

    /* Use an EC multi-multiplication to verify the following equation:
     *   0 = - share_i*G + idx^0*vss_commitment[0]
     *                   + ...
     *                   + idx^(threshold - 1)*vss_commitment[threshold - 1]*/
    verify_share_ecmult_data.ctx = ctx;
    verify_share_ecmult_data.vss_commitment = vss_commitment;
    /* Evaluate the public polynomial at the idx */
    if (!secp256k1_frost_compute_indexhash(ctx, &verify_share_ecmult_data.idx, pk)) {
        return 0;
    }
    secp256k1_scalar_set_int(&verify_share_ecmult_data.idxn, 1);
    secp256k1_scalar_negate(&share_neg, share);
    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &tmpj, &share_neg, secp256k1_frost_verify_share_ecmult_callback, (void *) &verify_share_ecmult_data, threshold)) {
        return 0;
    }
    return secp256k1_gej_is_infinity(&tmpj);
}

int secp256k1_frost_share_verify(const secp256k1_context* ctx, size_t threshold, const secp256k1_xonly_pubkey *pk, const secp256k1_frost_share *share, const secp256k1_pubkey * const* vss_commitment) {
    secp256k1_scalar share_i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pk != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(threshold > 1);

    if (!secp256k1_frost_share_load(ctx, &share_i, share)) {
        return 0;
    }

    return secp256k1_frost_vss_verify_internal(ctx, threshold, pk, &share_i, vss_commitment);
}

int secp256k1_frost_compute_pubshare(const secp256k1_context* ctx, secp256k1_pubkey *pubshare, size_t threshold, const secp256k1_xonly_pubkey *pk, const secp256k1_pubkey * const* vss_commitments, size_t n_participants) {
    secp256k1_gej pkj;
    secp256k1_ge pkp, tmp;
    secp256k1_frost_compute_pubshare_ecmult_data compute_pubshare_ecmult_data;
    secp256k1_frost_pubkey_combine_ecmult_data pubkey_combine_ecmult_data;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubshare != NULL);
    memset(pubshare, 0, sizeof(*pubshare));
    ARG_CHECK(pk != NULL);
    ARG_CHECK(vss_commitments != NULL);
    ARG_CHECK(n_participants > 1);
    ARG_CHECK(threshold > 1);

    if (threshold > n_participants) {
        return 0;
    }

    /* Use an EC multi-multiplication to compute the following equation:
     *   agg_share_i*G = (
     *      idx^0*vss_commitment[0][0] + ...
     *                                 + idx^(t - 1)*vss_commitment[0][t - 1]
     *   )                             + ...
     *                                 + (
     *      idx^0*vss_commitment[n - 1][0] + ...
     *                                     + idx^(t - 1)*vss_commitment[n - 1][t - 1]
     *   )*/
    compute_pubshare_ecmult_data.ctx = ctx;
    compute_pubshare_ecmult_data.vss_commitments = vss_commitments;
    compute_pubshare_ecmult_data.threshold = threshold;
    /* Evaluate the public polynomial at the idx */
    if (!secp256k1_frost_compute_indexhash(ctx, &compute_pubshare_ecmult_data.idx, pk)) {
        return 0;
    }
    secp256k1_scalar_set_int(&compute_pubshare_ecmult_data.idxn, 1);
    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_frost_compute_pubshare_ecmult_callback, (void *) &compute_pubshare_ecmult_data, n_participants*threshold)) {
        return 0;
    }
    secp256k1_ge_set_gej(&tmp, &pkj);

    /* Combine pubkeys */
    pubkey_combine_ecmult_data.ctx = ctx;
    pubkey_combine_ecmult_data.pks = vss_commitments;
    pubkey_combine_ecmult_data.threshold = threshold;

    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &pubkey_combine_ecmult_data, n_participants)) {
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    if (secp256k1_fe_is_odd(&pkp.y)) {
        secp256k1_ge_neg(&tmp, &tmp);
    }

    secp256k1_pubkey_save(pubshare, &tmp);

    return 1;
}

int secp256k1_frost_share_agg(const secp256k1_context* ctx, secp256k1_frost_share *agg_share, secp256k1_xonly_pubkey *agg_pk, unsigned char *vss_hash, const secp256k1_frost_share * const* shares, const secp256k1_pubkey * const* vss_commitments, size_t n_shares, size_t threshold, const secp256k1_xonly_pubkey *pk) {
    secp256k1_frost_pubkey_combine_ecmult_data pubkey_combine_ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    int pk_parity;
    secp256k1_scalar acc;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_share != NULL);
    memset(agg_share, 0, sizeof(*agg_share));
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(vss_hash != NULL);
    ARG_CHECK(shares != NULL);
    ARG_CHECK(vss_commitments != NULL);
    ARG_CHECK(n_shares > 1);
    ARG_CHECK(threshold > 1);

    if (threshold > n_shares) {
        return 0;
    }

    secp256k1_scalar_clear(&acc);
    for (i = 0; i < n_shares; i++) {
        secp256k1_scalar share_i;

        if (!secp256k1_frost_share_load(ctx, &share_i, shares[i])) {
            return 0;
        }
        /* Verify share against commitments */
        if (!secp256k1_frost_vss_verify_internal(ctx, threshold, pk, &share_i, &vss_commitments[i])) {
            return 0;
        }
        secp256k1_scalar_add(&acc, &acc, &share_i);
    }
    if (!secp256k1_frost_compute_vss_hash(ctx, vss_hash, vss_commitments, n_shares, threshold)) {
        return 0;
    }

    /* Combine pubkeys */
    pubkey_combine_ecmult_data.ctx = ctx;
    pubkey_combine_ecmult_data.pks = vss_commitments;
    pubkey_combine_ecmult_data.threshold = threshold;

    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &pubkey_combine_ecmult_data, n_shares)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    pk_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(agg_pk, &pkp);

    /* Invert the aggregate share if the combined pubkey has an odd Y coordinate. */
    if (pk_parity == 1) {
        secp256k1_scalar_negate(&acc, &acc);
    }
    secp256k1_frost_share_save(agg_share, &acc);

    return 1;
}

int secp256k1_frost_pubkey_get(const secp256k1_context* ctx, secp256k1_pubkey *ec_agg_pk, const secp256k1_xonly_pubkey *xonly_agg_pk) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ec_agg_pk != NULL);
    memset(ec_agg_pk, 0, sizeof(*ec_agg_pk));
    ARG_CHECK(xonly_agg_pk != NULL);

    /* The output of keygen is an aggregated public key that *always* has an
     * even Y coordinate. */
    if (!secp256k1_xonly_pubkey_load(ctx, &pk, xonly_agg_pk)) {
        return 0;
    }
    secp256k1_pubkey_save(ec_agg_pk, &pk);
    return 1;
}

int secp256k1_frost_pubkey_tweak(const secp256k1_context* ctx, secp256k1_frost_tweak_cache *tweak_cache, const secp256k1_xonly_pubkey *agg_pk) {
    secp256k1_tweak_cache_internal cache_i = { 0 };

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_cache != NULL);
    ARG_CHECK(agg_pk != NULL);

    /* The output of keygen is an aggregated public key that *always* has an
     * even Y coordinate. */
    if (!secp256k1_xonly_pubkey_load(ctx, &cache_i.pk, agg_pk)) {
        return 0;
    }
    secp256k1_tweak_cache_save(tweak_cache, &cache_i);

    return 1;
}

static int secp256k1_frost_pubkey_tweak_add_internal(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32, int xonly) {
    secp256k1_tweak_cache_internal cache_i;
    int overflow = 0;
    secp256k1_scalar tweak;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(tweak_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_tweak_cache_load(ctx, &cache_i, tweak_cache)) {
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
    secp256k1_tweak_cache_save(tweak_cache, &cache_i);
    if (output_pubkey != NULL) {
        secp256k1_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

int secp256k1_frost_pubkey_ec_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, tweak_cache, tweak32, 0);
}

int secp256k1_frost_pubkey_xonly_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, tweak_cache, tweak32, 1);
}

#endif
