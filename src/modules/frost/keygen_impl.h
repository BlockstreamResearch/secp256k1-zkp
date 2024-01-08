/**********************************************************************
 * Copyright (c) 2021-2023 Jesse Posner                               *
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

int secp256k1_frost_shares_trusted_gen(const secp256k1_context *ctx, secp256k1_frost_share *shares, secp256k1_pubkey *pubshares, secp256k1_xonly_pubkey *pk, const unsigned char *seed32, size_t threshold, size_t n_participants) {
    secp256k1_sha256 sha;
    secp256k1_gej rj;
    secp256k1_ge rp;
    unsigned char polygen[32];
    size_t i, j;
    int ret = 1;
    int pk_parity = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shares != NULL);
    for (i = 0; i < n_participants; i++) {
        memset(&shares[i], 0, sizeof(shares[i]));
    }
    ARG_CHECK(pubshares != NULL);
    ARG_CHECK(pk != NULL);
    ARG_CHECK(seed32 != NULL);
    ARG_CHECK(threshold > 1);
    ARG_CHECK(n_participants >= threshold);

    /* Commit to threshold, n_participants, and seed */
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/trusted-shares-polygen", sizeof("FROST/trusted-shares-polygen") - 1);
    secp256k1_sha256_write(&sha, seed32, 32);
    secp256k1_write_be64(&polygen[0], threshold);
    secp256k1_write_be64(&polygen[8], n_participants);
    secp256k1_sha256_write(&sha, polygen, 16);
    secp256k1_sha256_finalize(&sha, polygen);

    /* Derive share */
    /* See draft-irtf-cfrg-frost-08#appendix-C.1 */
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar share_i, idx;

        secp256k1_scalar_clear(&share_i);

        for (j = 0; j < threshold; j++) {
            unsigned char buf[32];
            secp256k1_scalar coeff_i;

            secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/trusted-shares-coeffgen", sizeof("FROST/trusted-shares-coeffgen") - 1);
            secp256k1_sha256_write(&sha, polygen, 32);
            secp256k1_write_be64(&buf[0], j);
            secp256k1_sha256_write(&sha, buf, 8);
            secp256k1_sha256_finalize(&sha, buf);
            secp256k1_scalar_set_b32(&coeff_i, buf, NULL);

            /* Horner's method to evaluate polynomial to derive shares */
            secp256k1_scalar_add(&share_i, &share_i, &coeff_i);
            if (j < threshold - 1) {
                secp256k1_scalar_set_int(&idx, i + 1);
                secp256k1_scalar_mul(&share_i, &share_i, &idx);
            }

            /* Compute x-only public key for constant term */
            if (i == 0 && j == threshold - 1) {
                /* Compute commitment to constant term */
                secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &coeff_i);
                secp256k1_ge_set_gej(&rp, &rj);
                /* The commitment is non-secret so it can be declassified to
                 * allow branching. */
                secp256k1_declassify(ctx, &rp, sizeof(rp));
                secp256k1_fe_normalize_var(&rp.y);
                pk_parity = secp256k1_extrakeys_ge_even_y(&rp);
                secp256k1_xonly_pubkey_save(pk, &rp);
            }
        }

        if (pk_parity == 1) {
            secp256k1_scalar_negate(&share_i, &share_i);
        }
        secp256k1_frost_share_save(&shares[i], &share_i);
        /* Compute pubshare */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &share_i);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubshares[i], &rp);
    }

    return ret;
}

int secp256k1_frost_pubkey_get(const secp256k1_context* ctx, secp256k1_pubkey *ec_pk, const secp256k1_xonly_pubkey *xonly_pk) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ec_pk != NULL);
    memset(ec_pk, 0, sizeof(*ec_pk));
    ARG_CHECK(xonly_pk != NULL);

    /* The output of keygen is an aggregated public key that *always* has an
     * even Y coordinate. */
    if (!secp256k1_xonly_pubkey_load(ctx, &pk, xonly_pk)) {
        return 0;
    }
    secp256k1_pubkey_save(ec_pk, &pk);
    return 1;
}

int secp256k1_frost_pubkey_tweak(const secp256k1_context* ctx, secp256k1_frost_tweak_cache *tweak_cache, const secp256k1_xonly_pubkey *pk) {
    secp256k1_tweak_cache_internal cache_i = { 0 };

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_cache != NULL);
    ARG_CHECK(pk != NULL);

    /* The output of keygen is an aggregated public key that *always* has an
     * even Y coordinate. */
    if (!secp256k1_xonly_pubkey_load(ctx, &cache_i.pk, pk)) {
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
