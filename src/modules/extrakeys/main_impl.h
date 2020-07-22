/**********************************************************************
 * Copyright (c) 2020 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_EXTRAKEYS_MAIN_
#define _SECP256K1_MODULE_EXTRAKEYS_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_extrakeys.h"

static SECP256K1_INLINE int secp256k1_xonly_pubkey_load(const secp256k1_context* ctx, secp256k1_ge *ge, const secp256k1_xonly_pubkey *pubkey) {
    return secp256k1_pubkey_load(ctx, ge, (const secp256k1_pubkey *) pubkey);
}

static SECP256K1_INLINE void secp256k1_xonly_pubkey_save(secp256k1_xonly_pubkey *pubkey, secp256k1_ge *ge) {
    secp256k1_pubkey_save((secp256k1_pubkey *) pubkey, ge);
}

int secp256k1_xonly_pubkey_parse(const secp256k1_context* ctx, secp256k1_xonly_pubkey *pubkey, const unsigned char *input32) {
    secp256k1_ge pk;
    secp256k1_fe x;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input32 != NULL);

    if (!secp256k1_fe_set_b32(&x, input32)) {
        return 0;
    }
    if (!secp256k1_ge_set_xo_var(&pk, &x, 0)) {
        return 0;
    }
    secp256k1_xonly_pubkey_save(pubkey, &pk);
    secp256k1_ge_clear(&pk);
    return 1;
}

int secp256k1_xonly_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output32, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output32 != NULL);
    memset(output32, 0, 32);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }
    secp256k1_fe_get_b32(output32, &pk.x);
    return 1;
}

int secp256k1_xonly_pubkey_from_pubkey(const secp256k1_context* ctx, secp256k1_xonly_pubkey *xonly_pubkey, int *y_parity, const secp256k1_pubkey *pubkey) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(xonly_pubkey != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_pubkey_load(ctx, &pk, pubkey);
    secp256k1_ge_even_y(&pk, y_parity);
    secp256k1_xonly_pubkey_save(xonly_pubkey, &pk);
    return 1;
}

int secp256k1_xonly_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, const secp256k1_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output_pubkey != NULL);
    memset(output_pubkey, 0, sizeof(*output_pubkey));
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(internal_pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, internal_pubkey)
        || !secp256k1_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32)) {
        return 0;
    }
    secp256k1_pubkey_save(output_pubkey, &pk);
    return 1;
}

int secp256k1_xonly_pubkey_tweak_add_check(const secp256k1_context* ctx, const unsigned char *output_pubkey32, int output_pubkey_parity, const secp256k1_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    secp256k1_ge pk;
    unsigned char pk_expected32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(internal_pubkey != NULL);
    ARG_CHECK(output_pubkey32 != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, internal_pubkey)
        || !secp256k1_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&pk.x);
    secp256k1_fe_normalize_var(&pk.y);
    secp256k1_fe_get_b32(pk_expected32, &pk.x);

    return memcmp(&pk_expected32, output_pubkey32, 32) == 0
            && secp256k1_fe_is_odd(&pk.y) == output_pubkey_parity;
}

static void secp256k1_keypair_save(secp256k1_keypair *keypair, const secp256k1_scalar *sk, secp256k1_ge *pk) {
    secp256k1_scalar_get_b32(&keypair->data[0], sk);
    secp256k1_pubkey_save((secp256k1_pubkey *)&keypair->data[32], pk);
}


static int secp256k1_keypair_seckey_load(const secp256k1_context* ctx, secp256k1_scalar *sk, const secp256k1_keypair *keypair) {
    int ret;

    secp256k1_scalar_set_b32(sk, &keypair->data[0], NULL);
    ret = !secp256k1_scalar_is_zero(sk);
    /* We can declassify ret here because sk is only zero if a keypair function
     * failed (which zeroes the keypair) and its return value is ignored. */
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    ARG_CHECK(ret);
    return 1;
}

/* Load a keypair into pk and sk (if non-NULL). This function declassifies pk
 * and ARG_CHECKs that the keypair is not invalid. It always initializes sk and
 * pk with dummy values. */
static int secp256k1_keypair_load(const secp256k1_context* ctx, secp256k1_scalar *sk, secp256k1_ge *pk, const secp256k1_keypair *keypair) {
    int ret;
    const secp256k1_pubkey *pubkey = (const secp256k1_pubkey *)&keypair->data[32];

    /* Need to declassify the pubkey because pubkey_load ARG_CHECKs if it's
     * invalid. */
    secp256k1_declassify(ctx, pubkey, sizeof(*pubkey));
    ret = secp256k1_pubkey_load(ctx, pk, pubkey);
    if (sk != NULL) {
        ret = ret && secp256k1_keypair_seckey_load(ctx, sk, keypair);
    }
    if (!ret) {
        *pk = secp256k1_ge_const_g;
        if (sk != NULL) {
            *sk = secp256k1_scalar_one;
        }
    }
    return ret;
}

int secp256k1_keypair_create(const secp256k1_context* ctx, secp256k1_keypair *keypair, const unsigned char *seckey32) {
    secp256k1_scalar sk;
    secp256k1_ge pk;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(keypair != NULL);
    memset(keypair, 0, sizeof(*keypair));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey32 != NULL);

    ret = secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &sk, &pk, seckey32);
    secp256k1_keypair_save(keypair, &sk, &pk);
    memczero(keypair, sizeof(*keypair), !ret);

    secp256k1_scalar_clear(&sk);
    return ret;
}

int secp256k1_keypair_pub(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const secp256k1_keypair *keypair) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(keypair != NULL);

    memcpy(pubkey->data, &keypair->data[32], sizeof(*pubkey));
    return 1;
}

int secp256k1_keypair_xonly_pub(const secp256k1_context* ctx, secp256k1_xonly_pubkey *pubkey, int *pubkey_parity, const secp256k1_keypair *keypair) {
    secp256k1_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(keypair != NULL);

    if (!secp256k1_keypair_load(ctx, NULL, &pk, keypair)) {
        return 0;
    }
    secp256k1_ge_even_y(&pk, pubkey_parity);
    secp256k1_xonly_pubkey_save(pubkey, &pk);

    return 1;
}

int secp256k1_keypair_xonly_tweak_add(const secp256k1_context* ctx, secp256k1_keypair *keypair, const unsigned char *tweak32) {
    secp256k1_ge pk;
    secp256k1_scalar sk;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    memset(keypair, 0, sizeof(*keypair));

    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
        secp256k1_ge_neg(&pk, &pk);
    }

    ret &= secp256k1_ec_seckey_tweak_add_helper(&sk, tweak32);
    secp256k1_scalar_cmov(&sk, &secp256k1_scalar_zero, !ret);
    ret &= secp256k1_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32);

    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (ret) {
        secp256k1_keypair_save(keypair, &sk, &pk);
    }

    secp256k1_scalar_clear(&sk);
    return ret;
}

#endif
