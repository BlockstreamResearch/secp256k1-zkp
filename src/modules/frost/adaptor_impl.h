/***********************************************************************
 * Copyright (c) 2022-2024 Jesse Posner                                *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_ADAPTOR_IMPL_H
#define SECP256K1_MODULE_FROST_ADAPTOR_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "session.h"
#include "../../scalar.h"

int secp256k1_frost_nonce_parity(const secp256k1_context* ctx, int *nonce_parity, const secp256k1_frost_session *session) {
    secp256k1_frost_session_internal session_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce_parity != NULL);
    ARG_CHECK(session != NULL);

    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        return 0;
    }
    *nonce_parity = session_i.fin_nonce_parity;
    return 1;
}

int secp256k1_frost_verify_adaptor(const secp256k1_context* ctx, const unsigned char *pre_sig64, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey, const secp256k1_pubkey *adaptor, int nonce_parity) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;
    secp256k1_ge adaptorp;
    secp256k1_xonly_pubkey noncepk;
    secp256k1_gej fin_nonce_ptj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    if (!secp256k1_xonly_pubkey_parse(ctx, &noncepk, &pre_sig64[0])) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_load(ctx, &r, &noncepk)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)) {
        return 0;
    }
    if (!nonce_parity) {
        secp256k1_ge_neg(&adaptorp, &adaptorp);
    }
    secp256k1_gej_set_ge(&fin_nonce_ptj, &adaptorp);
    secp256k1_gej_add_ge_var(&fin_nonce_ptj, &fin_nonce_ptj, &r, NULL);
    if (secp256k1_gej_is_infinity(&fin_nonce_ptj)) {
        /* unreachable with overwhelming probability */
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &pre_sig64[0], msg32, 32, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s);

    /* secp256k1_ge_set_gej_var(&r, &rj); */
    if (secp256k1_gej_is_infinity(&rj)) {
        return 0;
    }

    secp256k1_gej_neg(&rj, &rj);
    secp256k1_gej_add_var(&rj, &rj, &fin_nonce_ptj, NULL);
    return secp256k1_gej_is_infinity(&rj);
}

int secp256k1_frost_adapt(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *pre_sig64, const unsigned char *sec_adaptor32, int nonce_parity) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor32, &overflow);
    ret &= !overflow;

    /* Determine if the secret adaptor should be negated.
     *
     * The frost_session stores the X-coordinate and the parity of the "final nonce"
     * (r + t)*G, where r*G is the aggregate public nonce and t is the secret adaptor.
     *
     * Since a BIP340 signature requires an x-only public nonce, in the case where
     * (r + t)*G has odd Y-coordinate (i.e. nonce_parity == 1), the x-only public nonce
     * corresponding to the signature is actually (-r - t)*G. Thus adapting a
     * pre-signature requires negating t in this case.
     */
    if (nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(&sig64[32], &s);
    memmove(sig64, pre_sig64, 32);
    secp256k1_scalar_clear(&t);
    return ret;
}

int secp256k1_frost_extract_adaptor(const secp256k1_context* ctx, unsigned char *sec_adaptor32, const unsigned char *sig64, const unsigned char *pre_sig64, int nonce_parity) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    secp256k1_scalar_set_b32(&t, &sig64[32], &overflow);
    ret &= !overflow;
    secp256k1_scalar_negate(&t, &t);

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_add(&t, &t, &s);

    if (!nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_get_b32(sec_adaptor32, &t);
    secp256k1_scalar_clear(&t);
    return ret;
}

#endif
