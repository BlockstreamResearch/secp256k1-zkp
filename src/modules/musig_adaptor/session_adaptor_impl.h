/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_ADAPTOR_SESSION_IMPL_H
#define SECP256K1_MODULE_MUSIG_ADAPTOR_SESSION_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"
#include "../../../include/secp256k1_musig_adaptor.h"

#include "../musig/keyagg.h"
#include "../musig/session.h"
#include "../../eckey.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

int secp256k1_musig_nonce_process_adaptor(const secp256k1_context* ctx, secp256k1_musig_session *session, const secp256k1_musig_aggnonce  *aggnonce, const unsigned char *msg32, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_pubkey *adaptor) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_ge aggnonce_pts[2];
    unsigned char fin_nonce[32];
    secp256k1_musig_session_internal session_i;
    unsigned char agg_pk32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(adaptor != NULL);

    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    secp256k1_fe_get_b32(agg_pk32, &cache_i.pk.x);

    if (!secp256k1_musig_aggnonce_load(ctx, aggnonce_pts, aggnonce)) {
        return 0;
    }

    /* Add public adaptor to nonce */
    {
        secp256k1_ge adaptorp;
        secp256k1_gej tmp;
        if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)) {
            return 0;
        }
        secp256k1_gej_set_ge(&tmp, &aggnonce_pts[0]);
        secp256k1_gej_add_ge_var(&tmp, &tmp, &adaptorp, NULL);
        secp256k1_ge_set_gej(&aggnonce_pts[0], &tmp);
    }

    secp256k1_musig_nonce_process_internal(&session_i.fin_nonce_parity, fin_nonce, &session_i.noncecoef, aggnonce_pts, agg_pk32, msg32);
    secp256k1_schnorrsig_challenge(&session_i.challenge, fin_nonce, msg32, 32, agg_pk32);

    /* If there is a tweak then set `challenge` times `tweak` to the `s`-part.*/
    secp256k1_scalar_set_int(&session_i.s_part, 0);
    if (!secp256k1_scalar_is_zero(&cache_i.tweak)) {
        secp256k1_scalar e_tmp;
        secp256k1_scalar_mul(&e_tmp, &session_i.challenge, &cache_i.tweak);
        if (secp256k1_fe_is_odd(&cache_i.pk.y)) {
            secp256k1_scalar_negate(&e_tmp, &e_tmp);
        }
        session_i.s_part = e_tmp;
    }
    memcpy(session_i.fin_nonce, fin_nonce, sizeof(session_i.fin_nonce));
    secp256k1_musig_session_save(session, &session_i);
    return 1;
}

#endif
