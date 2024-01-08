/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_SESSION_H
#define SECP256K1_MODULE_FROST_SESSION_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "../../scalar.h"

typedef struct {
    int fin_nonce_parity;
    unsigned char fin_nonce[32];
    secp256k1_scalar noncecoef;
    secp256k1_scalar challenge;
    secp256k1_scalar s_part;
} secp256k1_frost_session_internal;

static int secp256k1_frost_session_load(const secp256k1_context* ctx, secp256k1_frost_session_internal *session_i, const secp256k1_frost_session *session);

#endif
