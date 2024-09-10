/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_H
#define SECP256K1_MODULE_FROST_KEYGEN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    secp256k1_ge pk;
    /* tweak is identical to value tacc[v] in the specification. */
    secp256k1_scalar tweak;
    /* parity_acc corresponds to gacc[v] in the spec. If gacc[v] is -1,
     * parity_acc is 1. Otherwise, parity_acc is 0. */
    int parity_acc;
} secp256k1_keygen_cache_internal;

static int secp256k1_keygen_cache_load(const secp256k1_context* ctx, secp256k1_keygen_cache_internal *cache_i, const secp256k1_frost_keygen_cache *cache);

static int secp256k1_frost_share_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_frost_share* share);

#endif
