/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../field.h"
#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    secp256k1_ge pk;
    secp256k1_fe second_pk_x;
    unsigned char pk_hash[32];
    secp256k1_scalar tweak;
    int internal_key_parity;
} secp256k1_keyagg_cache_internal;

/* Requires that the saved point is not infinity */
static void secp256k1_point_save(unsigned char *data, secp256k1_ge *ge);

static void secp256k1_point_load(secp256k1_ge *ge, const unsigned char *data);

static int secp256k1_keyagg_cache_load(const secp256k1_context* ctx, secp256k1_keyagg_cache_internal *cache_i, const secp256k1_musig_keyagg_cache *cache);

static void secp256k1_musig_keyaggcoef(secp256k1_scalar *r, const secp256k1_keyagg_cache_internal *cache_i, secp256k1_fe *x);

#endif
