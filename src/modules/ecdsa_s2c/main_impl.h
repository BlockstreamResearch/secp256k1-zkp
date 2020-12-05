/**********************************************************************
 * Copyright (c) 2019-2020 Marko Bencun, Jonas Nick                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_S2C_MAIN_H
#define SECP256K1_MODULE_ECDSA_S2C_MAIN_H

#include "include/secp256k1.h"
#include "include/secp256k1_ecdsa_s2c.h"

int secp256k1_ecdsa_s2c_opening_parse(const secp256k1_context* ctx, secp256k1_ecdsa_s2c_opening* opening, const unsigned char* input33) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(input33 != NULL);
    return secp256k1_ec_pubkey_parse(ctx, (secp256k1_pubkey*) opening, input33, 33);
}

int secp256k1_ecdsa_s2c_opening_serialize(const secp256k1_context* ctx, unsigned char* output33, const secp256k1_ecdsa_s2c_opening* opening) {
    size_t out_len = 33;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output33 != NULL);
    ARG_CHECK(opening != NULL);
    return secp256k1_ec_pubkey_serialize(ctx, output33, &out_len, (const secp256k1_pubkey*) opening, SECP256K1_EC_COMPRESSED);
}

#endif /* SECP256K1_ECDSA_S2C_MAIN_H */
