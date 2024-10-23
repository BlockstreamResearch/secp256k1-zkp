/**********************************************************************
 * Copyright (c) 2023-2024 Zhe Pang and Sivaram Dhakshinamoorthy      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorr_adaptor.h"

#include "../../hash.h"
#include "../../scalar.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("SchnorrAdaptor/nonce")||SHA256("SchnorrAdaptor/nonce"). */
static void secp256k1_nonce_function_schnorr_adaptor_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xe268ac2aul;
    sha->s[1] = 0x3a221b84ul;
    sha->s[2] = 0x69612afdul;
    sha->s[3] = 0x92ce3040ul;
    sha->s[4] = 0xc83ca35ful;
    sha->s[5] = 0xec2ee152ul;
    sha->s[6] = 0xba136ab7ul;
    sha->s[7] = 0x3bf6ec7ful;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("SchnorrAdaptor/aux")||SHA256("SchnorrAdaptor/aux"). */
static void secp256k1_nonce_function_schnorr_adaptor_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x50685e98ul;
    sha->s[1] = 0x6313905eul;
    sha->s[2] = 0x6db24fa0ul;
    sha->s[3] = 0xc8b15c48ul;
    sha->s[4] = 0x6b318921ul;
    sha->s[5] = 0x441d8ff3ul;
    sha->s[6] = 0xa7033a66ul;
    sha->s[7] = 0xc3545cddul;

    sha->bytes = 64;
}

/* algo argument for `nonce_function_schnorr_adaptor` to derive the nonce using a tagged hash function. */
static const unsigned char schnorr_adaptor_algo[20] = "SchnorrAdaptor/nonce";

/* Modified BIP-340 nonce function */
static int nonce_function_schnorr_adaptor(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *adaptor33, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_schnorr_adaptor_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("SchnorrAdaptor/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              65, 206, 231, 5, 44, 99, 30, 162,
             119, 101, 143, 108, 176, 134, 217, 23,
             54, 150, 157, 221, 198, 161, 164, 85,
             235, 82, 28, 56, 164, 220, 113, 53
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(schnorr_adaptor_algo)
            && secp256k1_memcmp_var(algo, schnorr_adaptor_algo, algolen) == 0) {
        secp256k1_nonce_function_schnorr_adaptor_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||adaptor33||pk||msg using the tagged hash */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, adaptor33, 33);
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened_schnorr_adaptor secp256k1_nonce_function_schnorr_adaptor = nonce_function_schnorr_adaptor;

#endif
