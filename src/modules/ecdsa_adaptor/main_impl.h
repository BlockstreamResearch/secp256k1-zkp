/**********************************************************************
 * Copyright (c) 2020-2021 Jonas Nick, Jesse Posner                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "include/secp256k1_ecdsa_adaptor.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/non")||SHA256("ECDSAadaptor/non"). */
static void secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x791dae43ul;
    sha->s[1] = 0xe52d3b44ul;
    sha->s[2] = 0x37f9edeaul;
    sha->s[3] = 0x9bfd2ab1ul;
    sha->s[4] = 0xcfb0f44dul;
    sha->s[5] = 0xccf1d880ul;
    sha->s[6] = 0xd18f2c13ul;
    sha->s[7] = 0xa37b9024ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/aux")||SHA256("ECDSAadaptor/aux"). */
static void secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xd14c7bd9ul;
    sha->s[1] = 0x095d35e6ul;
    sha->s[2] = 0xb8490a88ul;
    sha->s[3] = 0xfb00ef74ul;
    sha->s[4] = 0x0baa488ful;
    sha->s[5] = 0x69366693ul;
    sha->s[6] = 0x1c81c5baul;
    sha->s[7] = 0xc33b296aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char ecdsa_adaptor_algo[16] = "ECDSAadaptor/non";

/* Modified BIP-340 nonce function */
static int nonce_function_ecdsa_adaptor(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk33, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithims. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(ecdsa_adaptor_algo)
            && secp256k1_memcmp_var(algo, ecdsa_adaptor_algo, algolen) == 0) {
        secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per BIP-340 */
    if (data != NULL) {
        secp256k1_sha256_write(&sha, masked_key, 32);
    } else {
        secp256k1_sha256_write(&sha, key32, 32);
    }
    secp256k1_sha256_write(&sha, pk33, 33);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened_ecdsa_adaptor secp256k1_nonce_function_ecdsa_adaptor = nonce_function_ecdsa_adaptor;

#endif
