/**********************************************************************
 * Copyright (c) 2023 Zhe Pang                                        *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorr_adaptor.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("SchnorrAdaptor/nonce")||SHA256("SchnorrAdaptor/nonce"). */
static void secp256k1_adaptor_nonce_function_bip340_sha256_tagged(secp256k1_sha256 *sha) {
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
static void secp256k1_adaptor_nonce_function_bip340_sha256_tagged_aux(secp256k1_sha256 *sha) {
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

/* algo argument for adaptor_nonce_function_bip340 to derive the nonce of Schnorr adaptor signature
 * by using the correct tagged hash function. */
static const unsigned char adaptor_bip340_algo[20] = "SchnorrAdaptor/nonce";

static int adaptor_nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *t33, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_adaptor_nonce_function_bip340_sha256_tagged_aux(&sha);
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
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(adaptor_bip340_algo)
            && secp256k1_memcmp_var(algo, adaptor_bip340_algo, algolen) == 0) {
        secp256k1_adaptor_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||pk||msg using the tagged hash as per the spec */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, t33, 33);
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_adaptor_nonce_function_hardened secp256k1_adaptor_nonce_function_bip340 = adaptor_nonce_function_bip340;

static int secp256k1_schnorr_adaptor_presign_internal(const secp256k1_context *ctx, unsigned char *sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, secp256k1_adaptor_nonce_function_hardened noncefp, const unsigned char *t33, void *ndata) {
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_gej r0j;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_ge r0;
    secp256k1_ge t;
    unsigned char nonce32[32] = {0};
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    size_t size = 33;
    size_t msglen = 32;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(t33 != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_adaptor_nonce_function_bip340;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);

    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* d */
    secp256k1_scalar_get_b32(seckey, &sk);
    /* bytes_from_point(P) */
    secp256k1_fe_get_b32(pk_buf, &pk.x);

    ret &= !!noncefp(nonce32, msg32, seckey, t33, pk_buf, adaptor_bip340_algo, sizeof(adaptor_bip340_algo), ndata);
    /* k0 */
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* R = k0*G */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    /* T = cpoint(T) */
    ret &= !!secp256k1_eckey_pubkey_parse(&t, t33, 33);

    /* R' = k*G + T, can use gej_add_ge_var since r and t aren't secret */
    secp256k1_gej_add_ge_var(&r0j, &rj, &t, NULL);
    secp256k1_ge_set_gej(&r0, &r0j);

    /* We declassify R' to allow using it as a branch point. This is fine
     * because R' is not a secret.  */
    secp256k1_declassify(ctx, &r0, sizeof(r0));
    secp256k1_fe_normalize_var(&r0.y);
    if (secp256k1_fe_is_odd(&r0.y)) {
        secp256k1_scalar_negate(&k, &k);
    }

    ret &= !!secp256k1_eckey_pubkey_serialize(&r0, sig65, &size, 1);

    secp256k1_schnorrsig_challenge(&e, &sig65[1], msg32, msglen, pk_buf);
    secp256k1_scalar_mul(&e, &e, &sk);
    /* k + e * d */
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&sig65[33], &e);

    secp256k1_memczero(sig65, 65, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorr_adaptor_presign(const secp256k1_context *ctx, unsigned char *sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *t33, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return secp256k1_schnorr_adaptor_presign_internal(ctx, sig65, msg32, keypair, secp256k1_adaptor_nonce_function_bip340, t33, (unsigned char*)aux_rand32);
}

int secp256k1_schnorr_adaptor_extract_t(const secp256k1_context *ctx, unsigned char *t33, const unsigned char *sig65, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s0;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge r;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_ge r0;
    secp256k1_ge t;
    secp256k1_gej tj;
    secp256k1_xonly_pubkey pkr0;
    unsigned char buf[32];
    size_t size = 33;
    size_t msglen = 32;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(t33 != NULL);
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    /* P */
    ret &= !!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey);

    /* s0 */
    secp256k1_scalar_set_b32(&s0, &sig65[33], &overflow);
    ret &= !overflow;

    /* R0 */
    ret &= !!secp256k1_xonly_pubkey_parse(ctx, &pkr0, &sig65[1]);
    ret &= !!secp256k1_xonly_pubkey_load(ctx, &r0, &pkr0);

    /* Compute e */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig65[1], msg32, msglen, buf);

    /* Compute rj = s0*G + (-e) * pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s0);

    /* R */
    secp256k1_ge_set_gej_var(&r, &rj);
    ret &= !secp256k1_ge_is_infinity(&r);

    /* T = R0 + (- R) */
    secp256k1_gej_neg(&rj, &rj);
    secp256k1_gej_add_ge_var(&tj, &rj, &r0, NULL);
    if (sig65[0] == SECP256K1_TAG_PUBKEY_EVEN) {
        ;
    } else if (sig65[0] == SECP256K1_TAG_PUBKEY_ODD) {
        secp256k1_gej_neg(&tj, &tj);
    } else {
        ret = 0;
    }
    secp256k1_ge_set_gej(&t, &tj);
    ret &= !!secp256k1_eckey_pubkey_serialize(&t, t33, &size, 1);

    secp256k1_memczero(t33, 33, !ret);

    return ret;
}

int secp256k1_schnorr_adaptor_adapt(const secp256k1_context *ctx, unsigned char *sig64, const unsigned char *sig65, const unsigned char *t32) {
    secp256k1_scalar s0;
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(sig65[0] == SECP256K1_TAG_PUBKEY_EVEN || sig65[0] == SECP256K1_TAG_PUBKEY_ODD);
    ARG_CHECK(t32 != NULL);

    /* s0 */
    secp256k1_scalar_set_b32(&s0, &sig65[33], &overflow);
    ret &= !overflow;

    /* t */
    secp256k1_scalar_set_b32(&t, t32, &overflow);
    ret &= !overflow;

    if (sig65[0] == SECP256K1_TAG_PUBKEY_EVEN) {
        secp256k1_scalar_add(&s, &s0, &t);
    } else if (sig65[0] == SECP256K1_TAG_PUBKEY_ODD) {
        secp256k1_scalar_negate(&t, &t);
        secp256k1_scalar_add(&s, &s0, &t);
    }

    memcpy(sig64, &sig65[1], 32);
    secp256k1_scalar_get_b32(&sig64[32], &s);
    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&s);
    secp256k1_scalar_clear(&t);

    return ret;
}

int secp256k1_schnorr_adaptor_extract_adaptor(const secp256k1_context *ctx, unsigned char *t32, const unsigned char *sig65, const unsigned char *sig64) {
    secp256k1_scalar s0;
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(t32 != NULL);
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(sig65[0] == SECP256K1_TAG_PUBKEY_EVEN || sig65[0] == SECP256K1_TAG_PUBKEY_ODD);
    ARG_CHECK(sig64 != NULL);

    /* s0 */
    secp256k1_scalar_set_b32(&s0, &sig65[33], &overflow);
    ret &= !overflow;

    /* s */
    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    ret &= !overflow;

    if (sig65[0] == SECP256K1_TAG_PUBKEY_EVEN) {
        secp256k1_scalar_negate(&s0, &s0);
        secp256k1_scalar_add(&t, &s, &s0);
    } else if (sig65[0] == SECP256K1_TAG_PUBKEY_ODD) {
        secp256k1_scalar_negate(&s, &s);
        secp256k1_scalar_add(&t, &s0, &s);
    }

    secp256k1_scalar_get_b32(t32, &t);
    secp256k1_memczero(t32, 32, !ret);
    secp256k1_scalar_clear(&s);
    secp256k1_scalar_clear(&t);

    return ret;
}

#endif
