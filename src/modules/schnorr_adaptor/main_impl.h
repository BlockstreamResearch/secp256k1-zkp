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

static int secp256k1_schnorr_adaptor_presign_internal(const secp256k1_context *ctx, unsigned char *pre_sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, const secp256k1_pubkey *adaptor, secp256k1_nonce_function_hardened_schnorr_adaptor noncefp, void *ndata) {
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj, rpj;
    secp256k1_ge r, rp;
    secp256k1_ge pk;
    secp256k1_ge adaptor_ge;
    unsigned char nonce32[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    unsigned char adaptor_buff[33];
    size_t cmprssd_len = 33; /* for serializing `adaptor_ge` and `pre_sig65` */
    int serialize_ret = 0;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pre_sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(adaptor != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_schnorr_adaptor;
    }

    /* T := adaptor_ge */
    if(!secp256k1_pubkey_load(ctx, &adaptor_ge, adaptor)){
        return 0;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* Generate the nonce k */
    secp256k1_scalar_get_b32(seckey, &sk);
    secp256k1_fe_get_b32(pk_buf, &pk.x);
    serialize_ret = secp256k1_eckey_pubkey_serialize(&adaptor_ge, adaptor_buff, &cmprssd_len, 1);
    VERIFY_CHECK(serialize_ret);
    ret &= !!noncefp(nonce32, msg32, seckey, adaptor_buff, pk_buf, schnorr_adaptor_algo, sizeof(schnorr_adaptor_algo), ndata);
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* R = k*G */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    /* We declassify the non-secret values R and T to allow using them
     * as branch points. */
    secp256k1_declassify(ctx, &rj, sizeof(rj));
    secp256k1_declassify(ctx, &adaptor_ge, sizeof(adaptor_ge));
    /* R' = R + T */
    secp256k1_gej_add_ge_var(&rpj, &rj, &adaptor_ge, NULL);
    secp256k1_ge_set_gej(&rp, &rpj);

    /* We declassify R' (non-secret value) to branch on it */
    secp256k1_declassify(ctx, &rp, sizeof(rp));
    secp256k1_fe_normalize_var(&rp.y);

    /* Determine if the secret nonce should be negated.
    *
    * pre_sig65[0:33] contains the compressed 33-byte encoding of the public
    * nonce R' = k*G + T, where k is the secret nonce and T is the adaptor point.
    *
    * Since a BIP340 signature requires an x-only public nonce, in the case where
    * R' = k*G + T has odd Y-coordinate, the x-only public nonce corresponding to
    * the signature is actually -k*G - T. Therefore, we negate k to ensure that the
    * adapted pre-signature will result in a valid BIP340 signature, with an even R'.y
    *
    *  pre_sig65[33:65] =  k + e * d if R'.y is even
    *                   = -k + e * d if R'.y is odd
    */
    if (secp256k1_fe_is_odd(&rp.y)) {
        secp256k1_scalar_negate(&k, &k);
    }
    serialize_ret = secp256k1_eckey_pubkey_serialize(&rp, pre_sig65, &cmprssd_len, 1);
    /* R' is not the point at infinity with overwhelming probability */
    VERIFY_CHECK(serialize_ret);
    (void) serialize_ret;

    secp256k1_schnorrsig_challenge(&e, &pre_sig65[1], msg32, 32, pk_buf);
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&pre_sig65[33], &e);

    secp256k1_memczero(pre_sig65, 65, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorr_adaptor_presign(const secp256k1_context *ctx, unsigned char *pre_sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, const secp256k1_pubkey *adaptor, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return secp256k1_schnorr_adaptor_presign_internal(ctx, pre_sig65, msg32, keypair, adaptor, secp256k1_nonce_function_schnorr_adaptor, (unsigned char*)aux_rand32);
}


int secp256k1_schnorr_adaptor_extract(const secp256k1_context *ctx, secp256k1_pubkey *adaptor, const unsigned char *pre_sig65, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_ge adaptor_ge;
    secp256k1_gej adaptor_gej;
    secp256k1_gej rj;
    secp256k1_ge rp;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(pre_sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    /* R' := pre_sig65[0:33] */
    if (!secp256k1_eckey_pubkey_parse(&rp, &pre_sig65[0], 33)) {
        return 0;
    }
    /* s := pre_sig65[33:65] */
    secp256k1_scalar_set_b32(&s, &pre_sig65[33], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &pre_sig65[1], msg32, 32, buf);

    /* Compute R = s*G + (-e)*P */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s);
    if (secp256k1_gej_is_infinity(&rj)) {
        return 0;
    }

    /* Determine if R needs to be negated
     *
     * `adaptor_presign` negates the secret nonce k when R’.y is odd, during
     * the computation of the s value (i.e., presig[33:65]). Therefore, we need
     * to negate R = k*G (if R'.y is odd) before subtracting it from R' = R + T.
     *
     *  T =  R' - R if R'.y is even
     *    =  R' + R  if R'.y is odd
     */
    secp256k1_fe_normalize_var(&rp.y);
    if (!secp256k1_fe_is_odd(&rp.y)) {
        secp256k1_gej_neg(&rj, &rj);
    }
    secp256k1_gej_add_ge_var(&adaptor_gej, &rj, &rp, NULL);
    secp256k1_ge_set_gej(&adaptor_ge, &adaptor_gej);
    if (secp256k1_ge_is_infinity(&adaptor_ge)) {
        return 0;
    }
    secp256k1_pubkey_save(adaptor, &adaptor_ge);

    return 1;
}

int secp256k1_schnorr_adaptor_adapt(const secp256k1_context *ctx, unsigned char *sig64, const unsigned char *pre_sig65, const unsigned char *sec_adaptor32) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig65 != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);

    if (pre_sig65[0] != SECP256K1_TAG_PUBKEY_EVEN && pre_sig65[0] != SECP256K1_TAG_PUBKEY_ODD) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, &pre_sig65[33], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor32, &overflow);
    ret &= !overflow;

    /* Determine if the secret adaptor should be negated.
     *
     * pre_sig65[0:33] contains the compressed 33-byte encoding of the public
     * nonce R' = (k + t)*G, where r is the secret nonce generated by
     * `adaptor_presign` and t is the secret adaptor.
     *
     * Since a BIP340 signature requires an x-only public nonce, in the case where
     * (k + t)*G has odd Y-coordinate, the x-only public nonce corresponding to the
     * signature is actually (-k - t)*G. Thus adapting a pre-signature requires
     * negating t in this case.
     *
     * sig64[32:64]  =  s + t if R'.y is even
     *               =  s - t if R'.y is odd
     */
    if (pre_sig65[0] == SECP256K1_TAG_PUBKEY_ODD) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(&sig64[32], &s);
    memmove(sig64, &pre_sig65[1], 32);

    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&t);
    return ret;
}

int secp256k1_schnorr_adaptor_extract_sec(const secp256k1_context *ctx, unsigned char *sec_adaptor32, const unsigned char *pre_sig65, const unsigned char *sig64) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(pre_sig65 != NULL);
    ARG_CHECK(sig64 != NULL);

    if (pre_sig65[0] != SECP256K1_TAG_PUBKEY_EVEN && pre_sig65[0] != SECP256K1_TAG_PUBKEY_ODD) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, &pre_sig65[33], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, &sig64[32], &overflow);
    ret &= !overflow;

    /*TODO: should we parse presig[0:33] & sig[0:32], to make sure the presig &
     * has valid public nonce point?
     *
     * But we don't care about their validity here right? Then why do we ARG_CHECK
     * presig[0] parity byte?
     *
     * Here, the inputs are invalid but the output is valid :/  */

    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&t, &t, &s);
    /* `adaptor_adapt` negates the secret adaptor t when R’.y is odd, during
     * the computation of the BIP340 signature. Therefore, we need negate
     * (sig[32:64] - pre_sig65[33:65]) in this case.
     *
     *  t =  (sig[32:64] - pre_sig65[33:65])  if R'.y is even
     *    = -(sig[32:64] - pre_sig65[33:65])  if R'.y is odd
     */
    if (pre_sig65[0] == SECP256K1_TAG_PUBKEY_ODD) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_get_b32(sec_adaptor32, &t);

    secp256k1_memczero(sec_adaptor32, 32, !ret);
    secp256k1_scalar_clear(&t);
    return ret;
}

#endif
