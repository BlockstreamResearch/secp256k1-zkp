/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORRSIG_MAIN_
#define _SECP256K1_MODULE_SCHNORRSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_schnorrsig.h"
#include "hash.h"

int secp256k1_schnorrsig_serialize(const secp256k1_context* ctx, unsigned char *out64, const secp256k1_schnorrsig* sig) {
    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out64 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out64, sig->data, 64);
    return 1;
}

int secp256k1_schnorrsig_parse(const secp256k1_context* ctx, secp256k1_schnorrsig* sig, const unsigned char *in64) {
    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in64 != NULL);
    memcpy(sig->data, in64, 64);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIPSchnorr")||SHA256("BIPSchnorr"). */
static void secp256k1_schnorrsig_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x048d9a59ul;
    sha->s[1] = 0xfe39fb05ul;
    sha->s[2] = 0x28479648ul;
    sha->s[3] = 0xe4a660f9ul;
    sha->s[4] = 0x814b9e66ul;
    sha->s[5] = 0x0469e801ul;
    sha->s[6] = 0x83909280ul;
    sha->s[7] = 0xb329e454ul;
    sha->bytes = 64;
}

int secp256k1_schnorrsig_sign(const secp256k1_context* ctx, secp256k1_schnorrsig *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, void *ndata) {
    secp256k1_scalar x;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej pkj;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[32];
    unsigned char seckey_tmp[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bipschnorr;
    }
    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pkj, &x);
    secp256k1_ge_set_gej(&pk, &pkj);

    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have a square Y. */
    if (!secp256k1_fe_is_quad_var(&pk.y)) {
        secp256k1_scalar_negate(&x, &x);
    }

    secp256k1_scalar_get_b32(seckey_tmp, &x);
    if (!noncefp(buf, msg32, seckey_tmp, (unsigned char *) "BIPSchnorrDerive", (void*)ndata, 0)) {
        memset(sig, 0, sizeof(*sig));
        memset(seckey_tmp, 0, sizeof(seckey_tmp));
        secp256k1_scalar_clear(&x);
        return 0;
    }
    memset(seckey_tmp, 0, sizeof(seckey_tmp));

    secp256k1_scalar_set_b32(&k, buf, NULL);
    if (secp256k1_scalar_is_zero(&k)) {
        memset(sig, 0, sizeof(*sig));
        secp256k1_scalar_clear(&x);
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    if (!secp256k1_fe_is_quad_var(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
    }
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(&sig->data[0], &r.x);

    /* tagged hash(r.x, pk.x, msg32) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, &sig->data[0], 32);
    secp256k1_fe_normalize(&pk.x);
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_sha256_write(&sha, buf, sizeof(buf));
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(&e, buf, NULL);
    secp256k1_scalar_mul(&e, &e, &x);
    secp256k1_scalar_add(&e, &e, &k);

    secp256k1_scalar_get_b32(&sig->data[32], &e);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&x);

    return 1;
}

int secp256k1_schnorrsig_verify(const secp256k1_context* ctx, const secp256k1_schnorrsig *sig, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_fe rx;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_fe_set_b32(&rx, &sig->data[0])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, &sig->data[0], 32);
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_sha256_write(&sha, buf, sizeof(buf));
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&e, buf, NULL);

    /* Compute rj =  s*G + (-e)*pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&ctx->ecmult_ctx, &rj, &pkj, &e, &s);

    return secp256k1_gej_has_quad_y_var(&rj) /* fails if rj is infinity */
            && secp256k1_gej_eq_x_var(&rx, &rj);
}

/* Data that is used by the batch verification ecmult callback */
typedef struct {
    const secp256k1_context *ctx;
    /* Seed for the random number generator */
    unsigned char chacha_seed[32];
    /* Caches randomizers generated by the PRNG which returns two randomizers per call. Caching
     * avoids having to call the PRNG twice as often. The very first randomizer will be set to 1 and
     * the PRNG is called at every odd indexed schnorrsig to fill the cache. */
    secp256k1_scalar randomizer_cache[2];
    /* Signature, message, public key tuples to verify */
    const secp256k1_schnorrsig *const *sig;
    const unsigned char *const *msg32;
    const secp256k1_xonly_pubkey *const *pk;
    size_t n_sigs;
} secp256k1_schnorrsig_verify_ecmult_context;

/* Callback function which is called by ecmult_multi in order to convert the ecmult_context
 * consisting of signature, message and public key tuples into scalars and points. */
static int secp256k1_schnorrsig_verify_batch_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_schnorrsig_verify_ecmult_context *ecmult_context = (secp256k1_schnorrsig_verify_ecmult_context *) data;

    if (idx % 4 == 2) {
        /* Every idx corresponds to a (scalar,point)-tuple. So this callback is called with 4
         * consecutive tuples before we need to call the RNG for new randomizers:
         * (-randomizer_cache[0], R1)
         * (-randomizer_cache[0]*e1, P1)
         * (-randomizer_cache[1], R2)
         * (-randomizer_cache[1]*e2, P2) */
        secp256k1_scalar_chacha20(&ecmult_context->randomizer_cache[0], &ecmult_context->randomizer_cache[1], ecmult_context->chacha_seed, idx / 4);
    }

    /* R */
    if (idx % 2 == 0) {
        secp256k1_fe rx;
        *sc = ecmult_context->randomizer_cache[(idx / 2) % 2];
        if (!secp256k1_fe_set_b32(&rx, &ecmult_context->sig[idx / 2]->data[0])) {
            return 0;
        }
        if (!secp256k1_ge_set_xquad(pt, &rx)) {
            return 0;
        }
    /* eP */
    } else {
        unsigned char buf[32];
        secp256k1_sha256 sha;

        /* xonly_pubkey_load is guaranteed not to fail because
         * verify_batch_init_randomizer calls secp256k1_ec_pubkey_serialize
         * which only works if loading the pubkey into a group element
         * succeeds.*/
        VERIFY_CHECK(secp256k1_xonly_pubkey_load(ecmult_context->ctx, pt, ecmult_context->pk[idx / 2]));

        secp256k1_schnorrsig_sha256_tagged(&sha);
        secp256k1_sha256_write(&sha, &ecmult_context->sig[idx / 2]->data[0], 32);
        secp256k1_fe_get_b32(buf, &pt->x);
        secp256k1_sha256_write(&sha, buf, sizeof(buf));
        secp256k1_sha256_write(&sha, ecmult_context->msg32[idx / 2], 32);
        secp256k1_sha256_finalize(&sha, buf);

        secp256k1_scalar_set_b32(sc, buf, NULL);
        secp256k1_scalar_mul(sc, sc, &ecmult_context->randomizer_cache[(idx / 2) % 2]);
    }
    return 1;
}

/** Helper function for batch verification. Hashes signature verification data into the
 *  randomization seed and initializes ecmult_context.
 *
 *  Returns 1 if the randomizer was successfully initialized.
 *
 *  Args:    ctx: a secp256k1 context object
 *  Out: ecmult_context: context for batch_ecmult_callback
 *  In/Out   sha: an initialized sha256 object which hashes the schnorrsig input in order to get a
 *                seed for the randomizer PRNG
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays (must be 0 if they are NULL)
 */
static int secp256k1_schnorrsig_verify_batch_init_randomizer(const secp256k1_context *ctx, secp256k1_schnorrsig_verify_ecmult_context *ecmult_context, secp256k1_sha256 *sha, const secp256k1_schnorrsig *const *sig, const unsigned char *const *msg32, const secp256k1_xonly_pubkey *const *pk, size_t n_sigs) {
    size_t i;

    if (n_sigs > 0) {
        ARG_CHECK(sig != NULL);
        ARG_CHECK(msg32 != NULL);
        ARG_CHECK(pk != NULL);
    }

    for (i = 0; i < n_sigs; i++) {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_sha256_write(sha, sig[i]->data, 64);
        secp256k1_sha256_write(sha, msg32[i], 32);
        /* We use compressed serialization here. If we would use
         * xonly_pubkey serialization and a user would wrongly memcpy
         * normal secp256k1_pubkeys into xonly_pubkeys then the randomizer
         * would be the same for two different pubkeys. */
        if (!secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, (const secp256k1_pubkey *) pk[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        secp256k1_sha256_write(sha, buf, buflen);
    }
    ecmult_context->ctx = ctx;
    ecmult_context->sig = sig;
    ecmult_context->msg32 = msg32;
    ecmult_context->pk = pk;
    ecmult_context->n_sigs = n_sigs;

    return 1;
}

/** Helper function for batch verification. Sums the s part of all signatures multiplied by their
 *  randomizer.
 *
 *  Returns 1 if s is successfully summed.
 *
 *  In/Out: s: the s part of the input sigs is added to this s argument
 *  In:  chacha_seed: PRNG seed for computing randomizers
 *        sig: array of signatures, or NULL if there are no signatures
 *     n_sigs: number of signatures in above array (must be 0 if they are NULL)
 */
static int secp256k1_schnorrsig_verify_batch_sum_s(secp256k1_scalar *s, unsigned char *chacha_seed, const secp256k1_schnorrsig *const *sig, size_t n_sigs) {
    secp256k1_scalar randomizer_cache[2];
    size_t i;

    secp256k1_scalar_set_int(&randomizer_cache[0], 1);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;
        if (i % 2 == 1) {
            secp256k1_scalar_chacha20(&randomizer_cache[0], &randomizer_cache[1], chacha_seed, i / 2);
        }

        secp256k1_scalar_set_b32(&term, &sig[i]->data[32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_mul(&term, &term, &randomizer_cache[i % 2]);
        secp256k1_scalar_add(s, s, &term);
    }
    return 1;
}

/* schnorrsig batch verification.
 * Seeds a random number generator with the inputs and derives a random number ai for every
 * signature i. Fails if y-coordinate of any R is not a quadratic residue or if
 * 0 != -(s1 + a2*s2 + ... + au*su)G + R1 + a2*R2 + ... + au*Ru + e1*P1 + (a2*e2)P2 + ... + (au*eu)Pu. */
int secp256k1_schnorrsig_verify_batch(const secp256k1_context *ctx, secp256k1_scratch *scratch, const secp256k1_schnorrsig *const *sig, const unsigned char *const *msg32, const secp256k1_xonly_pubkey *const *pk, size_t n_sigs) {
    secp256k1_schnorrsig_verify_ecmult_context ecmult_context;
    secp256k1_sha256 sha;
    secp256k1_scalar s;
    secp256k1_gej rj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    /* Check that n_sigs is less than half of the maximum size_t value. This is necessary because
     * the number of points given to ecmult_multi is 2*n_sigs. */
    ARG_CHECK(n_sigs <= SIZE_MAX / 2);
    /* Check that n_sigs is less than 2^31 to ensure the same behavior of this function on 32-bit
     * and 64-bit platforms. */
    ARG_CHECK(n_sigs < ((uint32_t)1 << 31));

    secp256k1_sha256_initialize(&sha);
    if (!secp256k1_schnorrsig_verify_batch_init_randomizer(ctx, &ecmult_context, &sha, sig, msg32, pk, n_sigs)) {
        return 0;
    }
    secp256k1_sha256_finalize(&sha, ecmult_context.chacha_seed);
    secp256k1_scalar_set_int(&ecmult_context.randomizer_cache[0], 1);

    secp256k1_scalar_clear(&s);
    if (!secp256k1_schnorrsig_verify_batch_sum_s(&s, ecmult_context.chacha_seed, sig, n_sigs)) {
        return 0;
    }
    secp256k1_scalar_negate(&s, &s);

    return secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &rj, &s, secp256k1_schnorrsig_verify_batch_ecmult_callback, (void *) &ecmult_context, 2 * n_sigs)
            && secp256k1_gej_is_infinity(&rj);
}

#endif
