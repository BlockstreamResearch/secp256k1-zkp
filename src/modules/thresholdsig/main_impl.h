/**********************************************************************
 * Copyright (c) 2019 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_THRESHOLDSIG_MAIN_
#define _SECP256K1_MODULE_THRESHOLDSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_thresholdsig.h"
#include "hash.h"

int secp256k1_thresholdsig_keysplit(const secp256k1_context *ctx, secp256k1_thresholdsig_keyshard *shards, secp256k1_pubkey *pubcoeff, const unsigned char *seckey, const size_t k, const size_t n) {
    secp256k1_sha256 sha;
    size_t i;
    int overflow;
    unsigned char rngseed[32];
    secp256k1_scalar const_term;
    secp256k1_scalar rand[2];
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shards != NULL);
    ARG_CHECK(pubcoeff != NULL);
    ARG_CHECK(seckey != NULL);

    if (k == 0 || k >= n) {
        return 0;
    }

    /* Compute constant term of the polynomial, which is equal to the complete
     * signing key. Multiply by the MuSig coefficient now because after this step,
     * different signers' keys will be mixed and we will no longer be able to
     * multiply them by different constants. */
    secp256k1_scalar_set_b32(&const_term, seckey, &overflow);
    if (overflow) {
        return 0;
    }

    /* Compute public point corresponding to the constant term */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &const_term);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubcoeff[0], &rp);

    /* Compute a random seed which commits to all inputs */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i + 0] = k / (1ull << (i * 8));
        rngseed[i + 8] = n / (1ull << (i * 8));
    }
    secp256k1_sha256_write(&sha, rngseed, 16);
    secp256k1_sha256_finalize(&sha, rngseed);

    /* Evaluate the polynomial at nonzero values to get the keyshards, setting
     * the coefficients of the non-constant term to random secrets */
    for (i = 0; i < n; i++) {
        secp256k1_scalar shard_i;
        secp256k1_scalar scalar_i;
        size_t j;

        secp256k1_scalar_clear(&shard_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = 0; j < k - 1; j++) {
            if (j % 2 == 0) {
                secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, j);
            }
            secp256k1_scalar_add(&shard_i, &shard_i, &rand[j % 2]);
            secp256k1_scalar_mul(&shard_i, &shard_i, &scalar_i);
        }
        secp256k1_scalar_add(&shard_i, &shard_i, &const_term);
        secp256k1_scalar_get_b32(shards[i].data, &shard_i);
    }

    /* Compute public points corresponding to each shard */
    for (i = 0; i < k - 1; i++) {
        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubcoeff[k - i - 1], &rp);
    }

    return 1;
}


typedef struct {
    secp256k1_scalar musig_coeff;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey *pubcoeff;
} secp256k1_thresholdsig_verify_shard_ecmult_context;

static int secp256k1_thresholdsig_verify_shard_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_thresholdsig_verify_shard_ecmult_context *ctx = (secp256k1_thresholdsig_verify_shard_ecmult_context *) data;

    secp256k1_scalar_mul(sc, &ctx->musig_coeff, &ctx->idxn);
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);
    secp256k1_pubkey_load(NULL, pt, &ctx->pubcoeff[idx]);
    return 1;
}

int secp256k1_thresholdsig_verify_shard(const secp256k1_context *ctx, secp256k1_scratch *scratch, unsigned char *seckey, secp256k1_pubkey *signer_pubkeys, size_t n_keys, const unsigned char *pk_hash, int continuing, const secp256k1_thresholdsig_keyshard *privshard, size_t my_idx, size_t other_idx, const secp256k1_pubkey *pubcoeff, size_t n_coeffs) {
    size_t i;
    secp256k1_thresholdsig_verify_shard_ecmult_context ecmult_data;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(signer_pubkeys != NULL);
    ARG_CHECK(pk_hash != NULL);
    ARG_CHECK(pubcoeff != NULL);

    if (n_keys == 0 || n_coeffs == 0 || n_coeffs >= n_keys || my_idx >= n_keys || other_idx >= n_keys) {
        return 0;
    }

    ecmult_data.pubcoeff = pubcoeff;
    secp256k1_musig_coefficient(&ecmult_data.musig_coeff, pk_hash, other_idx);

    /* For each participant... */
    for (i = 0; i < n_keys; i++) {
        secp256k1_ge shardp;
        secp256k1_gej shardj;

        /* ...compute the participant's public shard by evaluating the public polynomial at their index */
        secp256k1_scalar_set_int(&ecmult_data.idx, i + 1);
        secp256k1_scalar_set_int(&ecmult_data.idxn, 1);

        if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &shardj, NULL, secp256k1_thresholdsig_verify_shard_ecmult_callback, (void *) &ecmult_data, n_coeffs)) {
            return 0;
        }

        /* If we computed our _own_ public shard, check that it is consistent with our private
         * shard. This check is equation (*) in the Pedersen VSS paper. This is the only part
         * of the function that handles secret data and which must be constant-time. */
        if (i == my_idx && privshard != NULL) {
            int overflow;
            secp256k1_gej expectedj;
            secp256k1_scalar shards;
            secp256k1_scalar_set_b32(&shards, privshard->data, &overflow);
            secp256k1_scalar_mul(&shards, &shards, &ecmult_data.musig_coeff);
            if (overflow) {
                return 0;
            }
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &expectedj, &shards);
            secp256k1_gej_neg(&expectedj, &expectedj);
            secp256k1_gej_add_var(&expectedj, &expectedj, &shardj, NULL);
            if (!secp256k1_gej_is_infinity(&expectedj)) {
                return 0;
            }

            if (seckey != NULL) {
                if (continuing) {
                    secp256k1_scalar current;
                    secp256k1_scalar_set_b32(&current, seckey, &overflow);
                    if (overflow) {
                        return 0;
                    }
                    secp256k1_scalar_add(&shards, &shards, &current);
                }
                secp256k1_scalar_get_b32(seckey, &shards);
            }
        }

        /* Add the shard to the public key we expect them to use when signing (well, when
         * signing they will additionally multiply the pubkey by a Lagrange coefficient,
         * but this cannot be determined until signing time). */
        if (continuing) {
            secp256k1_ge ge;
            if (!secp256k1_pubkey_load(ctx, &ge, &signer_pubkeys[i])) {
                return 0;
            }
            secp256k1_gej_add_ge_var(&shardj, &shardj, &ge, NULL);
        }
        if (secp256k1_gej_is_infinity(&shardj)) {
            return 0;
        }
        secp256k1_ge_set_gej(&shardp, &shardj);
        secp256k1_pubkey_save(&signer_pubkeys[i], &shardp);
    }

    return 1;
}

/* `data` is just used as a binary array indicating which signers are present, i.e.
 * which ones to exclude from the interpolation. */
static void secp256k1_thresholdsig_lagrange_coefficient(secp256k1_scalar *r, const secp256k1_musig_session_signer_data *data, size_t n_signers, size_t coeff_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar indexs;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&indexs, (int) coeff_index + 1);
    for (i = 0; i < n_signers; i++) {
        secp256k1_scalar mul;
        if (data[i].index == coeff_index) {
            continue;
        }

        secp256k1_scalar_set_int(&mul, (int) data[i].index + 1);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &indexs);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

static void secp256k1_thresholdsig_signers_init(secp256k1_musig_session_signer_data *signers, const size_t *indices, uint32_t n_signers) {
    uint32_t i;
    for (i = 0; i < n_signers; i++) {
        memset(&signers[i], 0, sizeof(signers[i]));
        signers[i].index = indices[i];
        signers[i].present = 0;
    }
}

int secp256k1_thresholdsig_session_initialize(const secp256k1_context* ctx, secp256k1_musig_session *session, secp256k1_musig_session_signer_data *signers, unsigned char *nonce_commitment32, const unsigned char *session_id32, const unsigned char *msg32, const secp256k1_pubkey *combined_pk, const size_t *indices, size_t n_signers, size_t my_index, const unsigned char *seckey) {
    unsigned char combined_ser[33];
    size_t combined_ser_size = sizeof(combined_ser);
    int overflow;
    secp256k1_scalar secret;
    secp256k1_scalar lagrange_coeff;
    secp256k1_sha256 sha;
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(session != NULL);
    ARG_CHECK(nonce_commitment32 != NULL);
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(signers != NULL);
    ARG_CHECK(indices != NULL);
    ARG_CHECK(seckey != NULL);

    if (msg32 != NULL) {
        memcpy(session->msg, msg32, 32);
        session->msg_is_set = 1;
    } else {
        session->msg_is_set = 0;
    }
    memcpy(&session->combined_pk, combined_pk, sizeof(*combined_pk));
    memset(session->pk_hash, 0, 32);
    session->nonce_is_set = 0;
    session->has_secret_data = 1;
    if (n_signers == 0) { /* my_index > n_signers is permissible since `my_index` indexes into the full signer set */
        return 0;
    }
    session->n_signers = n_signers;
    secp256k1_thresholdsig_signers_init(signers, indices, n_signers);
    session->nonce_commitments_hash_is_set = 0;

    /* Compute secret key - no MuSig coefficient, since we assume that was
     * applied during keyshard verification. In fact at this point we cannot
     * even compute the MuSig coefficients because we do not have access to
     * the original secret keys. However we *do* need to multiply by a
     * Lagrange coefficient corresponding to the set of signers that are
     * actually available at this point. */
    secp256k1_scalar_set_b32(&secret, seckey, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_thresholdsig_lagrange_coefficient(&lagrange_coeff, signers, n_signers, my_index);
    secp256k1_scalar_mul(&secret, &secret, &lagrange_coeff);
    secp256k1_scalar_get_b32(session->seckey, &secret);

    /* Compute secret nonce */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey, 32);
    secp256k1_sha256_write(&sha, session_id32, 32);
    if (session->msg_is_set) {
        secp256k1_sha256_write(&sha, msg32, 32);
    }
    secp256k1_ec_pubkey_serialize(ctx, combined_ser, &combined_ser_size, combined_pk, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, combined_ser, combined_ser_size);
    secp256k1_sha256_finalize(&sha, session->secnonce);
    secp256k1_scalar_set_b32(&secret, session->secnonce, &overflow);
    if (overflow) {
        return 0;
    }

    /* Compute public nonce and commitment */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &secret);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&session->nonce, &rp);

    if (nonce_commitment32 != NULL) {
        unsigned char commit[33];
        size_t commit_size = sizeof(commit);
        secp256k1_sha256_initialize(&sha);
        secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, &session->nonce, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, commit, commit_size);
        secp256k1_sha256_finalize(&sha, nonce_commitment32);
    }

    secp256k1_scalar_clear(&secret);
    return 1;
}

/* TODO this is literally identical to secp256k1_musig_partial_sig_verify except
 *      the musig coefficient is replaced by a Lagrange coefficient. Surely we can share more code?
*/
int secp256k1_thresholdsig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_session *session, const secp256k1_musig_session_signer_data *signers, size_t n_signers, size_t signer_idx, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_pubkey *pubkey) {
    unsigned char msghash[32];
    secp256k1_scalar lagrange_coeff;
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(session != NULL);
    ARG_CHECK(signers != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!session->nonce_is_set || !signers[signer_idx].present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_musig_compute_messagehash(ctx, msghash, session)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, msghash, NULL);

    /* Multiplying the messagehash by the Lagrange coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_thresholdsig_lagrange_coefficient(&lagrange_coeff, signers, n_signers, signers[signer_idx].index);
    secp256k1_scalar_mul(&e, &e, &lagrange_coeff);

    if (!secp256k1_pubkey_load(ctx, &rp, &signers[signer_idx].nonce)) {
        return 0;
    }

    if (!secp256k1_schnorrsig_real_verify(ctx, &rj, &s, &e, pubkey)) {
        return 0;
    }
    if (!session->nonce_is_negated) {
        secp256k1_ge_neg(&rp, &rp);
    }
    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);

    return secp256k1_gej_is_infinity(&rj);
}


#endif
