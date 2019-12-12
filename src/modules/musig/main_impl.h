/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra, Jonas Nick                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_MAIN_
#define _SECP256K1_MODULE_MUSIG_MAIN_

#include <stdint.h>
#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "hash.h"

/* Computes ell = SHA256(pk[0], ..., pk[np-1]) */
static int secp256k1_musig_compute_ell(const secp256k1_context *ctx, unsigned char *ell, const secp256k1_xonly_pubkey *pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &pk[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, 32);
    }
    secp256k1_sha256_finalize(&sha, ell);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("MuSig coefficient")||SHA256("MuSig coefficient"). */
static void secp256k1_musig_sha256_init_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x0fd0690cul;
    sha->s[1] = 0xfefeae97ul;
    sha->s[2] = 0x996eac7ful;
    sha->s[3] = 0x5c30d864ul;
    sha->s[4] = 0x8c4a0573ul;
    sha->s[5] = 0xaca1a22ful;
    sha->s[6] = 0x6f43b801ul;
    sha->s[7] = 0x85ce27cdul;
    sha->bytes = 64;
}

/* Compute r = SHA256(ell, idx). The four bytes of idx are serialized least significant byte first. */
static void secp256k1_musig_coefficient(secp256k1_scalar *r, const unsigned char *ell, uint32_t idx) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    size_t i;

    secp256k1_musig_sha256_init_tagged(&sha);
    secp256k1_sha256_write(&sha, ell, 32);
    /* We're hashing the index of the signer instead of its public key as specified
     * in the MuSig paper. This reduces the total amount of data that needs to be
     * hashed.
     * Additionally, it prevents creating identical musig_coefficients for identical
     * public keys. A participant Bob could choose his public key to be the same as
     * Alice's, then replay Alice's messages (nonce and partial signature) to create
     * a valid partial signature. This is not a problem for MuSig per se, but could
     * result in subtle issues with protocols building on threshold signatures.
     * With the assumption that public keys are unique, hashing the index is
     * equivalent to hashing the public key. Because the public key can be
     * identified by the index given the ordered list of public keys (included in
     * ell), the index is just a different encoding of the public key.*/
    for (i = 0; i < sizeof(uint32_t); i++) {
        unsigned char c = idx;
        secp256k1_sha256_write(&sha, &c, 1);
        idx >>= 8;
    }
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(r, buf, NULL);
}

typedef struct {
    const secp256k1_context *ctx;
    unsigned char ell[32];
    const secp256k1_xonly_pubkey *pks;
} secp256k1_musig_pubkey_combine_ecmult_data;

/* Callback for batch EC multiplication to compute ell_0*P0 + ell_1*P1 + ...  */
static int secp256k1_musig_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pubkey_combine_ecmult_data *ctx = (secp256k1_musig_pubkey_combine_ecmult_data *) data;
    secp256k1_musig_coefficient(sc, ctx->ell, idx);
    return secp256k1_xonly_pubkey_load(ctx->ctx, pt, &ctx->pks[idx]);
}


static void secp256k1_musig_signers_init(secp256k1_musig_session_signer_data *signers, uint32_t n_signers) {
    uint32_t i;
    for (i = 0; i < n_signers; i++) {
        memset(&signers[i], 0, sizeof(signers[i]));
        signers[i].index = i;
        signers[i].present = 0;
    }
}

static const uint64_t pre_session_magic = 0xf4adbbdf7c7dd304UL;

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_xonly_pubkey *combined_pk, secp256k1_musig_pre_session *pre_session, const secp256k1_xonly_pubkey *pubkeys, size_t n_pubkeys) {
    secp256k1_musig_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    int is_negated;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;
    if (!secp256k1_musig_compute_ell(ctx, ecmult_data.ell, pubkeys, n_pubkeys)) {
        return 0;
    }
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_musig_pubkey_combine_callback, (void *) &ecmult_data, n_pubkeys)) {
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_ge_absolute(&pkp, &is_negated);
    secp256k1_xonly_pubkey_save(combined_pk, &pkp);

    if (pre_session != NULL) {
        pre_session->magic = pre_session_magic;
        memcpy(pre_session->pk_hash, ecmult_data.ell, 32);
        pre_session->is_negated = is_negated;
        pre_session->tweak_is_set = 0;
    }
    return 1;
}

int secp256k1_musig_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_musig_pre_session *pre_session, secp256k1_xonly_pubkey *output_pubkey, int *is_negated, const secp256k1_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    /* This function can only be called once because otherwise signing would not
     * succeed */
    ARG_CHECK(pre_session->tweak_is_set == 0);

    pre_session->internal_key_is_negated = pre_session->is_negated;
    if(!secp256k1_xonly_pubkey_tweak_add(ctx, output_pubkey, is_negated, internal_pubkey, tweak32)) {
        return 0;
    }
    memcpy(pre_session->tweak, tweak32, 32);
    pre_session->tweak_is_set = 1;
    pre_session->is_negated = *is_negated;
    return 1;
}

int secp256k1_musig_session_initialize(const secp256k1_context* ctx, secp256k1_musig_session *session, secp256k1_musig_session_signer_data *signers, unsigned char *nonce_commitment32, const unsigned char *session_id32, const unsigned char *msg32, const secp256k1_xonly_pubkey *combined_pk, const secp256k1_musig_pre_session *pre_session, size_t n_signers, size_t my_index, const unsigned char *seckey) {
    unsigned char combined_ser[32];
    int overflow;
    secp256k1_scalar secret;
    secp256k1_scalar mu;
    secp256k1_sha256 sha;
    secp256k1_gej pj;
    secp256k1_ge p;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(session != NULL);
    ARG_CHECK(signers != NULL);
    ARG_CHECK(nonce_commitment32 != NULL);
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    ARG_CHECK(seckey != NULL);

    memset(session, 0, sizeof(*session));

    if (msg32 != NULL) {
        memcpy(session->msg, msg32, 32);
        session->msg_is_set = 1;
    } else {
        session->msg_is_set = 0;
    }
    memcpy(&session->combined_pk, combined_pk, sizeof(*combined_pk));
    session->pre_session = *pre_session;
    session->nonce_is_set = 0;
    session->has_secret_data = 1;
    if (n_signers == 0 || my_index >= n_signers) {
        return 0;
    }
    if (n_signers > UINT32_MAX) {
        return 0;
    }
    session->n_signers = (uint32_t) n_signers;
    secp256k1_musig_signers_init(signers, session->n_signers);
    session->nonce_commitments_hash_is_set = 0;

    /* Compute secret key */
    secp256k1_scalar_set_b32(&secret, seckey, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&secret);
        return 0;
    }
    secp256k1_musig_coefficient(&mu, session->pre_session.pk_hash, (uint32_t) my_index);
    /* Compute the signers public key point and determine if the secret is
     * negated before signing. That happens if the signer's pubkey is negated
     * XOR the MuSig-combined pubkey is negated XOR (if tweaked) the internal
     * key is negated before tweaking.  This can be seen by looking at the
     * secret key belonging to `combined_pk`.
     * Let's define
     * P' := mu_0*|P_0| + ... + mu_n*|P_n| where P_i is the i-th public key
     * point x_i*G, mu_i is the i-th musig coefficient and |.| is a function
     * that normalizes a point to a square Y by negating if necessary similar to
     * secp256k1_ge_absolute.
     * P := |P'| + t*G where t is the tweak. Then we have the combined xonly
     * public key |P| = x*G
     *      where x = sum_i(b_i*mu_i*x_i) + b'*t
     *            b' = -1 if P != |P|, 1 otherwise
     *            b_i = -1 if (P_i != |P_i| XOR P' != |P'| XOR P != |P|) and 1
     *                otherwise.
     */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &secret);
    if((!secp256k1_gej_has_quad_y_var(&pj)
            + session->pre_session.is_negated
            + (session->pre_session.tweak_is_set
                && session->pre_session.internal_key_is_negated))
            % 2 == 1) {
        secp256k1_scalar_negate(&secret, &secret);
    }
    secp256k1_scalar_mul(&secret, &secret, &mu);
    secp256k1_scalar_get_b32(session->seckey, &secret);

    /* Compute secret nonce */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, session_id32, 32);
    if (session->msg_is_set) {
        secp256k1_sha256_write(&sha, msg32, 32);
    }
    secp256k1_xonly_pubkey_serialize(ctx, combined_ser, combined_pk);
    secp256k1_sha256_write(&sha, combined_ser, 32);
    secp256k1_sha256_write(&sha, seckey, 32);
    secp256k1_sha256_finalize(&sha, session->secnonce);
    secp256k1_scalar_set_b32(&secret, session->secnonce, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&secret);
        return 0;
    }

    /* Compute public nonce and commitment */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &secret);
    secp256k1_ge_set_gej(&p, &pj);
    secp256k1_pubkey_save(&session->nonce, &p);

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

int secp256k1_musig_session_get_public_nonce(const secp256k1_context* ctx, secp256k1_musig_session *session, secp256k1_musig_session_signer_data *signers, secp256k1_pubkey *nonce, const unsigned char *const *commitments, size_t n_commitments, const unsigned char *msg32) {
    secp256k1_sha256 sha;
    unsigned char nonce_commitments_hash[32];
    size_t i;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signers != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(commitments != NULL);
    /* If the message was not set during initialization it must be set now. */
    ARG_CHECK(!(!session->msg_is_set && msg32 == NULL));
    /* The message can only be set once. */
    ARG_CHECK(!(session->msg_is_set && msg32 != NULL));

    if (!session->has_secret_data || n_commitments != session->n_signers) {
        return 0;
    }
    for (i = 0; i < n_commitments; i++) {
        ARG_CHECK(commitments[i] != NULL);
    }

    if (msg32 != NULL) {
        memcpy(session->msg, msg32, 32);
        session->msg_is_set = 1;
    }
    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < n_commitments; i++) {
        memcpy(signers[i].nonce_commitment, commitments[i], 32);
        secp256k1_sha256_write(&sha, commitments[i], 32);
    }
    secp256k1_sha256_finalize(&sha, nonce_commitments_hash);
    if (session->nonce_commitments_hash_is_set
            && memcmp(session->nonce_commitments_hash, nonce_commitments_hash, 32) != 0) {
        /* Abort if get_public_nonce has been called before with a different array of
         * commitments. */
        return 0;
    }
    memcpy(session->nonce_commitments_hash, nonce_commitments_hash, 32);
    session->nonce_commitments_hash_is_set = 1;
    memcpy(nonce, &session->nonce, sizeof(*nonce));
    return 1;
}

int secp256k1_musig_session_initialize_verifier(const secp256k1_context* ctx, secp256k1_musig_session *session, secp256k1_musig_session_signer_data *signers, const unsigned char *msg32, const secp256k1_xonly_pubkey *combined_pk, const secp256k1_musig_pre_session *pre_session, const unsigned char *const *commitments, size_t n_signers) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signers != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    ARG_CHECK(commitments != NULL);
    /* Check n_signers before checking commitments to allow testing the case where
     * n_signers is big without allocating the space. */
    if (n_signers > UINT32_MAX) {
        return 0;
    }
    for (i = 0; i < n_signers; i++) {
        ARG_CHECK(commitments[i] != NULL);
    }
    (void) ctx;

    memset(session, 0, sizeof(*session));

    memcpy(&session->combined_pk, combined_pk, sizeof(*combined_pk));
    session->pre_session = *pre_session;
    if (n_signers == 0) {
        return 0;
    }
    session->n_signers = (uint32_t) n_signers;
    secp256k1_musig_signers_init(signers, session->n_signers);

    session->pre_session = *pre_session;
    session->nonce_is_set = 0;
    session->msg_is_set = 1;
    memcpy(session->msg, msg32, 32);
    session->has_secret_data = 0;
    session->nonce_commitments_hash_is_set = 0;

    for (i = 0; i < n_signers; i++) {
        memcpy(signers[i].nonce_commitment, commitments[i], 32);
    }
    return 1;
}

int secp256k1_musig_set_nonce(const secp256k1_context* ctx, secp256k1_musig_session_signer_data *signer, const secp256k1_pubkey *nonce) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(signer != NULL);
    ARG_CHECK(nonce != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, nonce, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, commit, commit_size);
    secp256k1_sha256_finalize(&sha, commit);

    if (memcmp(commit, signer->nonce_commitment, 32) != 0) {
        return 0;
    }
    memcpy(&signer->nonce, nonce, sizeof(*nonce));
    signer->present = 1;
    return 1;
}

int secp256k1_musig_session_combine_nonces(const secp256k1_context* ctx, secp256k1_musig_session *session, const secp256k1_musig_session_signer_data *signers, size_t n_signers, int *nonce_is_negated, const secp256k1_pubkey *adaptor) {
    secp256k1_gej combined_noncej;
    secp256k1_ge combined_noncep;
    secp256k1_ge noncep;
    secp256k1_sha256 sha;
    unsigned char nonce_commitments_hash[32];
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signers != NULL);

    if (n_signers != session->n_signers) {
        return 0;
    }
    secp256k1_sha256_initialize(&sha);
    secp256k1_gej_set_infinity(&combined_noncej);
    for (i = 0; i < n_signers; i++) {
        if (!signers[i].present) {
            return 0;
        }
        secp256k1_sha256_write(&sha, signers[i].nonce_commitment, 32);
        secp256k1_pubkey_load(ctx, &noncep, &signers[i].nonce);
        secp256k1_gej_add_ge_var(&combined_noncej, &combined_noncej, &noncep, NULL);
    }
    secp256k1_sha256_finalize(&sha, nonce_commitments_hash);
    /* Either the session is a verifier session or or the nonce_commitments_hash has
     * been set in `musig_session_get_public_nonce`. */
    VERIFY_CHECK(!session->has_secret_data || session->nonce_commitments_hash_is_set);
    if (session->has_secret_data
            && memcmp(session->nonce_commitments_hash, nonce_commitments_hash, 32) != 0) {
        /* If the signers' commitments changed between get_public_nonce and now we
         * have to abort because in that case they may have seen our nonce before
         * creating their commitment. That can happen if the signer_data given to
         * this function is different to the signer_data given to get_public_nonce.
         * */
        return 0;
    }

    /* Add public adaptor to nonce */
    if (adaptor != NULL) {
        secp256k1_pubkey_load(ctx, &noncep, adaptor);
        secp256k1_gej_add_ge_var(&combined_noncej, &combined_noncej, &noncep, NULL);
    }
    secp256k1_ge_set_gej(&combined_noncep, &combined_noncej);
    if (secp256k1_fe_is_quad_var(&combined_noncep.y)) {
        session->nonce_is_negated = 0;
    } else {
        session->nonce_is_negated = 1;
        secp256k1_ge_neg(&combined_noncep, &combined_noncep);
    }
    if (nonce_is_negated != NULL) {
        *nonce_is_negated = session->nonce_is_negated;
    }
    secp256k1_pubkey_save(&session->combined_nonce, &combined_noncep);
    session->nonce_is_set = 1;
    return 1;
}

int secp256k1_musig_partial_signature_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_musig_partial_signature* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out32, sig->data, 32);
    return 1;
}

int secp256k1_musig_partial_signature_parse(const secp256k1_context* ctx, secp256k1_musig_partial_signature* sig, const unsigned char *in32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);
    memcpy(sig->data, in32, 32);
    return 1;
}

/* Compute msghash = SHA256(combined_nonce, combined_pk, msg) */
static int secp256k1_musig_compute_messagehash(const secp256k1_context *ctx, unsigned char *msghash, const secp256k1_musig_session *session) {
    unsigned char buf[32];
    secp256k1_ge rp;
    secp256k1_sha256 sha;

    secp256k1_schnorrsig_sha256_tagged(&sha);
    if (!session->nonce_is_set) {
        return 0;
    }
    secp256k1_pubkey_load(ctx, &rp, &session->combined_nonce);
    secp256k1_fe_get_b32(buf, &rp.x);
    secp256k1_sha256_write(&sha, buf, 32);

    secp256k1_xonly_pubkey_serialize(ctx, buf, &session->combined_pk);
    secp256k1_sha256_write(&sha, buf, 32);
    if (!session->msg_is_set) {
        return 0;
    }
    secp256k1_sha256_write(&sha, session->msg, 32);
    secp256k1_sha256_finalize(&sha, msghash);
    return 1;
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, const secp256k1_musig_session *session, secp256k1_musig_partial_signature *partial_sig) {
    unsigned char msghash[32];
    int overflow;
    secp256k1_scalar sk;
    secp256k1_scalar e, k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(session != NULL);

    if (!session->nonce_is_set || !session->has_secret_data) {
        return 0;
    }

    /* build message hash */
    if (!secp256k1_musig_compute_messagehash(ctx, msghash, session)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, msghash, NULL);

    secp256k1_scalar_set_b32(&sk, session->seckey, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&sk);
        return 0;
    }

    secp256k1_scalar_set_b32(&k, session->secnonce, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        secp256k1_scalar_clear(&sk);
        secp256k1_scalar_clear(&k);
        return 0;
    }
    if (session->nonce_is_negated) {
        secp256k1_scalar_negate(&k, &k);
    }

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&partial_sig->data[0], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k);

    return 1;
}

int secp256k1_musig_partial_sig_combine(const secp256k1_context* ctx, const secp256k1_musig_session *session, secp256k1_schnorrsig *sig, const secp256k1_musig_partial_signature *partial_sigs, size_t n_sigs) {
    size_t i;
    secp256k1_scalar s;
    secp256k1_ge noncep;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(session != NULL);

    if (!session->nonce_is_set) {
        return 0;
    }
    if (n_sigs != session->n_signers) {
        return 0;
    }
    secp256k1_scalar_clear(&s);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;

        secp256k1_scalar_set_b32(&term, partial_sigs[i].data, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_add(&s, &s, &term);
    }
    /* If there is a tweak then add (or subtract) `msghash` times `tweak` to `s`.*/
    if (session->pre_session.tweak_is_set) {
        unsigned char msghash[32];
        secp256k1_scalar e, scalar_tweak;
        int overflow = 0;

        if (!secp256k1_musig_compute_messagehash(ctx, msghash, session)) {
            return 0;
        }
        secp256k1_scalar_set_b32(&e, msghash, NULL);
        secp256k1_scalar_set_b32(&scalar_tweak, session->pre_session.tweak, &overflow);
        if (overflow || !secp256k1_eckey_privkey_tweak_mul(&e, &scalar_tweak)) {
            /* This mimics the behavior of secp256k1_ec_privkey_tweak_mul regarding
             * overflow and tweak being 0. */
            return 0;
        }
        if (session->pre_session.is_negated) {
            secp256k1_scalar_negate(&e, &e);
        }
        secp256k1_scalar_add(&s, &s, &e);
    }

    secp256k1_pubkey_load(ctx, &noncep, &session->combined_nonce);
    VERIFY_CHECK(secp256k1_fe_is_quad_var(&noncep.y));
    secp256k1_fe_normalize(&noncep.x);
    secp256k1_fe_get_b32(&sig->data[0], &noncep.x);
    secp256k1_scalar_get_b32(&sig->data[32], &s);

    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_session *session, const secp256k1_musig_session_signer_data *signer, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_xonly_pubkey *pubkey) {
    unsigned char msghash[32];
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar mu;
    secp256k1_gej pkj;
    secp256k1_gej rj;
    secp256k1_ge pkp;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(session != NULL);
    ARG_CHECK(signer != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!session->nonce_is_set || !signer->present) {
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

    /* Multiplying the messagehash by the musig coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_musig_coefficient(&mu, session->pre_session.pk_hash, signer->index);
    secp256k1_scalar_mul(&e, &e, &mu);

    if (!secp256k1_pubkey_load(ctx, &rp, &signer->nonce)) {
        return 0;
    }
    /* If the MuSig-combined point is negated, the signers will sign for the
     * negation of their individual xonly public key such that the combined
     * signature is valid for the MuSig aggregated xonly key. If the
     * MuSig-combined point was tweaked then `e` is negated if the combined
     * key is negated XOR the internal key is negated.*/
    if (session->pre_session.is_negated
            + (session->pre_session.tweak_is_set
                && session->pre_session.internal_key_is_negated)
            % 2 == 1) {
        secp256k1_scalar_negate(&e, &e);
    }

    /* Compute rj =  s*G + (-e)*pkj */
    secp256k1_scalar_negate(&e, &e);
    if (!secp256k1_xonly_pubkey_load(ctx, &pkp, pubkey)) {
        return 0;
    }
    secp256k1_gej_set_ge(&pkj, &pkp);
    secp256k1_ecmult(&ctx->ecmult_ctx, &rj, &pkj, &e, &s);

    if (!session->nonce_is_negated) {
        secp256k1_ge_neg(&rp, &rp);
    }
    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);

    return secp256k1_gej_is_infinity(&rj);
}

int secp256k1_musig_partial_sig_adapt(const secp256k1_context* ctx, secp256k1_musig_partial_signature *adaptor_sig, const secp256k1_musig_partial_signature *partial_sig, const unsigned char *sec_adaptor32, int nonce_is_negated) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);

    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor32, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&t);
        return 0;
    }

    if (nonce_is_negated) {
        secp256k1_scalar_negate(&t, &t);
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(adaptor_sig->data, &s);
    secp256k1_scalar_clear(&t);
    return 1;
}

int secp256k1_musig_extract_secret_adaptor(const secp256k1_context* ctx, unsigned char *sec_adaptor32, const secp256k1_schnorrsig *sig, const secp256k1_musig_partial_signature *partial_sigs, size_t n_partial_sigs, int nonce_is_negated) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;
    size_t i;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sigs != NULL);

    secp256k1_scalar_set_b32(&t, &sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&t, &t);

    for (i = 0; i < n_partial_sigs; i++) {
        secp256k1_scalar_set_b32(&s, partial_sigs[i].data, &overflow);
        if (overflow) {
            secp256k1_scalar_clear(&t);
            return 0;
        }
        secp256k1_scalar_add(&t, &t, &s);
    }

    if (!nonce_is_negated) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_get_b32(sec_adaptor32, &t);
    secp256k1_scalar_clear(&t);
    return 1;
}

#endif
