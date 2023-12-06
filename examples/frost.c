/***********************************************************************
 * Copyright (c) 2021-2023  Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/**
 * This file demonstrates how to use the FROST module to create a threshold
 * signature. Additionally, see the documentation in include/secp256k1_frost.h.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_frost.h>

#include "examples_util.h"
/* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 5

/* Threshold required in creating the aggregate signature */
#define THRESHOLD 3

struct signer_secrets {
    secp256k1_frost_share share;
    secp256k1_frost_secnonce secnonce;
};

struct signer {
    secp256k1_pubkey pubshare;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_frost_session session;
    secp256k1_frost_partial_sig partial_sig;
};

/* Create shares and coefficient commitments */
int create_shares(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signers, secp256k1_xonly_pubkey *pk) {
    int i;
    secp256k1_frost_share shares[N_SIGNERS];
    secp256k1_pubkey pubshares[N_SIGNERS];
    unsigned char seed[32];

    if (!fill_random(seed, sizeof(seed))) {
        return 0;
    }

    if (!secp256k1_frost_shares_trusted_gen(ctx, shares, pubshares, pk, seed, THRESHOLD, N_SIGNERS)) {
        return 0;
    }

    for (i = 0; i < N_SIGNERS; i++) {
        signer_secrets[i].share = shares[i];
        signers[i].pubshare = pubshares[i];
    }

    return 1;
}

/* Tweak the pubkey corresponding to the provided tweak cache, update the cache
 * and return the tweaked aggregate pk. */
int tweak(const secp256k1_context* ctx, secp256k1_xonly_pubkey *pk, secp256k1_frost_tweak_cache *cache) {
    secp256k1_pubkey output_pk;
    unsigned char ordinary_tweak[32] = "this could be a BIP32 tweak....";
    unsigned char xonly_tweak[32] = "this could be a taproot tweak..";

    if (!secp256k1_frost_pubkey_tweak(ctx, cache, pk)) {
        return 0;
    }

    /* Ordinary tweaking which, for example, allows deriving multiple child
     * public keys from a single aggregate key using BIP32 */
    if (!secp256k1_frost_pubkey_ec_tweak_add(ctx, NULL, cache, ordinary_tweak)) {
        return 0;
    }
    /* If one is not interested in signing, the same output_pk can be obtained
     * by calling `secp256k1_frost_pubkey_get` right after key aggregation to
     * get the full pubkey and then call `secp256k1_ec_pubkey_tweak_add`. */

    /* Xonly tweaking which, for example, allows creating taproot commitments */
    if (!secp256k1_frost_pubkey_xonly_tweak_add(ctx, &output_pk, cache, xonly_tweak)) {
        return 0;
    }
    /* Note that if we wouldn't care about signing, we can arrive at the same
     * output_pk by providing the untweaked public key to
     * `secp256k1_xonly_pubkey_tweak_add` (after converting it to an xonly pubkey
     * if necessary with `secp256k1_xonly_pubkey_from_pubkey`). */

    /* Now we convert the output_pk to an xonly pubkey to allow to later verify
     * the Schnorr signature against it. For this purpose we can ignore the
     * `pk_parity` output argument; we would need it if we would have to open
     * the taproot commitment. */
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, pk, NULL, &output_pk)) {
        return 0;
    }
    return 1;
}

/* Sign a message hash with the given threshold and aggregate shares and store
 * the result in sig */
int sign(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, const unsigned char* msg32, secp256k1_xonly_pubkey *pk, unsigned char *sig64, const secp256k1_frost_tweak_cache *cache) {
    int i;
    size_t signer_id = 0;
    int signers[THRESHOLD];
    int is_signer[N_SIGNERS];
    const secp256k1_frost_pubnonce *pubnonces[THRESHOLD];
    size_t ids[THRESHOLD];
    const secp256k1_frost_partial_sig *partial_sigs[THRESHOLD];

    for (i = 0; i < N_SIGNERS; i++) {
        unsigned char session_id[32];

        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_frost_nonce_gen. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        if (!fill_random(session_id, sizeof(session_id))) {
            return 0;
        }
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the other signers. */
        if (!secp256k1_frost_nonce_gen(ctx, &signer_secrets[i].secnonce, &signer[i].pubnonce, session_id, &signer_secrets[i].share, msg32, pk, NULL)) {
            return 0;
        }
        is_signer[i] = 0; /* Initialize is_signer */
    }
    /* Select a random subset of signers */
    for (i = 0; i < THRESHOLD; i++) {
        size_t subset_seed;

        while (1) {
            if (!fill_random((unsigned char*)&subset_seed, sizeof(subset_seed))) {
                return 0;
            }
            signer_id = subset_seed % N_SIGNERS;
            /* Check if signer has already been assigned */
            if (!is_signer[signer_id]) {
                is_signer[signer_id] = 1;
                signers[i] = signer_id;
                break;
            }
        }
        /* Mark signer as assigned */
        pubnonces[i] = &signer[signer_id].pubnonce;
        /* pubkeys[i] = &signer[signer_id].pubkey; */
        ids[i] = signer_id + 1;
    }
    /* Signing communication round 1: Exchange nonces */
    for (i = 0; i < THRESHOLD; i++) {
        signer_id = signers[i];
        if (!secp256k1_frost_nonce_process(ctx, &signer[signer_id].session, pubnonces, THRESHOLD, msg32, pk, signer_id + 1, ids, cache, NULL)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it to 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_frost_partial_sign(ctx, &signer[signer_id].partial_sig, &signer_secrets[signer_id].secnonce, &signer_secrets[signer_id].share, &signer[signer_id].session, cache)) {
            return 0;
        }
        partial_sigs[i] = &signer[signer_id].partial_sig;
    }
    /* Communication round 2: A production system would exchange
     * partial signatures here before moving on. */
    for (i = 0; i < THRESHOLD; i++) {
        signer_id = signers[i];
        /* To check whether signing was successful, it suffices to either verify
         * the aggregate signature with the aggregate public key using
         * secp256k1_schnorrsig_verify, or verify all partial signatures of all
         * signers individually. Verifying the aggregate signature is cheaper but
         * verifying the individual partial signatures has the advantage that it
         * can be used to determine which of the partial signatures are invalid
         * (if any), i.e., which of the partial signatures cause the aggregate
         * signature to be invalid and thus the protocol run to fail. It's also
         * fine to first verify the aggregate sig, and only verify the individual
         * sigs if it does not work.
         */
        if (!secp256k1_frost_partial_sig_verify(ctx, &signer[signer_id].partial_sig, &signer[signer_id].pubnonce, &signer[signer_id].pubshare, &signer[signer_id].session, cache)) {
            return 0;
        }
    }
    return secp256k1_frost_partial_sig_agg(ctx, sig64, &signer[signer_id].session, partial_sigs, THRESHOLD);
}

int main(void) {
    secp256k1_context* ctx;
    struct signer_secrets signer_secrets[N_SIGNERS];
    struct signer signers[N_SIGNERS];
    secp256k1_xonly_pubkey pk;
    secp256k1_frost_tweak_cache cache;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("Creating shares.........");
    if (!create_shares(ctx, signer_secrets, signers, &pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Tweaking................");
    /* Optionally tweak the key */
    if (!tweak(ctx, &pk, &cache)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing message.........");
    if (!sign(ctx, signer_secrets, signers, msg, &pk, sig, &cache)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    secp256k1_context_destroy(ctx);
    return 0;
}