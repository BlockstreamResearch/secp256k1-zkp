/**********************************************************************
 * Copyright (c) 2019 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_THRESHOLDSIG_TESTS_
#define _SECP256K1_MODULE_THRESHOLDSIG_TESTS_

#include "secp256k1_thresholdsig.h"

void thresholdsig_api_tests(void) {
    int nonce_is_negated;
    secp256k1_pubkey combined_pk;
    unsigned char pk_hash[32];
    unsigned char message[32];
    secp256k1_musig_session session[2];
    secp256k1_pubkey nonce[2];
    secp256k1_musig_partial_signature partial[2];
    secp256k1_schnorrsig final_sig;
    const unsigned char *ncs[2];
    unsigned char noncom[3][32];
    unsigned char sessid[3][32];
    secp256k1_thresholdsig_keyshard shards0[3];
    secp256k1_thresholdsig_keyshard shards1[3];
    secp256k1_thresholdsig_keyshard shards2[3];
    secp256k1_musig_session_signer_data signer_data0[3];
    secp256k1_musig_session_signer_data signer_data2[3];
    secp256k1_pubkey pubshards0[3];
    secp256k1_pubkey pubshards1[3];
    secp256k1_pubkey pubshards2[3];
    unsigned char seckey[3][32];
    unsigned char dummysk[32];
    secp256k1_pubkey pubkey[3];
    size_t indices[2] = { 0, 2 };
    size_t i;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    secp256k1_rand256(message);
    secp256k1_rand256(dummysk);
    for (i = 0; i < 3; i++) {
        secp256k1_rand256(seckey[i]);
        secp256k1_rand256(sessid[i]);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey[i], seckey[i]) == 1);
    }
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combined_pk, pk_hash, pubkey, 3));

    /** main test body **/
    /** 1. Key setup **/

    /* Key splitting */
    ecount = 0;
    CHECK(secp256k1_thresholdsig_keysplit(none, shards0, pubshards0, dummysk, 2, 3) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_thresholdsig_keysplit(vrfy, shards0, pubshards0, dummysk, 2, 3) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, dummysk, 2, 3) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_thresholdsig_keysplit(sign, NULL, pubshards0, dummysk, 2, 3) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, NULL, dummysk, 2, 3) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, NULL, 2, 3) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, dummysk, 0, 3) == 0);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, dummysk, 3, 3) == 0);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, dummysk, 4, 3) == 0);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, dummysk, 0, 0) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_thresholdsig_keysplit(sign, shards1, pubshards1, seckey[1], 2, 3) == 1);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards2, pubshards2, seckey[2], 2, 3) == 1);

    /* Verification of shards */
    ecount = 0;
    CHECK(secp256k1_thresholdsig_verify_shard(none, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_thresholdsig_verify_shard(sign, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_thresholdsig_verify_shard(vrfy, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 1);
    CHECK(ecount == 3);

    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, NULL, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 1);
    CHECK(ecount == 3); /* no output is ok */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, NULL, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 0, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 3, 0, pubshards0, 2) == 0);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 5, 0, pubshards0, 2) == 0);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 3, pubshards0, 2) == 0);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 5, 5, pubshards0, 2) == 0);
    CHECK(ecount == 4); /* no keys or bad index will result in a 0 return, but not an ARG_CHECK failure */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, NULL, 0, &shards0[0], 0, 0, pubshards0, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, NULL, 0, 0, pubshards0, 2) == 1);
    CHECK(ecount == 5); /* no private shard is fine; indicates a public verifier who is only checking internal consistency */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, NULL, 2) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 3) == 0);
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, dummysk, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 0) == 0);
    CHECK(ecount == 6); /* bad coefficient count will also fail but not ARG_CHECK */

    /* fail with bad coffecient count */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, NULL, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards0, 1) == 0);
    /* fail with bad public shards */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, NULL, pubkey, 3, pk_hash, 0, &shards0[0], 0, 0, pubshards1, 2) == 0);
    /* fail with bad index for secret shard */
    CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, NULL, pubkey, 3, pk_hash, 0, &shards0[0], 1, 0, pubshards0, 2) == 0);
    CHECK(ecount == 6);

    /* Redo above steps without failures to complete keysetup */
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards0, pubshards0, seckey[0], 2, 3) == 1);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards1, pubshards1, seckey[1], 2, 3) == 1);
    CHECK(secp256k1_thresholdsig_keysplit(sign, shards2, pubshards2, seckey[2], 2, 3) == 1);
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, seckey[i], pubkey, 3, pk_hash, 0, &shards0[i], i, 0, pubshards0, 2) == 1);
        CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, seckey[i], pubkey, 3, pk_hash, 1, &shards1[i], i, 1, pubshards1, 2) == 1);
        CHECK(secp256k1_thresholdsig_verify_shard(both, NULL, seckey[i], pubkey, 3, pk_hash, 1, &shards2[i], i, 2, pubshards2, 2) == 1);
    }

    for (i = 0; i < 3; i++) {
        secp256k1_pubkey newpk;
        CHECK(secp256k1_ec_pubkey_create(ctx, &newpk, seckey[i]) == 1);
        CHECK(memcmp(&pubkey[i], &newpk, sizeof(newpk)) == 0);
    }

    /** 2. Signing with signers 0 and 2; notice `n_signers` is set to 2, not 3 **/
    ecount = 0;
    CHECK(secp256k1_thresholdsig_session_initialize(none, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_thresholdsig_session_initialize(vrfy, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 1);
    CHECK(ecount == 2);

    CHECK(secp256k1_thresholdsig_session_initialize(sign, NULL, signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], NULL, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, NULL, sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], NULL, message, &combined_pk, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], NULL, &combined_pk, indices, 2, 0, seckey[0]) == 1);
    CHECK(ecount == 6);  /* NULL message is OK */
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, NULL, indices, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, NULL, 2, 0, seckey[0]) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 0, 0, seckey[0]) == 0);
    CHECK(ecount == 8);  /* n_signers is an error but not an ARG_CHECK error */
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, NULL) == 0);
    CHECK(ecount == 9);

    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[0], signer_data0, noncom[0], sessid[0], message, &combined_pk, indices, 2, 0, seckey[0]) == 1);
    CHECK(secp256k1_thresholdsig_session_initialize(sign, &session[1], signer_data2, noncom[1], sessid[1], message, &combined_pk, indices, 2, 2, seckey[2]) == 1);

    /* Nonce combination can be generated with normal MuSig functions */
    ncs[0] = noncom[0];
    ncs[1] = noncom[1];
    CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], signer_data0, &nonce[0], ncs, 2) == 1);
    CHECK(secp256k1_musig_session_get_public_nonce(none, &session[1], signer_data2, &nonce[1], ncs, 2) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data0[0], &nonce[0]) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data0[1], &nonce[1]) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data2[0], &nonce[0]) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data2[1], &nonce[1]) == 1);
    CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], signer_data0, 2, &nonce_is_negated, NULL) == 1);
    CHECK(secp256k1_musig_session_combine_nonces(none, &session[1], signer_data2, 2, &nonce_is_negated, NULL) == 1);

    /* Partial signatures can be generated with the normal MuSig functions */
    CHECK(secp256k1_musig_partial_sign(none, &session[0], &partial[0]) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &session[1], &partial[1]) == 1);

    /* Verification */
    ecount = 0;
    CHECK(secp256k1_thresholdsig_partial_sig_verify(none, &session[0], signer_data0, 2, 0, &partial[0], &pubkey[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(sign, &session[0], signer_data0, 2, 0, &partial[0], &pubkey[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 0, &partial[0], &pubkey[0]) == 1);
    CHECK(ecount == 2);

    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, NULL, signer_data0, 2, 0, &partial[0], &pubkey[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], NULL, 2, 0, &partial[0], &pubkey[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 0, NULL, &pubkey[0]) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 0, &partial[0], NULL) == 0);
    CHECK(ecount == 6);

    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 0, &partial[0], &pubkey[0]) == 1);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 1, &partial[1], &pubkey[0]) == 0);
    CHECK(secp256k1_thresholdsig_partial_sig_verify(vrfy, &session[0], signer_data0, 2, 1, &partial[1], &pubkey[2]) == 1);
    CHECK(ecount == 6);

    /* Combining can also be done with normal MuSig functions */
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig, partial, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, &final_sig, message, &combined_pk) == 1);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

void run_thresholdsig_tests(void) {
    thresholdsig_api_tests();
}

#endif
