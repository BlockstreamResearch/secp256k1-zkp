/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_ADAPTOR_TESTS_IMPL_H
#define SECP256K1_MODULE_MUSIG_ADAPTOR_TESTS_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"
#include "../../../include/secp256k1_musig_adaptor.h"

/* Tests for the musig adaptor API: nonce_process_adaptor, nonce_parity,
 * adapt, extract_adaptor */
static void musig_adaptor_api_tests(void) {
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    secp256k1_musig_pubnonce pubnonce[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];
    secp256k1_musig_aggnonce aggnonce;
    unsigned char msg[32];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_keyagg_cache invalid_keyagg_cache;
    secp256k1_musig_session session;
    secp256k1_musig_session invalid_session;
    secp256k1_pubkey pk[2];
    const secp256k1_pubkey *pk_ptr[2];
    secp256k1_pubkey invalid_pk;
    unsigned char session_secrand[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_pubnonce invalid_pubnonce;
    unsigned char final_sig[64];
    unsigned char pre_sig[64];
    unsigned char max64[64];
    secp256k1_musig_partial_sig partial_sig[2];
    const secp256k1_musig_partial_sig *partial_sig_ptr[2];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    int i;

    memset(max64, 0xff, sizeof(max64));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_keyagg_cache, 0, sizeof(invalid_keyagg_cache));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_session, 0, sizeof(invalid_session));

    testrand256(sec_adaptor);
    testrand256(msg);
    CHECK(secp256k1_ec_pubkey_create(CTX, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        testrand256(session_secrand[i]);
        testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }

    CHECK(secp256k1_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_musig_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_secrand[i], sk[i], &pk[i], msg, &keyagg_cache, NULL) == 1);
    }
    CHECK(secp256k1_musig_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);

    /** nonce_process_adaptor tests **/
    CHECK(secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, NULL, &aggnonce, msg, &keyagg_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, NULL, msg, &keyagg_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, (secp256k1_musig_aggnonce*) &invalid_pubnonce, msg, &keyagg_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, NULL, &keyagg_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, NULL, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, &invalid_keyagg_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, &keyagg_cache, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, &keyagg_cache, (secp256k1_pubkey *)&invalid_pk));

    CHECK(secp256k1_musig_nonce_process_adaptor(CTX, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);

    /* Partial sign and aggregate */
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_musig_partial_sign(CTX, &partial_sig[i], &secnonce[i], &keypair[i], &keyagg_cache, &session) == 1);
    }
    CHECK(secp256k1_musig_partial_sig_agg(CTX, pre_sig, &session, partial_sig_ptr, 2) == 1);

    /** nonce_parity tests */
    CHECK(secp256k1_musig_nonce_parity(CTX, &nonce_parity, &session) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_parity(CTX, NULL, &session));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_parity(CTX, &nonce_parity, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_musig_nonce_parity(CTX, &nonce_parity, &invalid_session));

    /** adapt tests */
    CHECK(secp256k1_musig_adapt(CTX, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_musig_adapt(CTX, NULL, pre_sig, sec_adaptor, 0));
    CHECK_ILLEGAL(CTX, secp256k1_musig_adapt(CTX, final_sig, NULL, sec_adaptor, 0));
    CHECK(secp256k1_musig_adapt(CTX, final_sig, max64, sec_adaptor, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_musig_adapt(CTX, final_sig, pre_sig, NULL, 0));
    CHECK(secp256k1_musig_adapt(CTX, final_sig, pre_sig, max64, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_musig_adapt(CTX, final_sig, pre_sig, sec_adaptor, 2));
    /* sig and pre_sig argument point to the same location */
    memcpy(final_sig, pre_sig, sizeof(final_sig));
    CHECK(secp256k1_musig_adapt(CTX, final_sig, final_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    CHECK(secp256k1_musig_adapt(CTX, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    /** extract_adaptor tests */
    CHECK(secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) == 0);
    /* wrong nonce parity */
    CHECK(secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, !nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) != 0);
    CHECK_ILLEGAL(CTX, secp256k1_musig_extract_adaptor(CTX, NULL, final_sig, pre_sig, 0));
    CHECK_ILLEGAL(CTX, secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, NULL, pre_sig, 0));
    CHECK(secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, max64, pre_sig, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, final_sig, NULL, 0));
    CHECK(secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, final_sig, max64, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_musig_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, 2));
}

static void scriptless_atomic_swap(void) {
    /* Throughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    unsigned char pre_sig_a[64];
    unsigned char final_sig_a[64];
    unsigned char pre_sig_b[64];
    unsigned char final_sig_b[64];
    secp256k1_musig_partial_sig partial_sig_a[2];
    const secp256k1_musig_partial_sig *partial_sig_a_ptr[2];
    secp256k1_musig_partial_sig partial_sig_b[2];
    const secp256k1_musig_partial_sig *partial_sig_b_ptr[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor;
    unsigned char sk_a[2][32];
    unsigned char sk_b[2][32];
    secp256k1_keypair keypair_a[2];
    secp256k1_keypair keypair_b[2];
    secp256k1_pubkey pk_a[2];
    const secp256k1_pubkey *pk_a_ptr[2];
    secp256k1_pubkey pk_b[2];
    const secp256k1_pubkey *pk_b_ptr[2];
    secp256k1_musig_keyagg_cache keyagg_cache_a;
    secp256k1_musig_keyagg_cache keyagg_cache_b;
    secp256k1_xonly_pubkey agg_pk_a;
    secp256k1_xonly_pubkey agg_pk_b;
    secp256k1_musig_secnonce secnonce_a[2];
    secp256k1_musig_secnonce secnonce_b[2];
    secp256k1_musig_pubnonce pubnonce_a[2];
    secp256k1_musig_pubnonce pubnonce_b[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr_a[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr_b[2];
    secp256k1_musig_aggnonce aggnonce_a;
    secp256k1_musig_aggnonce aggnonce_b;
    secp256k1_musig_session session_a, session_b;
    int nonce_parity_a;
    int nonce_parity_b;
    unsigned char seed_a[2][32] = { "a0", "a1" };
    unsigned char seed_b[2][32] = { "b0", "b1" };
    const unsigned char msg32_a[32] = {'t', 'h', 'i', 's', ' ', 'i', 's', ' ', 't', 'h', 'e', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', ' ', 'b', 'l', 'o', 'c', 'k', 'c', 'h', 'a', 'i', 'n', ' ', 'a'};
    const unsigned char msg32_b[32] = {'t', 'h', 'i', 's', ' ', 'i', 's', ' ', 't', 'h', 'e', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', ' ', 'b', 'l', 'o', 'c', 'k', 'c', 'h', 'a', 'i', 'n', ' ', 'b'};
    int i;

    /* Step 1: key setup */
    for (i = 0; i < 2; i++) {
        pk_a_ptr[i] = &pk_a[i];
        pk_b_ptr[i] = &pk_b[i];
        pubnonce_ptr_a[i] = &pubnonce_a[i];
        pubnonce_ptr_b[i] = &pubnonce_b[i];
        partial_sig_a_ptr[i] = &partial_sig_a[i];
        partial_sig_b_ptr[i] = &partial_sig_b[i];

        testrand256(sk_a[i]);
        testrand256(sk_b[i]);
        CHECK(create_keypair_and_pk(&keypair_a[i], &pk_a[i], sk_a[i]) == 1);
        CHECK(create_keypair_and_pk(&keypair_b[i], &pk_b[i], sk_b[i]) == 1);
    }
    testrand256(sec_adaptor);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pub_adaptor, sec_adaptor) == 1);

    CHECK(secp256k1_musig_pubkey_agg(CTX, &agg_pk_a, &keyagg_cache_a, pk_a_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(CTX, &agg_pk_b, &keyagg_cache_b, pk_b_ptr, 2) == 1);

    CHECK(secp256k1_musig_nonce_gen(CTX, &secnonce_a[0], &pubnonce_a[0], seed_a[0], sk_a[0], &pk_a[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(CTX, &secnonce_a[1], &pubnonce_a[1], seed_a[1], sk_a[1], &pk_a[1], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(CTX, &secnonce_b[0], &pubnonce_b[0], seed_b[0], sk_b[0], &pk_b[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(CTX, &secnonce_b[1], &pubnonce_b[1], seed_b[1], sk_b[1], &pk_b[1], NULL, NULL, NULL) == 1);

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_nonce_agg(CTX, &aggnonce_a, pubnonce_ptr_a, 2) == 1);
    CHECK(secp256k1_musig_nonce_process_adaptor(CTX, &session_a, &aggnonce_a, msg32_a, &keyagg_cache_a, &pub_adaptor) == 1);
    CHECK(secp256k1_musig_nonce_parity(CTX, &nonce_parity_a, &session_a) == 1);
    CHECK(secp256k1_musig_nonce_agg(CTX, &aggnonce_b, pubnonce_ptr_b, 2) == 1);
    CHECK(secp256k1_musig_nonce_process_adaptor(CTX, &session_b, &aggnonce_b, msg32_b, &keyagg_cache_b, &pub_adaptor) == 1);
    CHECK(secp256k1_musig_nonce_parity(CTX, &nonce_parity_b, &session_b) == 1);

    /* Step 3: Signer 0 produces partial signatures for both chains. */
    CHECK(secp256k1_musig_partial_sign(CTX, &partial_sig_a[0], &secnonce_a[0], &keypair_a[0], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sign(CTX, &partial_sig_b[0], &secnonce_b[0], &keypair_b[0], &keyagg_cache_b, &session_b) == 1);

    /* Step 4: Signer 1 receives partial signatures, verifies them and creates a
     * partial signature to send B-coins to signer 0. */
    CHECK(secp256k1_musig_partial_sig_verify(CTX, &partial_sig_a[0], &pubnonce_a[0], &pk_a[0], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(CTX, &partial_sig_b[0], &pubnonce_b[0], &pk_b[0], &keyagg_cache_b, &session_b) == 1);
    CHECK(secp256k1_musig_partial_sign(CTX, &partial_sig_b[1], &secnonce_b[1], &keypair_b[1], &keyagg_cache_b, &session_b) == 1);

    /* Step 5: Signer 0 aggregates its own partial signature with the partial
     * signature from signer 1 and adapts it. This results in a complete
     * signature which is broadcasted by signer 0 to take B-coins. */
    CHECK(secp256k1_musig_partial_sig_agg(CTX, pre_sig_b, &session_b, partial_sig_b_ptr, 2) == 1);
    CHECK(secp256k1_musig_adapt(CTX, final_sig_b, pre_sig_b, sec_adaptor, nonce_parity_b) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig_b, msg32_b, sizeof(msg32_b), &agg_pk_b) == 1);

    /* Step 6: Signer 1 signs, extracts adaptor from the published signature,
     * and adapts the signature to take A-coins. */
    CHECK(secp256k1_musig_partial_sign(CTX, &partial_sig_a[1], &secnonce_a[1], &keypair_a[1], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sig_agg(CTX, pre_sig_a, &session_a, partial_sig_a_ptr, 2) == 1);
    CHECK(secp256k1_musig_extract_adaptor(CTX, sec_adaptor_extracted, final_sig_b, pre_sig_b, nonce_parity_b) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_adapt(CTX, final_sig_a, pre_sig_a, sec_adaptor_extracted, nonce_parity_a) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig_a, msg32_a, sizeof(msg32_a), &agg_pk_a) == 1);
}

static void run_musig_adaptor_tests(void) {
    int i;

    musig_adaptor_api_tests();
    for (i = 0; i < COUNT; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        scriptless_atomic_swap();
    }
}

#endif
