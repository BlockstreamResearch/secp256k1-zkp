/***********************************************************************
 * Copyright (c) 2022 Jesse Posner                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_IMPL_H
#define SECP256K1_MODULE_FROST_TESTS_IMPL_H

#include <stdlib.h>
#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "session.h"
#include "keygen.h"
#include "../../scalar.h"
#include "../../scratch.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static int frost_create_pk(secp256k1_xonly_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_pubkey pubkey_tmp;

    ret = secp256k1_ec_pubkey_create(ctx, &pubkey_tmp, sk);
    ret &= secp256k1_xonly_pubkey_from_pubkey(ctx, pk, NULL, &pubkey_tmp);

    return ret;
}

/* Simple (non-adaptor, non-tweaked) 3-of-5 FROST aggregate, sign, verify
 * test. */
void frost_simple_test(void) {
    unsigned char sk[5][32];
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    unsigned char msg[32];
    secp256k1_pubkey vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    unsigned char vss_hash[32];
    unsigned char pok[5][64];
    secp256k1_xonly_pubkey agg_pk;
    unsigned char session_id[5][32];
    secp256k1_frost_share share[5][5];
    const secp256k1_frost_share *share_ptr[5];
    secp256k1_frost_share agg_share[5];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    secp256k1_pubkey pubshare[5];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    unsigned char final_sig[64];
    secp256k1_frost_session session;
    int i,j;

    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        vss_ptr[i] = vss_commitment[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        CHECK(frost_create_pk(&pk[i], sk[i]));
    }
    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[i], pok[i], session_id[i], 3) == 1);
        for (j = 0; j < 5; j++) {
            CHECK(secp256k1_frost_share_gen(ctx, &share[i][j], vss_commitment[j], session_id[i], &pk[j], 3) == 1);
        }
    }
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            share_ptr[j] = &share[j][i];
            CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[i], share_ptr[j], &vss_ptr[j]) == 1);
            CHECK(secp256k1_frost_compute_pubshare(ctx, &pubshare[j], 3, pk_ptr[j], vss_ptr, 5) == 1);
        }
        CHECK(secp256k1_frost_share_agg(ctx, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
    }

    secp256k1_testrand256(msg);
    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(session_id[i]);

        CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[i], &pubnonce[i], session_id[i], &agg_share[i], NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(ctx, &session, pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[i], pk_ptr, NULL, NULL) == 1);
        CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[i], &secnonce[i], &agg_share[i], &session, NULL) == 1);
        CHECK(secp256k1_frost_partial_sig_verify(ctx, &partial_sig[i], &pubnonce[i], &pubshare[i], &session, NULL) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), &agg_pk) == 1);
}

void frost_pubnonce_summing_to_inf(secp256k1_frost_pubnonce *pubnonce) {
    secp256k1_ge ge[2];
    int i;
    secp256k1_gej summed_nonces[2];
    const secp256k1_frost_pubnonce *pubnonce_ptr[2];

    ge[0] = secp256k1_ge_const_g;
    ge[1] = secp256k1_ge_const_g;

    for (i = 0; i < 2; i++) {
        secp256k1_frost_pubnonce_save(&pubnonce[i], ge);
        pubnonce_ptr[i] = &pubnonce[i];
        secp256k1_ge_neg(&ge[0], &ge[0]);
        secp256k1_ge_neg(&ge[1], &ge[1]);
    }

    secp256k1_frost_sum_nonces(ctx, summed_nonces, pubnonce_ptr, 2);
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[0]));
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[1]));
}

int frost_memcmp_and_randomize(unsigned char *value, const unsigned char *expected, size_t len) {
    int ret;
    size_t i;
    ret = secp256k1_memcmp_var(value, expected, len);
    for (i = 0; i < len; i++) {
        value[i] = secp256k1_testrand_bits(8);
    }
    return ret;
}

void frost_api_tests(void) {
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    secp256k1_frost_partial_sig invalid_partial_sig;
    const secp256k1_frost_partial_sig *invalid_partial_sig_ptr[5];
    unsigned char final_sig[64];
    unsigned char pre_sig[64];
    unsigned char buf[32];
    unsigned char sk[5][32];
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[5][32];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_frost_secnonce secnonce_tmp;
    secp256k1_frost_secnonce invalid_secnonce;
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    unsigned char pubnonce_ser[66];
    secp256k1_frost_pubnonce inf_pubnonce[5];
    secp256k1_frost_pubnonce invalid_pubnonce;
    const secp256k1_frost_pubnonce *invalid_pubnonce_ptr[5];
    unsigned char msg[32];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_pubkey full_agg_pk;
    secp256k1_frost_tweak_cache tweak_cache;
    secp256k1_frost_tweak_cache invalid_tweak_cache;
    secp256k1_frost_session session[5];
    secp256k1_frost_session invalid_session;
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    const secp256k1_xonly_pubkey *invalid_pk_ptr[5];
    secp256k1_xonly_pubkey invalid_pk;
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey vss_commitment[5][3];
    secp256k1_pubkey invalid_vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    const secp256k1_pubkey *invalid_vss_ptr[5];
    secp256k1_pubkey invalid_vss_pk;
    secp256k1_frost_share share[5][5];
    secp256k1_frost_share invalid_share;
    secp256k1_frost_share agg_share[5];
    unsigned char vss_hash[32];
    unsigned char pok[5][64];
    const secp256k1_frost_share *share_ptr[5];
    const secp256k1_frost_share *invalid_share_ptr[5];
    secp256k1_pubkey pubshare[5];
    int i, j;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    memset(max64, 0xff, sizeof(max64));
    memset(&invalid_share, 0xff, sizeof(invalid_share));
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_vss_pk, 0, sizeof(invalid_vss_pk));
    memset(&invalid_tweak_cache, 0, sizeof(invalid_tweak_cache));
    memset(&invalid_session, 0, sizeof(invalid_session));
    frost_pubnonce_summing_to_inf(inf_pubnonce);

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 5; i++) {
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        vss_ptr[i] = vss_commitment[i];
        invalid_vss_ptr[i] = invalid_vss_commitment[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        CHECK(frost_create_pk(&pk[i], sk[i]));
    }
    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_pk_ptr[0] = &invalid_pk;
    invalid_share_ptr[0] = &invalid_share;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 3; j++) {
            invalid_vss_commitment[i][j] = invalid_vss_pk;
        }
    }

    /** main test body **/

    /** Key generation **/
    ecount = 0;
    for (i = 0; i < 5; i++) {
        /* TODO: add vss_gen tests */
        CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[i], pok[i], session_id[i], 3) == 1);

        for (j = 0; j < 5; j++) {
            CHECK(secp256k1_frost_share_gen(none, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(sign, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, NULL, vss_commitment[j], session_id[i], pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*30)+(j*6)+1);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], NULL, session_id[i], pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*30)+(j*6)+2);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], NULL, pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*30)+(j*6)+3);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], NULL, 3) == 0);
            CHECK(ecount == (i*30)+(j*6)+4);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], &invalid_pk, 3) == 0);
            CHECK(ecount == (i*30)+(j*6)+5);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 0) == 0);
            CHECK(ecount == (i*30)+(j*6)+6);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);

            CHECK(secp256k1_frost_share_gen(none, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(sign, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, &share[i][j], vss_commitment[j], session_id[i], pk_ptr[j], 3) == 1);
        }
    }
    CHECK(ecount == 150);

    /* Share aggregation */
    ecount = 0;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            share_ptr[j] = &share[j][i];
        }
        CHECK(secp256k1_frost_share_agg(none, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(sign, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, NULL, &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], NULL, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+2);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, NULL, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+3);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, NULL, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+4);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, NULL, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+5);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, invalid_vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+6);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, NULL) == 0);
        CHECK(ecount == (i*13)+7);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, &invalid_pk) == 0);
        CHECK(ecount == (i*13)+8);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, invalid_share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+9);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 0, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+10);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, NULL, vss_ptr, 0, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+11);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 0, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+12);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, NULL, 5, 0, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+13);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);

        CHECK(secp256k1_frost_share_agg(none, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(sign, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
    }
    CHECK(ecount == 65);

    /* Share verification */
    ecount = 0;
    CHECK(secp256k1_frost_share_verify(none, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(sign, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[1]) == 0);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, NULL, share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, &invalid_pk, share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], NULL, &vss_ptr[1]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], &invalid_share, &vss_ptr[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &invalid_vss_ptr[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_frost_share_verify(vrfy, 0, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_frost_share_verify(none, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(sign, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[1], &vss_ptr[1]) == 1);

    /* Compute public verification share */
    ecount = 0;
    CHECK(secp256k1_frost_compute_pubshare(none, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(sign, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, NULL, 3, pk_ptr[0], vss_ptr, 5) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, NULL, vss_ptr, 5) == 0);
    CHECK(ecount == 2);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, &invalid_pk, vss_ptr, 5) == 0);
    CHECK(ecount == 3);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], NULL, 5) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], invalid_vss_ptr, 5) == 0);
    CHECK(ecount == 5);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 0, pk_ptr[0], invalid_vss_ptr, 5) == 0);
    CHECK(ecount == 6);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 0, pk_ptr[0], NULL, 5) == 0);
    CHECK(ecount == 7);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], invalid_vss_ptr, 0) == 0);
    CHECK(ecount == 8);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], NULL, 0) == 0);
    CHECK(ecount == 9);
    CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0);

    CHECK(secp256k1_frost_compute_pubshare(none, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(sign, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[1], 3, pk_ptr[1], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &pubshare[2], 3, pk_ptr[2], vss_ptr, 5) == 1);

    /* pubkey_get */
    ecount = 0;
    CHECK(secp256k1_frost_pubkey_get(none, &full_agg_pk, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_get(none, NULL, &agg_pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubkey_get(none, &full_agg_pk, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_memcmp_var(&full_agg_pk, zeros68, sizeof(full_agg_pk)) == 0);

    /** Tweaking **/

    /* pubkey_tweak */
    ecount = 0;
    CHECK(secp256k1_frost_pubkey_tweak(none, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(sign, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, NULL, &agg_pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &invalid_pk) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_frost_pubkey_tweak(none, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(sign, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &agg_pk) == 1);

    /* tweak_add */
    {
        int (*tweak_func[2]) (const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32);
        tweak_func[0] = secp256k1_frost_pubkey_ec_tweak_add;
        tweak_func[1] = secp256k1_frost_pubkey_xonly_tweak_add;
        CHECK(secp256k1_frost_pubkey_tweak(ctx, &tweak_cache, &agg_pk) == 1);
        for (i = 0; i < 2; i++) {
            secp256k1_pubkey tmp_output_pk;
            secp256k1_frost_tweak_cache tmp_tweak_cache = tweak_cache;
            ecount = 0;
            CHECK((*tweak_func[i])(ctx, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            /* Reset tweak_cache */
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(none, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(sign, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, NULL, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, NULL, tweak) == 0);
            CHECK(ecount == 1);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, NULL) == 0);
            CHECK(ecount == 2);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, max64) == 0);
            CHECK(ecount == 2);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            /* Uninitialized tweak_cache */
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &invalid_tweak_cache, tweak) == 0);
            CHECK(ecount == 3);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
        }
    }

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_frost_nonce_gen(none, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(vrfy, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_frost_nonce_gen(sttc, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, NULL, &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], NULL, session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], NULL, &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* no seckey and session_id is 0 */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, NULL, msg, &agg_pk, max64) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* session_id 0 is fine when a seckey is provided */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &agg_pk, max64) == 1);
    CHECK(ecount == 4);
    /* invalid agg_share */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &invalid_share, msg, &agg_pk, max64) == 0);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], NULL, &agg_pk, max64) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, NULL, max64) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &invalid_pk, max64) == 0);
    CHECK(ecount == 6);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, NULL) == 1);
    CHECK(ecount == 6);

    /* Every in-argument except session_id can be NULL */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[1], &pubnonce[1], session_id[1], &agg_share[1], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[2], &pubnonce[2], session_id[2], &agg_share[2], NULL, NULL, NULL) == 1);

    /** Serialize and parse public nonces **/
    ecount = 0;
    CHECK(secp256k1_frost_pubnonce_serialize(none, NULL, &pubnonce[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubnonce_serialize(none, pubnonce_ser, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK(secp256k1_frost_pubnonce_serialize(none, pubnonce_ser, &invalid_pubnonce) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK(secp256k1_frost_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);

    ecount = 0;
    CHECK(secp256k1_frost_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);
    CHECK(secp256k1_frost_pubnonce_parse(none, NULL, pubnonce_ser) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubnonce_parse(none, &pubnonce[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_pubnonce_parse(none, &pubnonce[0], zeros68) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_frost_pubnonce tmp;
        CHECK(secp256k1_frost_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);
        CHECK(secp256k1_frost_pubnonce_parse(none, &tmp, pubnonce_ser) == 1);
        CHECK(secp256k1_memcmp_var(&tmp, &pubnonce[0], sizeof(tmp)) == 0);
    }

    /** Process nonces **/
    ecount = 0;
    CHECK(secp256k1_frost_nonce_process(none, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(sign, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(vrfy, NULL, pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], NULL, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 0, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], invalid_pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, NULL, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, NULL, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, NULL, pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], NULL, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], invalid_pk_ptr, &tweak_cache, &adaptor) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, NULL, &adaptor) == 1);
    CHECK(ecount == 9);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &invalid_tweak_cache, &adaptor) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, NULL) == 1);
    CHECK(ecount == 10);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, (secp256k1_pubkey *)&invalid_pk) == 0);
    CHECK(ecount == 11);

    CHECK(secp256k1_frost_nonce_process(vrfy, &session[0], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[0], pk_ptr, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[1], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[1], pk_ptr, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(vrfy, &session[2], pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[2], pk_ptr, &tweak_cache, &adaptor) == 1);

    ecount = 0;
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], &session[0], &tweak_cache) == 1);
    /* The secnonce is set to 0 and subsequent signing attempts fail */
    CHECK(secp256k1_memcmp_var(&secnonce_tmp, zeros68, sizeof(secnonce_tmp)) == 0);
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 1);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, NULL, &secnonce_tmp, &agg_share[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 2);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], NULL, &agg_share[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &invalid_secnonce, &agg_share[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, NULL, &session[0], &tweak_cache) == 0);
    CHECK(ecount == 5);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &invalid_share, &session[0], &tweak_cache) == 0);
    CHECK(ecount == 6);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], NULL, &tweak_cache) == 0);
    CHECK(ecount == 7);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], &invalid_session, &tweak_cache) == 0);
    CHECK(ecount == 8);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], &session[0], NULL) == 1);
    CHECK(ecount == 8);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce_tmp, &agg_share[0], &session[0], &invalid_tweak_cache) == 0);
    CHECK(ecount == 9);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));

    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[0], &secnonce[0], &agg_share[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[1], &secnonce[1], &agg_share[1], &session[1], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(none, &partial_sig[2], &secnonce[2], &agg_share[2], &session[2], &tweak_cache) == 1);

    ecount = 0;
    CHECK(secp256k1_frost_partial_sig_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(secp256k1_frost_partial_sig_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_partial_sig_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_partial_sig_parse(none, &partial_sig[0], buf) == 1);
    CHECK(secp256k1_frost_partial_sig_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_partial_sig_parse(none, &partial_sig[0], max64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_partial_sig_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_frost_partial_sig tmp;
        CHECK(secp256k1_frost_partial_sig_serialize(none, buf, &partial_sig[0]) == 1);
        CHECK(secp256k1_frost_partial_sig_parse(none, &tmp, buf) == 1);
        CHECK(secp256k1_memcmp_var(&tmp, &partial_sig[0], sizeof(tmp)) == 0);
    }

    /** Partial signature verification */
    ecount = 0;
    CHECK(secp256k1_frost_partial_sig_verify(none, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(sign, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[1], &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 0);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, NULL, &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &invalid_partial_sig, &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], NULL, &pubshare[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &invalid_pubnonce, &pubshare[0], &session[0], &tweak_cache) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], NULL, &session[0], &tweak_cache) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &invalid_vss_pk, &session[0], &tweak_cache) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], NULL, &tweak_cache) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], &invalid_session, &tweak_cache) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], NULL) == 1);
    CHECK(ecount == 8);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &invalid_tweak_cache) == 0);
    CHECK(ecount == 9);

    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[1], &pubnonce[1], &pubshare[1], &session[1], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(vrfy, &partial_sig[2], &pubnonce[2], &pubshare[2], &session[2], &tweak_cache) == 1);

    /** Signature aggregation and verification */
    ecount = 0;
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[0], partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_frost_partial_sig_agg(none, NULL, &session[0], partial_sig_ptr, 3) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, NULL, partial_sig_ptr, 3) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &invalid_session, partial_sig_ptr, 3) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[0], NULL, 3) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[0], invalid_partial_sig_ptr, 3) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[0], partial_sig_ptr, 0) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[0], partial_sig_ptr, 1) == 1);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[1], partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_frost_partial_sig_agg(none, pre_sig, &session[2], partial_sig_ptr, 3) == 1);

    /** Adaptor signature verification */
    ecount = 0;
    CHECK(secp256k1_frost_nonce_parity(none, &nonce_parity, &session[0]) == 1);
    CHECK(secp256k1_frost_nonce_parity(none, NULL, &session[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_nonce_parity(none, &nonce_parity, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_nonce_parity(none, &nonce_parity, &invalid_session) == 0);
    CHECK(ecount == 3);

    ecount = 0;
    CHECK(secp256k1_frost_adapt(none, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_frost_adapt(none, NULL, pre_sig, sec_adaptor, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_adapt(none, final_sig, NULL, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_adapt(none, final_sig, max64, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_adapt(none, final_sig, pre_sig, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_adapt(none, final_sig, pre_sig, max64, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_adapt(none, final_sig, pre_sig, sec_adaptor, 2) == 0);
    CHECK(ecount == 4);
    /* sig and pre_sig argument point to the same location */
    memcpy(final_sig, pre_sig, sizeof(final_sig));
    CHECK(secp256k1_frost_adapt(none, final_sig, final_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    CHECK(secp256k1_frost_adapt(none, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) == 0);
    /* wrong nonce parity */
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, !nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) != 0);
    CHECK(secp256k1_frost_extract_adaptor(none, NULL, final_sig, pre_sig, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, NULL, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, max64, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, final_sig, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, final_sig, max64, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, 2) == 0);
    CHECK(ecount == 4);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(sttc);
}

void frost_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1[2], k2[2];

    secp256k1_nonce_function_frost(k1, args[0], args[1], args[2], args[3], args[4]);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    secp256k1_nonce_function_frost(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(secp256k1_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(secp256k1_scalar_eq(&k1[1], &k2[1]) == 0);
}

void frost_nonce_test(void) {
    unsigned char *args[5];
    unsigned char session_id[32];
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char agg_pk[32];
    unsigned char extra_input[32];
    int i, j;
    secp256k1_scalar k[5][2];

    secp256k1_testrand_bytes_test(session_id, sizeof(session_id));
    secp256k1_testrand_bytes_test(sk, sizeof(sk));
    secp256k1_testrand_bytes_test(msg, sizeof(msg));
    secp256k1_testrand_bytes_test(agg_pk, sizeof(agg_pk));
    secp256k1_testrand_bytes_test(extra_input, sizeof(extra_input));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = session_id;
    args[1] = msg;
    args[2] = sk;
    args[3] = agg_pk;
    args[4] = extra_input;
    for (i = 0; i < count; i++) {
        frost_nonce_bitflip(args, 0, sizeof(session_id));
        frost_nonce_bitflip(args, 1, sizeof(msg));
        frost_nonce_bitflip(args, 2, sizeof(sk));
        frost_nonce_bitflip(args, 3, sizeof(agg_pk));
        frost_nonce_bitflip(args, 4, sizeof(extra_input));
    }
    /* Check that if any argument is NULL, a different nonce is produced than if
     * any other argument is NULL. */
    memcpy(msg, session_id, sizeof(msg));
    memcpy(sk, session_id, sizeof(sk));
    memcpy(agg_pk, session_id, sizeof(agg_pk));
    memcpy(extra_input, session_id, sizeof(extra_input));
    secp256k1_nonce_function_frost(k[0], args[0], args[1], args[2], args[3], args[4]);
    secp256k1_nonce_function_frost(k[1], args[0], NULL, args[2], args[3], args[4]);
    secp256k1_nonce_function_frost(k[2], args[0], args[1], NULL, args[3], args[4]);
    secp256k1_nonce_function_frost(k[3], args[0], args[1], args[2], NULL, args[4]);
    secp256k1_nonce_function_frost(k[4], args[0], args[1], args[2], args[3], NULL);
    for (i = 0; i < 4; i++) {
        for (j = i+1; j < 5; j++) {
            CHECK(secp256k1_scalar_eq(&k[i][0], &k[j][0]) == 0);
            CHECK(secp256k1_scalar_eq(&k[i][1], &k[j][1]) == 0);
        }
    }
}

void frost_sha256_tag_test_internal(secp256k1_sha256 *sha_tagged, unsigned char *tag, size_t taglen) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char buf2[32];
    size_t i;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tag, taglen);
    secp256k1_sha256_finalize(&sha, buf);
    /* buf = SHA256(tag) */

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    /* Is buffer fully consumed? */
    CHECK((sha.bytes & 0x3F) == 0);

    /* Compare with tagged SHA */
    for (i = 0; i < 8; i++) {
        CHECK(sha_tagged->s[i] == sha.s[i]);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(sha_tagged, buf, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_sha256_finalize(sha_tagged, buf2);
    CHECK(secp256k1_memcmp_var(buf, buf2, 32) == 0);
}

/* Checks that the initialized tagged hashes initialized have the expected
 * state. */
void frost_sha256_tag_test(void) {
    secp256k1_sha256 sha_tagged;
    {
        char tag[8] = "VSS list";
        secp256k1_frost_vsslist_sha256(&sha_tagged);
        sha256_tag_test_internal(&sha_tagged, (unsigned char*)tag, sizeof(tag));
    }
}

/* Attempts to create a signature for the aggregate public key using given secret
 * keys and tweak_cache. */
void frost_tweak_test_helper(const secp256k1_xonly_pubkey* agg_pk, const secp256k1_frost_share *sr0, const secp256k1_frost_share *sr1, const secp256k1_frost_share *sr2, secp256k1_frost_tweak_cache *tweak_cache, const secp256k1_xonly_pubkey * const* pubkeys, const secp256k1_pubkey *sr_pk0, const secp256k1_pubkey *sr_pk1, const secp256k1_pubkey *sr_pk2) {
    unsigned char session_id[3][32];
    unsigned char msg[32];
    secp256k1_frost_secnonce secnonce[3];
    secp256k1_frost_pubnonce pubnonce[3];
    const secp256k1_frost_pubnonce *pubnonce_ptr[3];
    secp256k1_frost_session session[5];
    secp256k1_frost_partial_sig partial_sig[3];
    const secp256k1_frost_partial_sig *partial_sig_ptr[3];
    unsigned char final_sig[64];
    int i;

    for (i = 0; i < 3; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        secp256k1_testrand256(session_id[i]);
    }
    secp256k1_testrand256(msg);


    CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[0], &pubnonce[0], session_id[0], sr0, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[1], &pubnonce[1], session_id[1], sr1, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[2], &pubnonce[2], session_id[2], sr2, NULL, NULL, NULL) == 1);

    CHECK(secp256k1_frost_nonce_process(ctx, &session[0], pubnonce_ptr, 3, msg, agg_pk, pubkeys[0], pubkeys, tweak_cache, NULL) == 1);
    CHECK(secp256k1_frost_nonce_process(ctx, &session[1], pubnonce_ptr, 3, msg, agg_pk, pubkeys[1], pubkeys, tweak_cache, NULL) == 1);
    CHECK(secp256k1_frost_nonce_process(ctx, &session[2], pubnonce_ptr, 3, msg, agg_pk, pubkeys[2], pubkeys, tweak_cache, NULL) == 1);


    CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[0], &secnonce[0], sr0, &session[0], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[1], &secnonce[1], sr1, &session[1], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[2], &secnonce[2], sr2, &session[2], tweak_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_verify(ctx, &partial_sig[0], &pubnonce[0], sr_pk0, &session[0], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(ctx, &partial_sig[1], &pubnonce[1], sr_pk1, &session[1], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(ctx, &partial_sig[2], &pubnonce[2], sr_pk2, &session[2], tweak_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_agg(ctx, final_sig, &session[0], partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), agg_pk) == 1);
}

/* Create aggregate public key P[0], tweak multiple times (using xonly and
 * ordinary tweaking) and test signing. */
void frost_tweak_test(void) {
    unsigned char sk[5][32];
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    secp256k1_pubkey pubshare[5];
    secp256k1_frost_tweak_cache tweak_cache;
    enum { N_TWEAKS = 8 };
    secp256k1_pubkey P[N_TWEAKS + 1];
    secp256k1_xonly_pubkey P_xonly[N_TWEAKS + 1];
    unsigned char session_id[5][32];
    secp256k1_pubkey vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    unsigned char vss_hash[32];
    unsigned char pok[5][64];
    secp256k1_frost_share share[5];
    secp256k1_frost_share agg_share[5];
    const secp256k1_frost_share *share_ptr[5];
    int i;

    /* Key Setup */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        vss_ptr[i] = vss_commitment[i];
        share_ptr[i] = &share[i];

        CHECK(frost_create_pk(&pk[i], sk[i]));
    }
    CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[0], pok[0], session_id[0], 3) == 1);
    CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[1], pok[0], session_id[1], 3) == 1);
    CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[2], pok[0], session_id[2], 3) == 1);
    CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[3], pok[0], session_id[3], 3) == 1);
    CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[4], pok[0], session_id[4], 3) == 1);
    /* Signer 1 */
    CHECK(secp256k1_frost_share_gen(ctx, &share[0], vss_commitment[0], session_id[0], pk_ptr[0], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[1], vss_commitment[0], session_id[1], pk_ptr[0], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[2], vss_commitment[0], session_id[2], pk_ptr[0], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[3], vss_commitment[0], session_id[3], pk_ptr[0], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[4], vss_commitment[0], session_id[4], pk_ptr[0], 3) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[0], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[0], share_ptr[1], &vss_ptr[1]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[0], share_ptr[2], &vss_ptr[2]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[0], share_ptr[3], &vss_ptr[3]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[0], share_ptr[4], &vss_ptr[4]) == 1);
    CHECK(secp256k1_frost_share_agg(ctx, &agg_share[0], &P_xonly[0], vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[0]) == 1);
    CHECK(secp256k1_frost_compute_pubshare(ctx, &pubshare[0], 3, pk_ptr[0], vss_ptr, 5) == 1);
    /* Signer 2 */
    CHECK(secp256k1_frost_share_gen(ctx, &share[0], vss_commitment[1], session_id[0], pk_ptr[1], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[1], vss_commitment[1], session_id[1], pk_ptr[1], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[2], vss_commitment[1], session_id[2], pk_ptr[1], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[3], vss_commitment[1], session_id[3], pk_ptr[1], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[4], vss_commitment[1], session_id[4], pk_ptr[1], 3) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[1], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[1], share_ptr[1], &vss_ptr[1]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[1], share_ptr[2], &vss_ptr[2]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[1], share_ptr[3], &vss_ptr[3]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[1], share_ptr[4], &vss_ptr[4]) == 1);
    CHECK(secp256k1_frost_share_agg(ctx, &agg_share[1], &P_xonly[0], vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[1]) == 1);
    CHECK(secp256k1_frost_compute_pubshare(ctx, &pubshare[1], 3, pk_ptr[1], vss_ptr, 5) == 1);
    /* Signer 3 */
    CHECK(secp256k1_frost_share_gen(ctx, &share[0], vss_commitment[2], session_id[0], pk_ptr[2], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[1], vss_commitment[2], session_id[1], pk_ptr[2], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[2], vss_commitment[2], session_id[2], pk_ptr[2], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[3], vss_commitment[2], session_id[3], pk_ptr[2], 3) == 1);
    CHECK(secp256k1_frost_share_gen(ctx, &share[4], vss_commitment[2], session_id[4], pk_ptr[2], 3) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[2], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[2], share_ptr[1], &vss_ptr[1]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[2], share_ptr[2], &vss_ptr[2]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[2], share_ptr[3], &vss_ptr[3]) == 1);
    CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[2], share_ptr[4], &vss_ptr[4]) == 1);
    CHECK(secp256k1_frost_share_agg(ctx, &agg_share[2], &P_xonly[0], vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[2]) == 1);
    CHECK(secp256k1_frost_compute_pubshare(ctx, &pubshare[2], 3, pk_ptr[2], vss_ptr, 5) == 1);

    frost_tweak_test_helper(&P_xonly[0], &agg_share[0], &agg_share[1], &agg_share[2], NULL, pk_ptr, &pubshare[0], &pubshare[1], &pubshare[2]);
    CHECK(secp256k1_frost_pubkey_get(ctx, &P[0], &P_xonly[0]));
    CHECK(secp256k1_frost_pubkey_tweak(ctx, &tweak_cache, &P_xonly[0]) == 1);

    /* Compute Pi = f(Pj) + tweaki*G where where j = i-1 and try signing for */
    /* that key. If xonly is set to true, the function f is normalizes the input */
    /* point to have an even X-coordinate ("xonly-tweaking"). */
    /* Otherwise, the function f is the identity function.  */
    for (i = 1; i <= N_TWEAKS; i++) {
        unsigned char tweak[32];
        int P_parity;
        int xonly = secp256k1_testrand_bits(1);

        secp256k1_testrand256(tweak);
        if (xonly) {
            CHECK(secp256k1_frost_pubkey_xonly_tweak_add(ctx, &P[i], &tweak_cache, tweak) == 1);
        } else {
            CHECK(secp256k1_frost_pubkey_ec_tweak_add(ctx, &P[i], &tweak_cache, tweak) == 1);
        }
        CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &P_xonly[i], &P_parity, &P[i]));
        /* Check that frost_pubkey_tweak_add produces same result as */
        /* xonly_pubkey_tweak_add or ec_pubkey_tweak_add.  */
        if (xonly) {
            unsigned char P_serialized[32];
            CHECK(secp256k1_xonly_pubkey_serialize(ctx, P_serialized, &P_xonly[i]));
            CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, P_serialized, P_parity, &P_xonly[i-1], tweak) == 1);
        } else {
            secp256k1_pubkey tmp_key = P[i-1];
            CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &tmp_key, tweak));
            CHECK(secp256k1_memcmp_var(&tmp_key, &P[i], sizeof(tmp_key)) == 0);
        }
        /* Test signing for P[i] */
        frost_tweak_test_helper(&P_xonly[i], &agg_share[0], &agg_share[1], &agg_share[2], &tweak_cache, pk_ptr, &pubshare[0], &pubshare[1], &pubshare[2]);
    }
}

/* Performs a FROST DKG */
void frost_dkg_test_helper(secp256k1_frost_share *agg_share, secp256k1_xonly_pubkey *agg_pk, const secp256k1_xonly_pubkey *pk) {
    secp256k1_pubkey vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    unsigned char vss_hash[32];
    unsigned char pok[5][64];
    unsigned char session_id[5][32];
    secp256k1_frost_share share[5][5];
    const secp256k1_frost_share *share_ptr[5];
    int i, j;

    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(session_id[i]);
        vss_ptr[i] = vss_commitment[i];
    }
    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_vss_gen(ctx, vss_commitment[i], pok[i], session_id[i], 3) == 1);
        for (j = 0; j < 5; j++) {
            CHECK(secp256k1_frost_share_gen(ctx, &share[i][j], vss_commitment[j], session_id[i], &pk[j], 3) == 1);
        }
    }
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            share_ptr[j] = &share[j][i];
        }
        CHECK(secp256k1_frost_share_agg(ctx, &agg_share[i], agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, &pk[i]) == 1);
    }
}

/* Signs a message with a FROST keypair */
int frost_sign_test_helper(unsigned char *final_sig, const secp256k1_frost_share *agg_share, const secp256k1_xonly_pubkey *agg_pk, const secp256k1_xonly_pubkey * const* pubkeys, const unsigned char *msg, const secp256k1_pubkey *adaptor) {
    unsigned char session_id[3][32];
    secp256k1_frost_secnonce secnonce[3];
    secp256k1_frost_pubnonce pubnonce[3];
    const secp256k1_frost_pubnonce *pubnonce_ptr[3];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    secp256k1_frost_session session;
    int i;
    int nonce_parity;
    secp256k1_frost_session_internal session_i;

    for (i = 0; i < 3; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
    }

    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(session_id[i]);

        CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[i], &pubnonce[i], session_id[i], agg_share, NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(ctx, &session, pubnonce_ptr, 3, msg, agg_pk, pubkeys[i], pubkeys, NULL, adaptor) == 1);
        CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[i], &secnonce[i], &agg_share[i], &session, NULL) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 3) == 1);

    CHECK(secp256k1_frost_nonce_parity(ctx, &nonce_parity, &session));

    secp256k1_frost_session_load(ctx, &session_i, &session);

    return nonce_parity;
}

void frost_rand_scalar(secp256k1_scalar *scalar) {
    unsigned char buf32[32];
    secp256k1_testrand256(buf32);
    secp256k1_scalar_set_b32(scalar, buf32, NULL);
}

void frost_multi_hop_lock_tests(void) {
    secp256k1_frost_share agg_share_a[5];
    secp256k1_frost_share agg_share_b[5];
    secp256k1_xonly_pubkey agg_pk_a;
    secp256k1_xonly_pubkey agg_pk_b;
    secp256k1_xonly_pubkey pk_a[5];
    secp256k1_xonly_pubkey pk_b[5];
    const secp256k1_xonly_pubkey *pk_ptr_a[5];
    const secp256k1_xonly_pubkey *pk_ptr_b[5];
    unsigned char sk_a[5][32];
    unsigned char sk_b[5][32];
    unsigned char asig_ab[64];
    unsigned char asig_bc[64];
    unsigned char pop[32];
    secp256k1_pubkey pubkey_pop;
    unsigned char tx_ab[32];
    unsigned char tx_bc[32];
    unsigned char buf[32];
    secp256k1_scalar t1, t2, tp;
    secp256k1_pubkey l, r;
    secp256k1_ge l_ge, r_ge;
    secp256k1_scalar deckey;
    unsigned char sig_ab[64];
    unsigned char sig_bc[64];
    int nonce_parity_ab;
    int nonce_parity_bc;
    int i;

    /* Alice DKG */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(sk_a[i]);
        pk_ptr_a[i] = &pk_a[i];

        CHECK(frost_create_pk(&pk_a[i], sk_a[i]));
    }
    frost_dkg_test_helper(agg_share_a, &agg_pk_a, pk_a);

    /* Bob DKG */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(sk_b[i]);
        pk_ptr_b[i] = &pk_b[i];

        CHECK(frost_create_pk(&pk_b[i], sk_b[i]));
    }
    frost_dkg_test_helper(agg_share_b, &agg_pk_b, pk_b);

    /* Carol setup */
    /* Proof of payment */
    secp256k1_testrand256(pop);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_pop, pop));

    /* Alice setup */
    secp256k1_testrand256(tx_ab);
    frost_rand_scalar(&t1);
    frost_rand_scalar(&t2);
    secp256k1_scalar_add(&tp, &t1, &t2);
    /* Left lock */
    secp256k1_pubkey_load(ctx, &l_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&l_ge, &t1));
    secp256k1_pubkey_save(&l, &l_ge);
    /* Right lock */
    secp256k1_pubkey_load(ctx, &r_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&r_ge, &tp));
    secp256k1_pubkey_save(&r, &r_ge);
    /* Encrypt Alice's signature with the left lock as the encryption key */
    nonce_parity_ab = frost_sign_test_helper(asig_ab, agg_share_a, &agg_pk_a, pk_ptr_a, tx_ab, &l);

    /* Bob setup */
    CHECK(secp256k1_frost_verify_adaptor(ctx, asig_ab, tx_ab, &agg_pk_a, &l, nonce_parity_ab) == 1);
    secp256k1_testrand256(tx_bc);
    /* Encrypt Bob's signature with the right lock as the encryption key */
    nonce_parity_bc = frost_sign_test_helper(asig_bc, agg_share_b, &agg_pk_b, pk_ptr_b, tx_bc, &r);

    /* Carol decrypt */
    CHECK(secp256k1_frost_verify_adaptor(ctx, asig_bc, tx_bc, &agg_pk_b, &r, nonce_parity_bc) == 1);
    secp256k1_scalar_set_b32(&deckey, pop, NULL);
    secp256k1_scalar_add(&deckey, &deckey, &tp);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(ctx, sig_bc, asig_bc, buf, nonce_parity_bc));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig_bc, tx_bc, sizeof(tx_bc), &agg_pk_b) == 1);

    /* Bob recover and decrypt */
    CHECK(secp256k1_frost_extract_adaptor(ctx, buf, sig_bc, asig_bc, nonce_parity_bc));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&deckey, &deckey, &t2);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(ctx, sig_ab, asig_ab, buf, nonce_parity_ab));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig_ab, tx_ab, sizeof(tx_ab), &agg_pk_a) == 1);

    /* Alice recover and derive proof of payment */
    CHECK(secp256k1_frost_extract_adaptor(ctx, buf, sig_ab, asig_ab, nonce_parity_ab));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t1, &t1);
    secp256k1_scalar_add(&deckey, &deckey, &t1);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_memcmp_var(buf, pop, 32) == 0);
}

void run_frost_tests(void) {
    int i;

    for (i = 0; i < count; i++) {
        frost_simple_test();
    }
    frost_api_tests();
    frost_nonce_test();
    for (i = 0; i < count; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        frost_tweak_test();
    }
    frost_sha256_tag_test();
    for (i = 0; i < count; i++) {
        frost_multi_hop_lock_tests();
    }
}

#endif
