/***********************************************************************
 * Copyright (c) 2022, 2023 Jesse Posner                               *
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

/* Simple (non-adaptor, non-tweaked) 3-of-5 FROST aggregate, sign, verify
 * test. */
void frost_simple_test(void) {
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    unsigned char msg[32];
    secp256k1_xonly_pubkey pk;
    unsigned char seed[32];
    secp256k1_frost_share shares[5];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_pubkey pubshares[5];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    unsigned char final_sig[64];
    secp256k1_frost_session session;
    int i;
    size_t ids[5];

    secp256k1_testrand256(seed);

    for (i = 0; i < 5; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        ids[i] = i + 1;
    }

    CHECK(secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 3, 5) == 1);

    secp256k1_testrand256(msg);
    for (i = 0; i < 3; i++) {
        unsigned char session_id[32];

        secp256k1_testrand256(session_id);

        CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_id, &shares[i], NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(CTX, &session, pubnonce_ptr, 3, msg, &pk, ids[i], ids, NULL, NULL) == 1);
        CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[i], &secnonce[i], &shares[i], &session, NULL) == 1);
        CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[i], &pubnonce[i], &pubshares[i], &session, NULL) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session, partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk) == 1);
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

    secp256k1_frost_sum_nonces(CTX, summed_nonces, pubnonce_ptr, 2);
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
    /* unsigned char sk[5][32]; */
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[5][32];
    unsigned char seed[32];
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
    secp256k1_xonly_pubkey pk;
    secp256k1_pubkey full_pk;
    secp256k1_frost_tweak_cache tweak_cache;
    secp256k1_frost_tweak_cache invalid_tweak_cache;
    secp256k1_frost_session session[5];
    secp256k1_frost_session invalid_session;
    secp256k1_xonly_pubkey invalid_pk;
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey invalid_vss_pk;
    secp256k1_frost_share invalid_share;
    secp256k1_frost_share shares[5];
    secp256k1_pubkey pubshares[5];
    int i;
    size_t ids[5];
    size_t invalid_ids[5];

    /** setup **/
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
    secp256k1_testrand256(seed);
    CHECK(secp256k1_ec_pubkey_create(CTX, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 5; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        ids[i] = i + 1;
        invalid_ids[i] = i + 1;
        secp256k1_testrand256(session_id[i]);
    }
    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;
    invalid_ids[2] = 0;

    /** main test body **/

    /** Key generation **/
    CHECK(secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 3, 5) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, NULL, pubshares, &pk, seed, 3, 5));
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, NULL, &pk, seed, 3, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, NULL, seed, 3, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, NULL, 3, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 0, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 3, 0));
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 3, 2));

    CHECK(secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &pk, seed, 3, 5) == 1);

    /* pubkey_get */
    CHECK(secp256k1_frost_pubkey_get(CTX, &full_pk, &pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_get(CTX, NULL, &pk));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_get(CTX, &full_pk, NULL));
    CHECK(secp256k1_memcmp_var(&full_pk, zeros68, sizeof(full_pk)) == 0);

    /** Tweaking **/

    /* pubkey_tweak */
    CHECK(secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, &pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_tweak(CTX, NULL, &pk));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, &invalid_pk));

    CHECK(secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, &pk) == 1);

    /* tweak_add */
    {
        int (*tweak_func[2]) (const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32);
        tweak_func[0] = secp256k1_frost_pubkey_ec_tweak_add;
        tweak_func[1] = secp256k1_frost_pubkey_xonly_tweak_add;
        CHECK(secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, &pk) == 1);
        for (i = 0; i < 2; i++) {
            secp256k1_pubkey tmp_output_pk;
            secp256k1_frost_tweak_cache tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            /* Reset tweak_cache */
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(CTX, NULL, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, NULL, tweak));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, &tmp_tweak_cache, NULL));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_tweak_cache, max64) == 0);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            /* Uninitialized tweak_cache */
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, &invalid_tweak_cache, tweak));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
        }
    }

    /** Session creation **/
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &pk, max64) == 1);
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_frost_nonce_gen(STATIC_CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &pk, max64));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, NULL, &pubnonce[0], session_id[0], &shares[0], msg, &pk, max64));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], NULL, session_id[0], &shares[0], msg, &pk, max64));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], NULL, &shares[0], msg, &pk, max64));
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* no seckey and session_id is 0 */
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], zeros68, NULL, msg, &pk, max64) == 0);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* session_id 0 is fine when a seckey is provided */
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], zeros68, &shares[0], msg, &pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &pk, max64) == 1);
    /* invalid share */
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &invalid_share, msg, &pk, max64));
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], NULL, &pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, NULL, max64) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &invalid_pk, max64));
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &pk, NULL) == 1);

    /* Every in-argument except session_id can be NULL */
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], NULL, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[1], &pubnonce[1], session_id[1], &shares[1], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[2], &pubnonce[2], session_id[2], &shares[2], NULL, NULL, NULL) == 1);

    /** Serialize and parse public nonces **/
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, NULL, &pubnonce[0]));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, NULL));
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, &invalid_pubnonce));
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK(secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, &pubnonce[0]) == 1);

    CHECK(secp256k1_frost_pubnonce_parse(CTX, &pubnonce[0], pubnonce_ser) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_parse(CTX, NULL, pubnonce_ser));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_parse(CTX, &pubnonce[0], NULL));
    CHECK(secp256k1_frost_pubnonce_parse(CTX, &pubnonce[0], zeros68) == 0);
    CHECK(secp256k1_frost_pubnonce_parse(CTX, &pubnonce[0], pubnonce_ser) == 1);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_frost_pubnonce tmp;
        CHECK(secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, &pubnonce[0]) == 1);
        CHECK(secp256k1_frost_pubnonce_parse(CTX, &tmp, pubnonce_ser) == 1);
        CHECK(secp256k1_memcmp_var(&tmp, &pubnonce[0], sizeof(tmp)) == 0);
    }

    /** Process nonces **/
    CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, &adaptor) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, NULL, pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], NULL, 3, msg, &pk, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 0, msg, &pk, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], invalid_pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, NULL, &pk, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, NULL, ids[0], ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, 0, ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], invalid_ids, &tweak_cache, &adaptor));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], NULL, &tweak_cache, &adaptor));
    CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, NULL, &adaptor) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, &invalid_tweak_cache, &adaptor));
    CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, NULL) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, (secp256k1_pubkey *)&invalid_pk));

    CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, &pk, ids[0], ids, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(CTX, &session[1], pubnonce_ptr, 3, msg, &pk, ids[1], ids, &tweak_cache, &adaptor) == 1);
    CHECK(secp256k1_frost_nonce_process(CTX, &session[2], pubnonce_ptr, 3, msg, &pk, ids[2], ids, &tweak_cache, &adaptor) == 1);

    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &tweak_cache) == 1);
    /* The secnonce is set to 0 and subsequent signing attempts fail */
    CHECK(secp256k1_memcmp_var(&secnonce_tmp, zeros68, sizeof(secnonce_tmp)) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, NULL, &secnonce_tmp, &shares[0], &session[0], &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], NULL, &shares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &invalid_secnonce, &shares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, NULL, &session[0], &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &invalid_share, &session[0], &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], NULL, &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &invalid_session, &tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], NULL) == 1);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &invalid_tweak_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));

    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce[0], &shares[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[1], &secnonce[1], &shares[1], &session[1], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[2], &secnonce[2], &shares[2], &session[2], &tweak_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_serialize(CTX, buf, &partial_sig[0]) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_serialize(CTX, NULL, &partial_sig[0]));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_serialize(CTX, buf, NULL));
    CHECK(secp256k1_frost_partial_sig_parse(CTX, &partial_sig[0], buf) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_parse(CTX, NULL, buf));
    CHECK(secp256k1_frost_partial_sig_parse(CTX, &partial_sig[0], max64) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_parse(CTX, &partial_sig[0], NULL));

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_frost_partial_sig tmp;
        CHECK(secp256k1_frost_partial_sig_serialize(CTX, buf, &partial_sig[0]) == 1);
        CHECK(secp256k1_frost_partial_sig_parse(CTX, &tmp, buf) == 1);
        CHECK(secp256k1_memcmp_var(&tmp, &partial_sig[0], sizeof(tmp)) == 0);
    }

    /** Partial signature verification */
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[0], &pubshares[0], &session[0], &tweak_cache) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, NULL, &pubnonce[0], &pubshares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &invalid_partial_sig, &pubnonce[0], &pubshares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], NULL, &pubshares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &invalid_pubnonce, &pubshares[0], &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], NULL, &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &invalid_vss_pk, &session[0], &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], NULL, &tweak_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], &invalid_session, &tweak_cache));
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], &session[0], NULL) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], &session[0], &invalid_tweak_cache));

    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshares[0], &session[0], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[1], &pubshares[1], &session[1], &tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[2], &pubnonce[2], &pubshares[2], &session[2], &tweak_cache) == 1);

    /** Signature aggregation and verification */
    CHECK(secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[0], partial_sig_ptr, 3) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, NULL, &session[0], partial_sig_ptr, 3));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, pre_sig, NULL, partial_sig_ptr, 3));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, pre_sig, &invalid_session, partial_sig_ptr, 3));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[0], NULL, 3));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[0], invalid_partial_sig_ptr, 3));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[0], partial_sig_ptr, 0));
    CHECK(secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[0], partial_sig_ptr, 1) == 1);
    CHECK(secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[1], partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_frost_partial_sig_agg(CTX, pre_sig, &session[2], partial_sig_ptr, 3) == 1);

    /** Adaptor signature verification */
    CHECK(secp256k1_frost_nonce_parity(CTX, &nonce_parity, &session[0]) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_parity(CTX, NULL, &session[0]));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_parity(CTX, &nonce_parity, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_parity(CTX, &nonce_parity, &invalid_session));

    CHECK(secp256k1_frost_adapt(CTX, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_adapt(CTX, NULL, pre_sig, sec_adaptor, 0));
    CHECK_ILLEGAL(CTX, secp256k1_frost_adapt(CTX, final_sig, NULL, sec_adaptor, 0));
    CHECK(secp256k1_frost_adapt(CTX, final_sig, max64, sec_adaptor, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_adapt(CTX, final_sig, pre_sig, NULL, 0));
    CHECK(secp256k1_frost_adapt(CTX, final_sig, pre_sig, max64, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_adapt(CTX, final_sig, pre_sig, sec_adaptor, 2));
    /* sig and pre_sig argument point to the same location */
    memcpy(final_sig, pre_sig, sizeof(final_sig));
    CHECK(secp256k1_frost_adapt(CTX, final_sig, final_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk) == 1);

    CHECK(secp256k1_frost_adapt(CTX, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk) == 1);

    /** Secret adaptor can be extracted from signature */
    CHECK(secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) == 0);
    /* wrong nonce parity */
    CHECK(secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, !nonce_parity) == 1);
    CHECK(secp256k1_memcmp_var(sec_adaptor, sec_adaptor1, 32) != 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_extract_adaptor(CTX, NULL, final_sig, pre_sig, 0));
    CHECK_ILLEGAL(CTX, secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, NULL, pre_sig, 0));
    CHECK(secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, max64, pre_sig, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, final_sig, NULL, 0));
    CHECK(secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, final_sig, max64, 0) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_extract_adaptor(CTX, sec_adaptor1, final_sig, pre_sig, 2));
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
    for (i = 0; i < COUNT; i++) {
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

/* Attempts to create a signature for the aggregate public key using given secret
 * keys and tweak_cache. */
void frost_tweak_test_helper(const secp256k1_xonly_pubkey* pk, const secp256k1_frost_share *sr0, const secp256k1_frost_share *sr1, const secp256k1_frost_share *sr2, secp256k1_frost_tweak_cache *tweak_cache, const size_t *ids, const secp256k1_pubkey *sr_pk0, const secp256k1_pubkey *sr_pk1, const secp256k1_pubkey *sr_pk2) {
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


    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], sr0, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[1], &pubnonce[1], session_id[1], sr1, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[2], &pubnonce[2], session_id[2], sr2, NULL, NULL, NULL) == 1);

    CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, pk, ids[0], ids, tweak_cache, NULL) == 1);
    CHECK(secp256k1_frost_nonce_process(CTX, &session[1], pubnonce_ptr, 3, msg, pk, ids[1], ids, tweak_cache, NULL) == 1);
    CHECK(secp256k1_frost_nonce_process(CTX, &session[2], pubnonce_ptr, 3, msg, pk, ids[2], ids, tweak_cache, NULL) == 1);


    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce[0], sr0, &session[0], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[1], &secnonce[1], sr1, &session[1], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[2], &secnonce[2], sr2, &session[2], tweak_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], sr_pk0, &session[0], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[1], sr_pk1, &session[1], tweak_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[2], &pubnonce[2], sr_pk2, &session[2], tweak_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session[0], partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), pk) == 1);
}

/* Create aggregate public key P[0], tweak multiple times (using xonly and
 * ordinary tweaking) and test signing. */
void frost_tweak_test(void) {
    secp256k1_pubkey pubshares[5];
    secp256k1_frost_tweak_cache tweak_cache;
    enum { N_TWEAKS = 8 };
    secp256k1_pubkey P[N_TWEAKS + 1];
    secp256k1_xonly_pubkey P_xonly[N_TWEAKS + 1];
    unsigned char seed[32];
    secp256k1_frost_share shares[5];
    int i;
    size_t ids[5];

    secp256k1_testrand256(seed);

    /* Key Setup */
    for (i = 0; i < 5; i++) {
        ids[i] = i + 1;
    }
    CHECK(secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, &P_xonly[0], seed, 3, 5) == 1);

    frost_tweak_test_helper(&P_xonly[0], &shares[0], &shares[1], &shares[2], NULL, ids, &pubshares[0], &pubshares[1], &pubshares[2]);
    CHECK(secp256k1_frost_pubkey_get(CTX, &P[0], &P_xonly[0]));
    CHECK(secp256k1_frost_pubkey_tweak(CTX, &tweak_cache, &P_xonly[0]) == 1);

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
            CHECK(secp256k1_frost_pubkey_xonly_tweak_add(CTX, &P[i], &tweak_cache, tweak) == 1);
        } else {
            CHECK(secp256k1_frost_pubkey_ec_tweak_add(CTX, &P[i], &tweak_cache, tweak) == 1);
        }
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &P_xonly[i], &P_parity, &P[i]));
        /* Check that frost_pubkey_tweak_add produces same result as */
        /* xonly_pubkey_tweak_add or ec_pubkey_tweak_add.  */
        if (xonly) {
            unsigned char P_serialized[32];
            CHECK(secp256k1_xonly_pubkey_serialize(CTX, P_serialized, &P_xonly[i]));
            CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, P_serialized, P_parity, &P_xonly[i-1], tweak) == 1);
        } else {
            secp256k1_pubkey tmp_key = P[i-1];
            CHECK(secp256k1_ec_pubkey_tweak_add(CTX, &tmp_key, tweak));
            CHECK(secp256k1_memcmp_var(&tmp_key, &P[i], sizeof(tmp_key)) == 0);
        }
        /* Test signing for P[i] */
        frost_tweak_test_helper(&P_xonly[i], &shares[0], &shares[1], &shares[2], &tweak_cache, ids, &pubshares[0], &pubshares[1], &pubshares[2]);
    }
}

/* Performs a FROST DKG */
void frost_dkg_test_helper(secp256k1_frost_share *shares, secp256k1_xonly_pubkey *pk) {
    unsigned char seed[32];
    secp256k1_pubkey pubshares[5];

    secp256k1_testrand256(seed);

    CHECK(secp256k1_frost_shares_trusted_gen(CTX, shares, pubshares, pk, seed, 3, 5) == 1);
}

/* Signs a message with a FROST keypair */
int frost_sign_test_helper(unsigned char *final_sig, const secp256k1_frost_share *share, const secp256k1_xonly_pubkey *pk, const unsigned char *msg, const secp256k1_pubkey *adaptor) {
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
    size_t ids[5];

    for (i = 0; i < 3; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        ids[i] = i + 1;
    }

    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(session_id[i]);

        CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_id[i], &share[i], NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(CTX, &session, pubnonce_ptr, 3, msg, pk, i + 1, ids, NULL, adaptor) == 1);
        CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[i], &secnonce[i], &share[i], &session, NULL) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session, partial_sig_ptr, 3) == 1);

    CHECK(secp256k1_frost_nonce_parity(CTX, &nonce_parity, &session));

    secp256k1_frost_session_load(CTX, &session_i, &session);

    return nonce_parity;
}

void frost_rand_scalar(secp256k1_scalar *scalar) {
    unsigned char buf32[32];
    secp256k1_testrand256(buf32);
    secp256k1_scalar_set_b32(scalar, buf32, NULL);
}

void frost_multi_hop_lock_tests(void) {
    secp256k1_frost_share share_a[5];
    secp256k1_frost_share share_b[5];
    secp256k1_xonly_pubkey agg_pk_a;
    secp256k1_xonly_pubkey agg_pk_b;
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

    /* Alice DKG */
    frost_dkg_test_helper(share_a, &agg_pk_a);

    /* Bob DKG */
    frost_dkg_test_helper(share_b, &agg_pk_b);

    /* Carol setup */
    /* Proof of payment */
    secp256k1_testrand256(pop);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pubkey_pop, pop));

    /* Alice setup */
    secp256k1_testrand256(tx_ab);
    frost_rand_scalar(&t1);
    frost_rand_scalar(&t2);
    secp256k1_scalar_add(&tp, &t1, &t2);
    /* Left lock */
    secp256k1_pubkey_load(CTX, &l_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&l_ge, &t1));
    secp256k1_pubkey_save(&l, &l_ge);
    /* Right lock */
    secp256k1_pubkey_load(CTX, &r_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&r_ge, &tp));
    secp256k1_pubkey_save(&r, &r_ge);
    /* Encrypt Alice's signature with the left lock as the encryption key */
    nonce_parity_ab = frost_sign_test_helper(asig_ab, share_a, &agg_pk_a, tx_ab, &l);

    /* Bob setup */
    CHECK(secp256k1_frost_verify_adaptor(CTX, asig_ab, tx_ab, &agg_pk_a, &l, nonce_parity_ab) == 1);
    secp256k1_testrand256(tx_bc);
    /* Encrypt Bob's signature with the right lock as the encryption key */
    nonce_parity_bc = frost_sign_test_helper(asig_bc, share_b, &agg_pk_b, tx_bc, &r);

    /* Carol decrypt */
    CHECK(secp256k1_frost_verify_adaptor(CTX, asig_bc, tx_bc, &agg_pk_b, &r, nonce_parity_bc) == 1);
    secp256k1_scalar_set_b32(&deckey, pop, NULL);
    secp256k1_scalar_add(&deckey, &deckey, &tp);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(CTX, sig_bc, asig_bc, buf, nonce_parity_bc));
    CHECK(secp256k1_schnorrsig_verify(CTX, sig_bc, tx_bc, sizeof(tx_bc), &agg_pk_b) == 1);

    /* Bob recover and decrypt */
    CHECK(secp256k1_frost_extract_adaptor(CTX, buf, sig_bc, asig_bc, nonce_parity_bc));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&deckey, &deckey, &t2);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(CTX, sig_ab, asig_ab, buf, nonce_parity_ab));
    CHECK(secp256k1_schnorrsig_verify(CTX, sig_ab, tx_ab, sizeof(tx_ab), &agg_pk_a) == 1);

    /* Alice recover and derive proof of payment */
    CHECK(secp256k1_frost_extract_adaptor(CTX, buf, sig_ab, asig_ab, nonce_parity_ab));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t1, &t1);
    secp256k1_scalar_add(&deckey, &deckey, &t1);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_memcmp_var(buf, pop, 32) == 0);
}

void run_frost_tests(void) {
    int i;

    for (i = 0; i < COUNT; i++) {
        frost_simple_test();
    }
    frost_api_tests();
    frost_nonce_test();
    for (i = 0; i < COUNT; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        frost_tweak_test();
    }
    for (i = 0; i < COUNT; i++) {
        frost_multi_hop_lock_tests();
    }
}

#endif
