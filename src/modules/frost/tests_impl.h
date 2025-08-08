/***********************************************************************
 * Copyright (c) 2022-2024 Jesse Posner                                *
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

/* Simple (non-adaptor, non-tweaked) 3-of-5 FROST generate, sign, verify
 * test. */
void frost_simple_test(void) {
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    unsigned char msg[32];
    secp256k1_pubkey vss_commitment[3];
    secp256k1_xonly_pubkey pk_xonly;
    secp256k1_pubkey pk;
    unsigned char buf[32];
    secp256k1_frost_secshare shares[5];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_pubkey pubshare[5];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    unsigned char final_sig[64];
    secp256k1_frost_session session;
    int i;
    size_t ids[5];
    const secp256k1_pubkey *pubshare_ptr[5];
    secp256k1_frost_keygen_cache cache;

    for (i = 0; i < 5; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        ids[i] = i;
        pubshare_ptr[i] = &pubshare[i];
    }
    secp256k1_testrand256(buf);
    CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, buf, 3, 5) == 1);
    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_share_verify(CTX, 3, i, &shares[i], vss_commitment) == 1);
        CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[i], 3, i, vss_commitment) == 1);
    }
    CHECK(secp256k1_frost_pubkey_gen(CTX, &cache, pubshare_ptr, 5, ids) == 1);

    secp256k1_testrand256(msg);
    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(buf);

        CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[i], &pubnonce[i], buf, &shares[i], NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(CTX, &session, pubnonce_ptr, 3, msg, i, ids, &cache, NULL) == 1);
        CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[i], &secnonce[i], &shares[i], &session, &cache) == 1);
        CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[i], &pubnonce[i], &pubshare[i], &session, &cache) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session, partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_frost_pubkey_get(CTX, &pk, &cache) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &pk_xonly, NULL, &pk) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk_xonly) == 1);
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
    unsigned char sk[5][32];
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
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey pk_xonly;
    secp256k1_frost_keygen_cache keygen_cache;
    secp256k1_frost_keygen_cache invalid_keygen_cache;
    secp256k1_frost_session session[5];
    secp256k1_frost_session invalid_session;
    secp256k1_xonly_pubkey invalid_pk;
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey vss_commitment[3];
    secp256k1_pubkey invalid_vss_commitment[3];
    secp256k1_pubkey invalid_pubshare;
    secp256k1_frost_secshare shares[5];
    secp256k1_frost_secshare invalid_share;
    secp256k1_pubkey pubshare[5];
    int i;
    size_t ids[5];
    const secp256k1_pubkey *pubshare_ptr[5];

    /** setup **/
    memset(max64, 0xff, sizeof(max64));
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_share, 0, sizeof(invalid_share));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_pubshare, 0, sizeof(invalid_pubshare));
    memset(&invalid_keygen_cache, 0, sizeof(invalid_keygen_cache));
    memset(&invalid_session, 0, sizeof(invalid_session));
    frost_pubnonce_summing_to_inf(inf_pubnonce);

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(CTX, &adaptor, sec_adaptor) == 1);
    secp256k1_testrand256(seed);
    for (i = 0; i < 5; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        invalid_pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        ids[i] = i;
        pubshare_ptr[i] = &pubshare[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
    }
    for (i = 0; i < 3; i++) {
        invalid_vss_commitment[i] = vss_commitment[i];
    }

    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;
    invalid_vss_commitment[0] = invalid_pubshare;

    /** main test body **/

    /** Key generation **/
    CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 5) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, NULL, vss_commitment, seed, 3, 5));
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, shares, NULL, seed, 3, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, shares, vss_commitment, NULL, 3, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 0, 5));
    for (i = 0; i < 5; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 0));
    CHECK_ILLEGAL(CTX, secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 2));
    for (i = 0; i < 2; i++) {
        CHECK(frost_memcmp_and_randomize(shares[i].data, zeros68, sizeof(shares[i].data)) == 0);
    }

    CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 5) == 1);

    /* Share verification */
    /* CHECK(secp256k1_frost_share_verify(CTX, 3, id_ptr[0], &shares[0], vss_commitment) == 1); */
    /* CHECK(secp256k1_frost_share_verify(CTX, 3, id_ptr[1], &shares[0], vss_commitment) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 3, NULL, &shares[0], vss_commitment)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 3, id_ptr[0], NULL, vss_commitment)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 3, id_ptr[0], &invalid_share, vss_commitment)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 3, id_ptr[0], &shares[0], NULL)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 3, id_ptr[0], &shares[0], invalid_vss_commitment)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_share_verify(CTX, 0, id_ptr[4], &shares[0], vss_commitment)); */

    /* Compute public verification share */
    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], vss_commitment) == 1); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, NULL, 3, id_ptr[0], vss_commitment)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, NULL, vss_commitment)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], NULL)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], invalid_vss_commitment)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 0, id_ptr[0], invalid_vss_commitment)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 0, id_ptr[0], NULL)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], invalid_vss_commitment)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], NULL)); */
    /* CHECK(frost_memcmp_and_randomize(pubshare[0].data, zeros68, sizeof(pubshare[0].data)) == 0); */

    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[0], 3, id_ptr[0], vss_commitment) == 1); */
    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[1], 3, id_ptr[1], vss_commitment) == 1); */
    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[2], 3, id_ptr[2], vss_commitment) == 1); */
    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[3], 3, id_ptr[3], vss_commitment) == 1); */
    /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[4], 3, id_ptr[4], vss_commitment) == 1); */

    /* pubkey_gen */
    /* CHECK(secp256k1_frost_pubkey_gen(CTX, &keygen_cache, pubshare_ptr, 5, id_ptr) == 1); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_gen(CTX, NULL, pubshare_ptr, 5, id_ptr)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_gen(CTX, &keygen_cache, NULL, 5, id_ptr)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_gen(CTX, &keygen_cache, pubshare_ptr, 0, id_ptr)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_gen(CTX, &keygen_cache, pubshare_ptr, 5, NULL)); */

    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_compute_pubshare(
            CTX, &pubshare[i], 3, i, vss_commitment) == 1);
        pubshare_ptr[i] = &pubshare[i];
    }
    CHECK(secp256k1_frost_pubkey_gen(
        CTX, &keygen_cache, pubshare_ptr, 5, ids) == 1);


    /* pubkey_get */
    memset(&pk, 0, sizeof(pk));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_get(CTX, NULL, &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubkey_get(CTX, &pk, NULL));
    CHECK(secp256k1_memcmp_var(&pk, zeros68, sizeof(pk)) == 0);
    CHECK(secp256k1_frost_pubkey_get(CTX, &pk, &keygen_cache) == 1);

    /* tweak_add */
    {
        int (*tweak_func[2]) (const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_keygen_cache *keygen_cache, const unsigned char *tweak32);
        tweak_func[0] = secp256k1_frost_pubkey_ec_tweak_add;
        tweak_func[1] = secp256k1_frost_pubkey_xonly_tweak_add;

        for (i = 0; i < 2; i++) {
            secp256k1_pubkey tmp_output_pk;
            secp256k1_frost_keygen_cache tmp_keygen_cache = keygen_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_keygen_cache, tweak) == 1);
            /* Reset keygen_cache */
            tmp_keygen_cache = keygen_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_keygen_cache, tweak) == 1);
            tmp_keygen_cache = keygen_cache;
            CHECK((*tweak_func[i])(CTX, NULL, &tmp_keygen_cache, tweak) == 1);
            tmp_keygen_cache = keygen_cache;
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, NULL, tweak));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keygen_cache = keygen_cache;
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, &tmp_keygen_cache, NULL));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keygen_cache = keygen_cache;
            CHECK((*tweak_func[i])(CTX, &tmp_output_pk, &tmp_keygen_cache, max64) == 0);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keygen_cache = keygen_cache;
            /* Uninitialized keygen_cache */
            CHECK_ILLEGAL(CTX, (*tweak_func[i])(CTX, &tmp_output_pk, &invalid_keygen_cache, tweak));
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
        }
    }

    /** Session creation **/
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &pk_xonly, NULL, &pk) == 1);
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &keygen_cache, max64) == 1); */
    /* CHECK_ILLEGAL(STATIC_CTX, secp256k1_frost_nonce_gen(STATIC_CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &keygen_cache, max64)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, NULL, &pubnonce[0], session_id[0], &shares[0], msg, &keygen_cache, max64)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], NULL, session_id[0], &shares[0], msg, &keygen_cache, max64)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], NULL, &shares[0], msg, &keygen_cache, max64)); */
    /* CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0); */
    /* [> no seckey and session_id is 0 <] */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], zeros68, NULL, msg, &keygen_cache, max64) == 0); */
    /* CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0); */
    /* [> session_id 0 is fine when a seckey is provided <] */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], zeros68, &shares[0], msg, &keygen_cache, max64) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &keygen_cache, max64) == 1); */
    /* [> invalid share <] */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &invalid_share, msg, &keygen_cache, max64)); */
    /* CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], NULL, &keygen_cache, max64) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, NULL, max64) == 1); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &invalid_keygen_cache, max64)); */
    /* CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], &shares[0], msg, &keygen_cache, NULL) == 1); */

    /* [> Every in-argument except session_id can be NULL <] */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], NULL, NULL, NULL, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[1], &pubnonce[1], session_id[1], &shares[1], NULL, NULL, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[2], &pubnonce[2], session_id[2], &shares[2], NULL, NULL, NULL) == 1); */

    for (i = 0; i < 3; i++) {
    CHECK(secp256k1_frost_nonce_gen(
        CTX,
        &secnonce[i],
        &pubnonce[i],
        session_id[i],
        &shares[i],
        NULL,
        NULL,
        NULL
    ) == 1);
    pubnonce_ptr[i] = &pubnonce[i];
}

    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(
            CTX,
            &session[i],
            pubnonce_ptr,
            3,
            msg,
            ids[i],
            ids,
            &keygen_cache,
            &adaptor
        ) == 1);
    }

    /** Serialize and parse public nonces **/
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, NULL, &pubnonce[0]));
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, NULL));
    CHECK(frost_memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_pubnonce_serialize(CTX, pubnonce_ser, &invalid_pubnonce));
    CHECK(frost_memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
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
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor) == 1); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, NULL, pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], NULL, 3, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 0, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], invalid_pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, NULL, id_ptr[0], id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, NULL, id_ptr, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], NULL, &keygen_cache, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, NULL, &adaptor)); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &invalid_keygen_cache, &adaptor)); */
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, NULL) == 1); */
    /* CHECK_ILLEGAL(CTX, secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, (secp256k1_pubkey *)&invalid_pk)); */

    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, id_ptr[0], id_ptr, &keygen_cache, &adaptor) == 1); */
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[1], pubnonce_ptr, 3, msg, id_ptr[1], id_ptr, &keygen_cache, &adaptor) == 1); */
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[2], pubnonce_ptr, 3, msg, id_ptr[2], id_ptr, &keygen_cache, &adaptor) == 1); */

    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &keygen_cache) == 1);
    /* The secnonce is set to 0 and subsequent signing attempts fail */
    CHECK(secp256k1_memcmp_var(&secnonce_tmp, zeros68, sizeof(secnonce_tmp)) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, NULL, &secnonce_tmp, &shares[0], &session[0], &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], NULL, &shares[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &invalid_secnonce, &shares[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, NULL, &session[0], &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &invalid_share, &session[0], &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], NULL, &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &invalid_session, &keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], NULL));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce_tmp, &shares[0], &session[0], &invalid_keygen_cache));
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));

    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce[0], &shares[0], &session[0], &keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[1], &secnonce[1], &shares[1], &session[1], &keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[2], &secnonce[2], &shares[2], &session[2], &keygen_cache) == 1);

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
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[0], &pubshare[0], &session[0], &keygen_cache) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, NULL, &pubnonce[0], &pubshare[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &invalid_partial_sig, &pubnonce[0], &pubshare[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], NULL, &pubshare[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &invalid_pubnonce, &pubshare[0], &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], NULL, &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &invalid_pubshare, &session[0], &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], NULL, &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], &invalid_session, &keygen_cache));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], NULL));
    CHECK_ILLEGAL(CTX, secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &invalid_keygen_cache));

    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pubshare[0], &session[0], &keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[1], &pubshare[1], &session[1], &keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[2], &pubnonce[2], &pubshare[2], &session[2], &keygen_cache) == 1);

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
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk_xonly) == 1);

    CHECK(secp256k1_frost_adapt(CTX, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), &pk_xonly) == 1);

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
    for (i = 0; i < 5; i++) {
        CHECK(!secp256k1_scalar_eq(&k[i][0], &k[i][1]));
        for (j = i+1; j < 5; j++) {
            CHECK(!secp256k1_scalar_eq(&k[i][0], &k[j][0]));
            CHECK(!secp256k1_scalar_eq(&k[i][1], &k[j][1]));
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

/* Attempts to create a signature for the group public key using given secret
 * keys and keygen_cache. */
void frost_tweak_test_helper(const secp256k1_xonly_pubkey* agg_pk, const secp256k1_frost_secshare *sr0, const secp256k1_frost_secshare *sr1, const secp256k1_frost_secshare *sr2, secp256k1_frost_keygen_cache *keygen_cache, const unsigned char * const* ids33, const secp256k1_pubkey *sr_pk0, const secp256k1_pubkey *sr_pk1, const secp256k1_pubkey *sr_pk2) {
    unsigned char session_id[3][32];
    unsigned char msg[32];
    secp256k1_frost_secnonce secnonce[3];
    secp256k1_frost_pubnonce pubnonce[3];
    const secp256k1_frost_pubnonce *pubnonce_ptr[3];
    secp256k1_frost_session session[5];
    secp256k1_frost_partial_sig partial_sig[3];
    const secp256k1_frost_partial_sig *partial_sig_ptr[3];
    unsigned char final_sig[64];
    size_t ids[3] = {0, 1, 2};
    int i;

    for (i = 0; i < 3; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        secp256k1_testrand256(session_id[i]);
    }
    secp256k1_testrand256(msg);


    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_id[0], sr0, NULL, NULL, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[1], &pubnonce[1], session_id[1], sr1, NULL, NULL, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[2], &pubnonce[2], session_id[2], sr2, NULL, NULL, NULL) == 1); */

    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[0], pubnonce_ptr, 3, msg, ids33[0], ids33, keygen_cache, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[1], pubnonce_ptr, 3, msg, ids33[1], ids33, keygen_cache, NULL) == 1); */
    /* CHECK(secp256k1_frost_nonce_process(CTX, &session[2], pubnonce_ptr, 3, msg, ids33[2], ids33, keygen_cache, NULL) == 1); */

    for (i = 0; i < 3; i++) {
        const secp256k1_frost_secshare *share = (i==0 ? sr0 : i==1 ? sr1 : sr2);
        CHECK(secp256k1_frost_nonce_gen(
            CTX,
            &secnonce[i],
            &pubnonce[i],
            session_id[i],
            share,
            NULL,
            NULL,
            NULL
        ) == 1);
    }

    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(
            CTX,
            &session[i],
            pubnonce_ptr,
            3,
            msg,
            ids[i],
            ids,
            keygen_cache,
            NULL
        ) == 1);
    }


    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[0], &secnonce[0], sr0, &session[0], keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[1], &secnonce[1], sr1, &session[1], keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[2], &secnonce[2], sr2, &session[2], keygen_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], sr_pk0, &session[0], keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[1], sr_pk1, &session[1], keygen_cache) == 1);
    CHECK(secp256k1_frost_partial_sig_verify(CTX, &partial_sig[2], &pubnonce[2], sr_pk2, &session[2], keygen_cache) == 1);

    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session[0], partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, final_sig, msg, sizeof(msg), agg_pk) == 1);
}

/* Create group public key P[0], tweak multiple times (using xonly and
 * ordinary tweaking) and test signing. */
void frost_tweak_test(void) {
    unsigned char sk[5][32];
    secp256k1_pubkey pubshare[5];
    secp256k1_frost_keygen_cache keygen_cache;
    enum { N_TWEAKS = 8 };
    secp256k1_pubkey P[N_TWEAKS + 1];
    secp256k1_xonly_pubkey P_xonly[N_TWEAKS + 1];
    unsigned char seed[32];
    secp256k1_pubkey vss_commitment[3];
    secp256k1_frost_secshare shares[5];
    int i;
    unsigned char id[5][33];
    const unsigned char *id_ptr[5];
    const secp256k1_pubkey *pubshare_ptr[5];

    /* Key Setup */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(sk[i]);
        id_ptr[i] = id[i];
        pubshare_ptr[i] = &pubshare[i];
    }
    secp256k1_testrand256(seed);
    size_t ids[5];
    CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 5) == 1);
    /* CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 5, id_ptr) == 1); */
    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[i], 3, i, vss_commitment) == 1);
        pubshare_ptr[i] = &pubshare[i];
        ids[i] = i;
        /* CHECK(secp256k1_frost_share_verify(CTX, 3, id_ptr[i], &shares[i], vss_commitment) == 1); */
        /* CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[i], 3, id_ptr[i], vss_commitment) == 1); */
    }
    CHECK(secp256k1_frost_pubkey_gen(CTX, &keygen_cache, pubshare_ptr, 5, ids) == 1);
    /* Compute P0 and test signing for it */
    /* CHECK(secp256k1_frost_pubkey_gen(CTX, &keygen_cache, pubshare_ptr, 5, id_ptr) == 1); */
    CHECK(secp256k1_frost_pubkey_get(CTX, &P[0], &keygen_cache) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &P_xonly[0], NULL, &P[0]));
    frost_tweak_test_helper(&P_xonly[0], &shares[0], &shares[1], &shares[2], &keygen_cache, id_ptr, &pubshare[0], &pubshare[1], &pubshare[2]);

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
            CHECK(secp256k1_frost_pubkey_xonly_tweak_add(CTX, &P[i], &keygen_cache, tweak) == 1);
        } else {
            CHECK(secp256k1_frost_pubkey_ec_tweak_add(CTX, &P[i], &keygen_cache, tweak) == 1);
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
        frost_tweak_test_helper(&P_xonly[i], &shares[0], &shares[1], &shares[2], &keygen_cache, id_ptr, &pubshare[0], &pubshare[1], &pubshare[2]);
    }
}

/* Performs a FROST DKG */
void frost_dkg_test_helper(secp256k1_frost_keygen_cache *keygen_cache, secp256k1_frost_secshare *shares, const unsigned char * const *ids33) {
    secp256k1_pubkey vss_commitment[3];
    unsigned char seed[32];
    int i;
    secp256k1_pubkey pubshare[5];
    const secp256k1_pubkey *pubshare_ptr[5];

    secp256k1_testrand256(seed);
    for (i = 0; i < 5; i++) {
        pubshare_ptr[i] = &pubshare[i];
    }
    CHECK(secp256k1_frost_shares_gen(CTX, shares, vss_commitment, seed, 3, 5) == 1);
    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_frost_compute_pubshare(CTX, &pubshare[i], 3, (size_t)i, vss_commitment) == 1);
    }
    {
        size_t ids[5] = {0,1,2,3,4};
        CHECK(secp256k1_frost_pubkey_gen(CTX, keygen_cache, pubshare_ptr, 5, ids) == 1);
    }
}

/* Signs a message with a FROST keypair */
int frost_sign_test_helper(unsigned char *final_sig, const secp256k1_frost_secshare *shares, const unsigned char * const *ids33, const unsigned char *msg, const secp256k1_pubkey *adaptor, secp256k1_frost_keygen_cache *keygen_cache) {
    unsigned char session_id[3][32];
    secp256k1_frost_secnonce secnonce[3];
    secp256k1_frost_pubnonce pubnonce[3];
    const secp256k1_frost_pubnonce *pubnonce_ptr[3];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    secp256k1_frost_session session[3];
    int i;
    int nonce_parity;
    secp256k1_frost_session_internal session_i;

    for (i = 0; i < 3; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
    }

    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(session_id[i]);
        CHECK(secp256k1_frost_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_id[i], &shares[i], NULL, NULL, NULL) == 1);
    }
    {
        size_t ids[3] = {0, 1, 2};
        for (i = 0; i < 3; i++) {
            CHECK(secp256k1_frost_nonce_process(CTX, &session[i], pubnonce_ptr, 3, msg, ids[i], ids, keygen_cache, adaptor) == 1);
        }
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_partial_sign(CTX, &partial_sig[i], &secnonce[i], &shares[i], &session[i], keygen_cache) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(CTX, final_sig, &session[0], partial_sig_ptr, 3) == 1);

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
    secp256k1_frost_secshare shares_a[5];
    secp256k1_frost_secshare shares_b[5];
    secp256k1_xonly_pubkey pk_a;
    secp256k1_xonly_pubkey pk_b;
    secp256k1_pubkey tmp;
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
    unsigned char id_a[5][33];
    const unsigned char *id_ptr_a[5];
    unsigned char id_b[5][33];
    const unsigned char *id_ptr_b[5];
    secp256k1_frost_keygen_cache cache_a;
    secp256k1_frost_keygen_cache cache_b;

    /* Alice DKG */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(sk_a[i]);
        id_ptr_a[i] = id_a[i];
    }
    frost_dkg_test_helper(&cache_a, shares_a, id_ptr_a);
    CHECK(secp256k1_frost_pubkey_get(CTX, &tmp, &cache_a) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &pk_a, NULL, &tmp) == 1);

    /* Bob DKG */
    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(sk_b[i]);
        id_ptr_b[i] = id_b[i];
    }
    frost_dkg_test_helper(&cache_b, shares_b, id_ptr_b);
    CHECK(secp256k1_frost_pubkey_get(CTX, &tmp, &cache_b) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &pk_b, NULL, &tmp) == 1);

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
    nonce_parity_ab = frost_sign_test_helper(asig_ab, shares_a, id_ptr_a, tx_ab, &l, &cache_a);

    /* Bob setup */
    CHECK(secp256k1_frost_verify_adaptor(CTX, asig_ab, tx_ab, &pk_a, &l, nonce_parity_ab) == 1);
    secp256k1_testrand256(tx_bc);
    /* Encrypt Bob's signature with the right lock as the encryption key */
    nonce_parity_bc = frost_sign_test_helper(asig_bc, shares_b, id_ptr_b, tx_bc, &r, &cache_b);

    /* Carol decrypt */
    CHECK(secp256k1_frost_verify_adaptor(CTX, asig_bc, tx_bc, &pk_b, &r, nonce_parity_bc) == 1);
    secp256k1_scalar_set_b32(&deckey, pop, NULL);
    secp256k1_scalar_add(&deckey, &deckey, &tp);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(CTX, sig_bc, asig_bc, buf, nonce_parity_bc));
    CHECK(secp256k1_schnorrsig_verify(CTX, sig_bc, tx_bc, sizeof(tx_bc), &pk_b) == 1);

    /* Bob recover and decrypt */
    CHECK(secp256k1_frost_extract_adaptor(CTX, buf, sig_bc, asig_bc, nonce_parity_bc));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&deckey, &deckey, &t2);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_frost_adapt(CTX, sig_ab, asig_ab, buf, nonce_parity_ab));
    CHECK(secp256k1_schnorrsig_verify(CTX, sig_ab, tx_ab, sizeof(tx_ab), &pk_a) == 1);

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
