/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_SESSION_IMPL_H
#define SECP256K1_MODULE_FROST_SESSION_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "keygen.h"
#include "session.h"
#include "../../eckey.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

static const unsigned char secp256k1_frost_secnonce_magic[4] = { 0x84, 0x7d, 0x46, 0x25 };

static void secp256k1_frost_secnonce_save(secp256k1_frost_secnonce *secnonce, secp256k1_scalar *k) {
    memcpy(&secnonce->data[0], secp256k1_frost_secnonce_magic, 4);
    secp256k1_scalar_get_b32(&secnonce->data[4], &k[0]);
    secp256k1_scalar_get_b32(&secnonce->data[36], &k[1]);
}

static int secp256k1_frost_secnonce_load(const secp256k1_context* ctx, secp256k1_scalar *k, secp256k1_frost_secnonce *secnonce) {
    int is_zero;
    ARG_CHECK(secp256k1_memcmp_var(&secnonce->data[0], secp256k1_frost_secnonce_magic, 4) == 0);
    secp256k1_scalar_set_b32(&k[0], &secnonce->data[4], NULL);
    secp256k1_scalar_set_b32(&k[1], &secnonce->data[36], NULL);
    /* We make very sure that the nonce isn't invalidated by checking the values
     * in addition to the magic. */
    is_zero = secp256k1_scalar_is_zero(&k[0]) & secp256k1_scalar_is_zero(&k[1]);
    secp256k1_declassify(ctx, &is_zero, sizeof(is_zero));
    ARG_CHECK(!is_zero);
    return 1;
}

/* If flag is true, invalidate the secnonce; otherwise leave it. Constant-time. */
static void secp256k1_frost_secnonce_invalidate(const secp256k1_context* ctx, secp256k1_frost_secnonce *secnonce, int flag) {
    secp256k1_memczero(secnonce->data, sizeof(secnonce->data), flag);
    /* The flag argument is usually classified. So, above code makes the magic
     * classified. However, we need the magic to be declassified to be able to
     * compare it during secnonce_load. */
    secp256k1_declassify(ctx, secnonce->data, sizeof(secp256k1_frost_secnonce_magic));
}

static const unsigned char secp256k1_frost_pubnonce_magic[4] = { 0x8b, 0xcf, 0xe2, 0xc2 };

/* Requires that none of the provided group elements is infinity. Works for both
 * frost_pubnonce and frost_aggnonce. */
static void secp256k1_frost_pubnonce_save(secp256k1_frost_pubnonce* nonce, secp256k1_ge* ge) {
    int i;
    memcpy(&nonce->data[0], secp256k1_frost_pubnonce_magic, 4);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_to_bytes(nonce->data + 4+64*i, &ge[i]);
    }
}

/* Works for both frost_pubnonce and frost_aggnonce. Returns 1 unless the nonce
 * wasn't properly initialized */
static int secp256k1_frost_pubnonce_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_frost_pubnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_frost_pubnonce_magic, 4) == 0);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_from_bytes(&ge[i], nonce->data + 4+64*i);
    }
    return 1;
}

static const unsigned char secp256k1_frost_session_cache_magic[4] = { 0x5c, 0x11, 0xa8, 0x3 };

/* A session consists of
 * - 4 byte session cache magic
 * - 1 byte the parity of the final nonce
 * - 32 byte serialized x-only final nonce
 * - 32 byte nonce coefficient b
 * - 32 byte signature challenge hash e
 * - 32 byte scalar s that is added to the partial signatures of the signers
 */
static void secp256k1_frost_session_save(secp256k1_frost_session *session, const secp256k1_frost_session_internal *session_i) {
    unsigned char *ptr = session->data;

    memcpy(ptr, secp256k1_frost_session_cache_magic, 4);
    ptr += 4;
    *ptr = session_i->fin_nonce_parity;
    ptr += 1;
    memcpy(ptr, session_i->fin_nonce, 32);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->noncecoef);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->challenge);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->s_part);
}

static int secp256k1_frost_session_load(const secp256k1_context* ctx, secp256k1_frost_session_internal *session_i, const secp256k1_frost_session *session) {
    const unsigned char *ptr = session->data;

    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_frost_session_cache_magic, 4) == 0);
    ptr += 4;
    session_i->fin_nonce_parity = *ptr;
    ptr += 1;
    memcpy(session_i->fin_nonce, ptr, 32);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->noncecoef, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->challenge, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->s_part, ptr, NULL);
    return 1;
}

static const unsigned char secp256k1_frost_partial_sig_magic[4] = { 0x8d, 0xd8, 0x31, 0x6e };

static void secp256k1_frost_partial_sig_save(secp256k1_frost_partial_sig* sig, secp256k1_scalar *s) {
    memcpy(&sig->data[0], secp256k1_frost_partial_sig_magic, 4);
    secp256k1_scalar_get_b32(&sig->data[4], s);
}

static int secp256k1_frost_partial_sig_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_frost_partial_sig* sig) {
    int overflow;

    ARG_CHECK(secp256k1_memcmp_var(&sig->data[0], secp256k1_frost_partial_sig_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &sig->data[4], &overflow);
    /* Parsed signatures can not overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

int secp256k1_frost_pubnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_frost_pubnonce* nonce) {
    secp256k1_ge ge[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    memset(out66, 0, 66);
    ARG_CHECK(nonce != NULL);

    if (!secp256k1_frost_pubnonce_load(ctx, ge, nonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        int ret;
        size_t size = 33;
        ret = secp256k1_eckey_pubkey_serialize(&ge[i], &out66[33*i], &size, 1);
#ifdef VERIFY
         /* serialize must succeed because the point was just loaded */
         VERIFY_CHECK(ret && size == 33);
#else
        (void) ret;
#endif
    }
    return 1;
}

int secp256k1_frost_pubnonce_parse(const secp256k1_context* ctx, secp256k1_frost_pubnonce* nonce, const unsigned char *in66) {
    secp256k1_ge ge[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(in66 != NULL);
    for (i = 0; i < 2; i++) {
        if (!secp256k1_eckey_pubkey_parse(&ge[i], &in66[33*i], 33)) {
            return 0;
        }
        if (!secp256k1_ge_is_in_correct_subgroup(&ge[i])) {
            return 0;
        }
    }
    /* The group elements can not be infinity because they were just parsed */
    secp256k1_frost_pubnonce_save(nonce, ge);
    return 1;
}

int secp256k1_frost_partial_sig_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_frost_partial_sig* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out32, &sig->data[4], 32);
    return 1;
}

int secp256k1_frost_partial_sig_parse(const secp256k1_context* ctx, secp256k1_frost_partial_sig* sig, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_frost_partial_sig_save(sig, &tmp);
    return 1;
}

/* Write optional inputs into the hash */
static void secp256k1_nonce_function_frost_helper(secp256k1_sha256 *sha, unsigned int prefix_size, const unsigned char *data32) {
    /* The spec requires length prefix to be 4 bytes for `extra_in`, 1 byte
     * otherwise */
    VERIFY_CHECK(prefix_size == 4 || prefix_size == 1);
    if (prefix_size == 4) {
        /* Four byte big-endian value, pad first three bytes with 0 */
        unsigned char zero[3] = {0};
        secp256k1_sha256_write(sha, zero, 3);
    }
    if (data32 != NULL) {
        unsigned char len = 32;
        secp256k1_sha256_write(sha, &len, 1);
        secp256k1_sha256_write(sha, data32, 32);
    } else {
        unsigned char len = 0;
        secp256k1_sha256_write(sha, &len, 1);
    }
}

static void secp256k1_nonce_function_frost(secp256k1_scalar *k, const unsigned char *session_id, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk32, const unsigned char *extra_input32) {
    secp256k1_sha256 sha;
    unsigned char rand[32];
    unsigned char i;

    if (key32 != NULL) {
        secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/aux", sizeof("FROST/aux") - 1);
        secp256k1_sha256_write(&sha, session_id, 32);
        secp256k1_sha256_finalize(&sha, rand);
        for (i = 0; i < 32; i++) {
            rand[i] ^= key32[i];
        }
    } else {
        memcpy(rand, session_id, sizeof(rand));
    }

    /* Subtract one from `sizeof` to avoid hashing the implicit null byte */
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/nonce", sizeof("FROST/nonce") - 1);
    secp256k1_sha256_write(&sha, rand, sizeof(rand));
    secp256k1_nonce_function_frost_helper(&sha, 1, pk32);
    secp256k1_nonce_function_frost_helper(&sha, 1, msg32);
    secp256k1_nonce_function_frost_helper(&sha, 4, extra_input32);

    for (i = 0; i < 2; i++) {
        unsigned char buf[32];
        secp256k1_sha256 sha_tmp = sha;
        secp256k1_sha256_write(&sha_tmp, &i, 1);
        secp256k1_sha256_finalize(&sha_tmp, buf);
        secp256k1_scalar_set_b32(&k[i], buf, NULL);
    }
}

int secp256k1_frost_nonce_gen(const secp256k1_context* ctx, secp256k1_frost_secnonce *secnonce, secp256k1_frost_pubnonce *pubnonce, const unsigned char *session_id32, const secp256k1_frost_share *share, const unsigned char *msg32, const secp256k1_frost_keygen_cache *keygen_cache, const unsigned char *extra_input32) {
    secp256k1_keygen_cache_internal cache_i;
    secp256k1_scalar k[2];
    secp256k1_ge nonce_pt[2];
    int i;
    unsigned char pk_ser[32];
    unsigned char *pk_ser_ptr = NULL;
    unsigned char sk_ser[32];
    unsigned char *sk_ser_ptr = NULL;
    int sk_serialize_success;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    memset(secnonce, 0, sizeof(*secnonce));
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    if (share == NULL) {
        /* Check in constant time that the session_id is not 0 as a
         * defense-in-depth measure that may protect against a faulty RNG. */
        unsigned char acc = 0;
        for (i = 0; i < 32; i++) {
            acc |= session_id32[i];
        }
        ret &= !!acc;
        memset(&acc, 0, sizeof(acc));
    }

    /* Check that the share is valid to be able to sign for it later. */
    if (share != NULL) {
        secp256k1_scalar sk;

        ret &= secp256k1_frost_share_load(ctx, &sk, share);
        secp256k1_scalar_clear(&sk);

        sk_serialize_success = secp256k1_frost_share_serialize(ctx, sk_ser, share);
        sk_ser_ptr = sk_ser;
#ifdef VERIFY
    VERIFY_CHECK(sk_serialize_success);
#else
    (void) sk_serialize_success;
#endif
    }

    if (keygen_cache != NULL) {
        if (!secp256k1_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
            return 0;
        }
        /* The loaded point cache_i.pk can not be the point at infinity. */
        secp256k1_fe_get_b32(pk_ser, &cache_i.pk.x);
        pk_ser_ptr = pk_ser;
    }

    secp256k1_nonce_function_frost(k, session_id32, msg32, sk_ser_ptr, pk_ser_ptr, extra_input32);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[0]));
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[1]));
    VERIFY_CHECK(!secp256k1_scalar_eq(&k[0], &k[1]));
    secp256k1_frost_secnonce_save(secnonce, k);
    secp256k1_frost_secnonce_invalidate(ctx, secnonce, !ret);

    for (i = 0; i < 2; i++) {
        secp256k1_gej nonce_ptj;
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &nonce_ptj, &k[i]);
        secp256k1_ge_set_gej(&nonce_pt[i], &nonce_ptj);
        secp256k1_declassify(ctx, &nonce_pt[i], sizeof(nonce_pt));
        secp256k1_scalar_clear(&k[i]);
    }
    /* nonce_pt won't be infinity because k != 0 with overwhelming probability */
    secp256k1_frost_pubnonce_save(pubnonce, nonce_pt);
    return ret;
}

static int secp256k1_frost_sum_nonces(const secp256k1_context* ctx, secp256k1_gej *summed_nonces, const secp256k1_frost_pubnonce * const *pubnonces, size_t n_pubnonces) {
    size_t i;
    int j;

    secp256k1_gej_set_infinity(&summed_nonces[0]);
    secp256k1_gej_set_infinity(&summed_nonces[1]);

    for (i = 0; i < n_pubnonces; i++) {
        secp256k1_ge nonce_pt[2];
        if (!secp256k1_frost_pubnonce_load(ctx, nonce_pt, pubnonces[i])) {
            return 0;
        }
        for (j = 0; j < 2; j++) {
            secp256k1_gej_add_ge_var(&summed_nonces[j], &summed_nonces[j], &nonce_pt[j], NULL);
        }
    }
    return 1;
}

/* TODO: consider updating to frost-08 to address maleability at the cost of performance */
/* See https://github.com/cfrg/draft-irtf-cfrg-frost/pull/217 */
static int secp256k1_frost_compute_noncehash(const secp256k1_context* ctx, unsigned char *noncehash, const unsigned char *msg, const secp256k1_frost_pubnonce * const *pubnonces, size_t n_pubnonces, const unsigned char *pk32, const unsigned char * const *ids33) {
    unsigned char buf[66];
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/noncecoef", sizeof("FROST/noncecoef") - 1);
    /* TODO: sort by index */
    for (i = 0; i < n_pubnonces; i++) {
        secp256k1_scalar idx;

        if (!secp256k1_frost_compute_indexhash(&idx, ids33[i])) {
            return 0;
        }
        secp256k1_scalar_get_b32(buf, &idx);
        secp256k1_sha256_write(&sha, buf, 32);
        if (!secp256k1_frost_pubnonce_serialize(ctx, buf, pubnonces[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, buf, sizeof(buf));
    }
    secp256k1_sha256_write(&sha, pk32, 32);
    secp256k1_sha256_write(&sha, msg, 32);
    secp256k1_sha256_finalize(&sha, noncehash);
    return 1;
}

static int secp256k1_frost_nonce_process_internal(const secp256k1_context* ctx, int *fin_nonce_parity, unsigned char *fin_nonce, secp256k1_scalar *b, secp256k1_gej *aggnoncej, const unsigned char *msg, const secp256k1_frost_pubnonce * const *pubnonces, size_t n_pubnonces, const unsigned char *pk32, const unsigned char * const *ids33) {
    unsigned char noncehash[32];
    secp256k1_ge fin_nonce_pt;
    secp256k1_gej fin_nonce_ptj;
    secp256k1_ge aggnonce[2];

    secp256k1_ge_set_gej(&aggnonce[0], &aggnoncej[0]);
    secp256k1_ge_set_gej(&aggnonce[1], &aggnoncej[1]);
    if (!secp256k1_frost_compute_noncehash(ctx, noncehash, msg, pubnonces, n_pubnonces, pk32, ids33)) {
        return 0;
    }
    /* fin_nonce = aggnonce[0] + b*aggnonce[1] */
    secp256k1_scalar_set_b32(b, noncehash, NULL);
    secp256k1_gej_set_infinity(&fin_nonce_ptj);
    secp256k1_ecmult(&fin_nonce_ptj, &aggnoncej[1], b, NULL);
    secp256k1_gej_add_ge_var(&fin_nonce_ptj, &fin_nonce_ptj, &aggnonce[0], NULL);
    secp256k1_ge_set_gej(&fin_nonce_pt, &fin_nonce_ptj);
    if (secp256k1_ge_is_infinity(&fin_nonce_pt)) {
        fin_nonce_pt = secp256k1_ge_const_g;
    }
    /* fin_nonce_pt is not the point at infinity */
    secp256k1_fe_normalize_var(&fin_nonce_pt.x);
    secp256k1_fe_get_b32(fin_nonce, &fin_nonce_pt.x);
    secp256k1_fe_normalize_var(&fin_nonce_pt.y);
    *fin_nonce_parity = secp256k1_fe_is_odd(&fin_nonce_pt.y);
    return 1;
}

int secp256k1_frost_nonce_process(const secp256k1_context* ctx, secp256k1_frost_session *session, const secp256k1_frost_pubnonce * const* pubnonces, size_t n_pubnonces, const unsigned char *msg32, const unsigned char *my_id33, const unsigned char * const *ids33, const secp256k1_frost_keygen_cache *keygen_cache, const secp256k1_pubkey *adaptor) {
    secp256k1_keygen_cache_internal cache_i;
    secp256k1_gej aggnonce_ptj[2];
    unsigned char fin_nonce[32];
    secp256k1_frost_session_internal session_i = { 0 };
    unsigned char pk32[32];
    secp256k1_scalar l;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(ids33 != NULL);
    ARG_CHECK(my_id33 != NULL);
    ARG_CHECK(keygen_cache != NULL);
    ARG_CHECK(n_pubnonces > 1);

    if (!secp256k1_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
        return 0;
    }
    secp256k1_fe_get_b32(pk32, &cache_i.pk.x);

    if (!secp256k1_frost_sum_nonces(ctx, aggnonce_ptj, pubnonces, n_pubnonces)) {
        return 0;
    }
    /* Add public adaptor to nonce */
    if (adaptor != NULL) {
        secp256k1_ge adaptorp;
        if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&aggnonce_ptj[0], &aggnonce_ptj[0], &adaptorp, NULL);
    }
    if (!secp256k1_frost_nonce_process_internal(ctx, &session_i.fin_nonce_parity, fin_nonce, &session_i.noncecoef, aggnonce_ptj, msg32, pubnonces, n_pubnonces, pk32, ids33)) {
        return 0;
    }

    secp256k1_schnorrsig_challenge(&session_i.challenge, fin_nonce, msg32, 32, pk32);

    /* If there is a tweak then set `challenge` times `tweak` to the `s`-part.*/
    secp256k1_scalar_set_int(&session_i.s_part, 0);
    if (!secp256k1_scalar_is_zero(&cache_i.tweak)) {
        secp256k1_scalar e_tmp;
        secp256k1_scalar_mul(&e_tmp, &session_i.challenge, &cache_i.tweak);
        if (secp256k1_fe_is_odd(&cache_i.pk.y)) {
            secp256k1_scalar_negate(&e_tmp, &e_tmp);
        }
        secp256k1_scalar_add(&session_i.s_part, &session_i.s_part, &e_tmp);
    }
    /* Update the challenge by multiplying the Lagrange coefficient to prepare
     * for signing. */
    if (!secp256k1_frost_lagrange_coefficient(&l, ids33, n_pubnonces, my_id33)) {
        return 0;
    }
    secp256k1_scalar_mul(&session_i.challenge, &session_i.challenge, &l);
    memcpy(session_i.fin_nonce, fin_nonce, sizeof(session_i.fin_nonce));
    secp256k1_frost_session_save(session, &session_i);
    return 1;
}

void secp256k1_frost_partial_sign_clear(secp256k1_scalar *sk, secp256k1_scalar *k) {
    secp256k1_scalar_clear(sk);
    secp256k1_scalar_clear(&k[0]);
    secp256k1_scalar_clear(&k[1]);
}

int secp256k1_frost_partial_sign(const secp256k1_context* ctx, secp256k1_frost_partial_sig *partial_sig, secp256k1_frost_secnonce *secnonce, const secp256k1_frost_share *share, const secp256k1_frost_session *session, const secp256k1_frost_keygen_cache *keygen_cache) {
    secp256k1_scalar sk;
    secp256k1_scalar k[2];
    secp256k1_scalar s;
    secp256k1_keygen_cache_internal cache_i;
    secp256k1_frost_session_internal session_i;
    int ret;

    VERIFY_CHECK(ctx != NULL);

    ARG_CHECK(secnonce != NULL);
    /* Fails if the magic doesn't match */
    ret = secp256k1_frost_secnonce_load(ctx, k, secnonce);
    /* Set nonce to zero to avoid nonce reuse. This will cause subsequent calls
     * of this function to fail */
    memset(secnonce, 0, sizeof(*secnonce));
    if (!ret) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }

    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(keygen_cache != NULL);
    ARG_CHECK(session != NULL);

    if (!secp256k1_frost_share_load(ctx, &sk, share)) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }
    if (!secp256k1_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }

    /* Negate sk if secp256k1_fe_is_odd(&cache_i.pk.y)) XOR cache_i.parity_acc.
     * This corresponds to the line "Let d = g⋅gacc⋅d' mod n" in the
     * specification. */
    if ((secp256k1_fe_is_odd(&cache_i.pk.y)
         != cache_i.parity_acc)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }

    if (session_i.fin_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }

    /* Sign */
    secp256k1_scalar_mul(&s, &session_i.challenge, &sk);
    secp256k1_scalar_mul(&k[1], &session_i.noncecoef, &k[1]);
    secp256k1_scalar_add(&k[0], &k[0], &k[1]);
    secp256k1_scalar_add(&s, &s, &k[0]);
    secp256k1_frost_partial_sig_save(partial_sig, &s);
    secp256k1_frost_partial_sign_clear(&sk, k);
    return 1;
}

int secp256k1_frost_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_frost_partial_sig *partial_sig, const secp256k1_frost_pubnonce *pubnonce, const secp256k1_pubkey *pubshare, const secp256k1_frost_session *session, const secp256k1_frost_keygen_cache *keygen_cache) {
    secp256k1_keygen_cache_internal cache_i;
    secp256k1_frost_session_internal session_i;
    secp256k1_scalar e, s;
    secp256k1_gej pkj;
    secp256k1_ge nonce_pt[2];
    secp256k1_gej rj;
    secp256k1_gej tmp;
    secp256k1_ge pkp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubnonce != NULL);
    ARG_CHECK(pubshare != NULL);
    ARG_CHECK(keygen_cache != NULL);
    ARG_CHECK(session != NULL);

    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        return 0;
    }

    /* Compute "effective" nonce rj = aggnonce[0] + b*aggnonce[1] */
    /* TODO: use multiexp to compute -s*G + e*pubshare + aggnonce[0] + b*aggnonce[1] */
    if (!secp256k1_frost_pubnonce_load(ctx, nonce_pt, pubnonce)) {
        return 0;
    }
    secp256k1_gej_set_ge(&rj, &nonce_pt[1]);
    secp256k1_ecmult(&rj, &rj, &session_i.noncecoef, NULL);
    secp256k1_gej_add_ge_var(&rj, &rj, &nonce_pt[0], NULL);

    if (!secp256k1_pubkey_load(ctx, &pkp, pubshare)) {
        return 0;
    }
    if (!secp256k1_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
        return 0;
    }

    secp256k1_scalar_set_int(&e, 1);
    /* Negate e if secp256k1_fe_is_odd(&cache_i.pk.y)) XOR cache_i.parity_acc.
     * This corresponds to the line "Let g' = g⋅gacc mod n" and the multiplication "g'⋅e"
     * in the specification. */
    if (secp256k1_fe_is_odd(&cache_i.pk.y)
            != cache_i.parity_acc) {
        secp256k1_scalar_negate(&e, &e);
    }
    secp256k1_scalar_mul(&e, &e, &session_i.challenge);

    if (!secp256k1_frost_partial_sig_load(ctx, &s, partial_sig)) {
        return 0;
    }

    /* Compute -s*G + e*pkj + rj (e already includes the lagrange coefficient l) */
    secp256k1_scalar_negate(&s, &s);
    secp256k1_gej_set_ge(&pkj, &pkp);
    secp256k1_ecmult(&tmp, &pkj, &e, &s);
    if (session_i.fin_nonce_parity) {
        secp256k1_gej_neg(&rj, &rj);
    }
    secp256k1_gej_add_var(&tmp, &tmp, &rj, NULL);

    return secp256k1_gej_is_infinity(&tmp);
}

int secp256k1_frost_partial_sig_agg(const secp256k1_context* ctx, unsigned char *sig64, const secp256k1_frost_session *session, const secp256k1_frost_partial_sig * const* partial_sigs, size_t n_sigs) {
    size_t i;
    secp256k1_frost_session_internal session_i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(n_sigs > 0);

    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        return 0;
    }
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar term;
        if (!secp256k1_frost_partial_sig_load(ctx, &term, partial_sigs[i])) {
            return 0;
        }
        secp256k1_scalar_add(&session_i.s_part, &session_i.s_part, &term);
    }
    secp256k1_scalar_get_b32(&sig64[32], &session_i.s_part);
    memcpy(&sig64[0], session_i.fin_nonce, 32);
    return 1;
}

#endif
