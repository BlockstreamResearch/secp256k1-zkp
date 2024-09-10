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

#endif
