/**********************************************************************
 * Copyright (c) 2014-2016 Pieter Wuille, Andrew Poelstra             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_WHITELIST_TESTS_H
#define SECP256K1_MODULE_WHITELIST_TESTS_H

#include "../../../include/secp256k1_whitelist.h"
#include "../../unit_test.h"

static void test_whitelist_end_to_end_internal(const unsigned char *summed_seckey, const unsigned char *online_seckey, const secp256k1_pubkey *online_pubkeys, const secp256k1_pubkey *offline_pubkeys, const secp256k1_pubkey *sub_pubkey, const size_t signer_i, const size_t n_keys) {
        unsigned char serialized[32 + 4 + 32 * SECP256K1_WHITELIST_MAX_N_KEYS] = {0};
        size_t slen = sizeof(serialized);
        secp256k1_whitelist_signature sig;
        secp256k1_whitelist_signature sig1;

        CHECK(secp256k1_whitelist_sign(CTX, &sig, online_pubkeys, offline_pubkeys, n_keys, sub_pubkey, online_seckey, summed_seckey, signer_i));
        CHECK(secp256k1_whitelist_verify(CTX, &sig, online_pubkeys, offline_pubkeys, n_keys, sub_pubkey) == 1);
        /* Check that exchanging keys causes a failure */
        CHECK(secp256k1_whitelist_verify(CTX, &sig, offline_pubkeys, online_pubkeys, n_keys, sub_pubkey) != 1);
        /* Serialization round trip */
        CHECK(secp256k1_whitelist_signature_serialize(CTX, serialized, &slen, &sig) == 1);
        CHECK(slen == 33 + 32 * n_keys);
        /* (Check various bad-length conditions) */
        CHECK(secp256k1_whitelist_signature_parse(CTX, &sig1, serialized, slen + 32) == 0);
        CHECK(secp256k1_whitelist_signature_parse(CTX, &sig1, serialized, slen + 1) == 0);
        CHECK(secp256k1_whitelist_signature_parse(CTX, &sig1, serialized, slen - 1) == 0);
        CHECK(secp256k1_whitelist_signature_parse(CTX, &sig1, serialized, 0) == 0);
        /* A failed parse must leave a signature that fails validation for any
         * key set, as documented on secp256k1_whitelist_signature_parse. */
        CHECK(secp256k1_whitelist_signature_n_keys(&sig1) > SECP256K1_WHITELIST_MAX_N_KEYS);
        CHECK(secp256k1_whitelist_verify(CTX, &sig1, online_pubkeys, offline_pubkeys, n_keys, sub_pubkey) == 0);
        /* Re-parse to restore a valid state. */
        CHECK(secp256k1_whitelist_signature_parse(CTX, &sig1, serialized, slen) == 1);
        CHECK(secp256k1_whitelist_verify(CTX, &sig1, online_pubkeys, offline_pubkeys, n_keys, sub_pubkey) == 1);
        CHECK(secp256k1_whitelist_verify(CTX, &sig1, offline_pubkeys, online_pubkeys, n_keys, sub_pubkey) != 1);

        /* Test n_keys */
        CHECK(secp256k1_whitelist_signature_n_keys(&sig) == n_keys);
        CHECK(secp256k1_whitelist_signature_n_keys(&sig1) == n_keys);

        /* Test bad number of keys in signature */
        sig.n_keys = n_keys + 1;
        CHECK(secp256k1_whitelist_verify(CTX, &sig, offline_pubkeys, online_pubkeys, n_keys, sub_pubkey) != 1);
        sig.n_keys = n_keys;
}

static void test_whitelist_end_to_end(const size_t n_keys, int test_all_keys) {
    unsigned char **online_seckey = malloc(n_keys * sizeof(*online_seckey));
    unsigned char **summed_seckey = malloc(n_keys * sizeof(*summed_seckey));
    secp256k1_pubkey *online_pubkeys = malloc(n_keys * sizeof(*online_pubkeys));
    secp256k1_pubkey *offline_pubkeys = malloc(n_keys * sizeof(*offline_pubkeys));

    secp256k1_scalar ssub;
    unsigned char csub[32];
    secp256k1_pubkey sub_pubkey;

    /* Generate random keys */
    size_t i;
    /* Start with subkey */
    testutil_random_scalar_order_test(&ssub);
    secp256k1_scalar_get_b32(csub, &ssub);
    CHECK(secp256k1_ec_seckey_verify(CTX, csub) == 1);
    CHECK(secp256k1_ec_pubkey_create(CTX, &sub_pubkey, csub) == 1);
    /* Then offline and online whitelist keys */
    for (i = 0; i < n_keys; i++) {
        secp256k1_scalar son, soff;

        online_seckey[i] = malloc(32);
        summed_seckey[i] = malloc(32);

        /* Create two keys */
        testutil_random_scalar_order_test(&son);
        secp256k1_scalar_get_b32(online_seckey[i], &son);
        CHECK(secp256k1_ec_seckey_verify(CTX, online_seckey[i]) == 1);
        CHECK(secp256k1_ec_pubkey_create(CTX, &online_pubkeys[i], online_seckey[i]) == 1);

        testutil_random_scalar_order_test(&soff);
        secp256k1_scalar_get_b32(summed_seckey[i], &soff);
        CHECK(secp256k1_ec_seckey_verify(CTX, summed_seckey[i]) == 1);
        CHECK(secp256k1_ec_pubkey_create(CTX, &offline_pubkeys[i], summed_seckey[i]) == 1);

        /* Make summed_seckey correspond to the sum of offline_pubkey and sub_pubkey */
        secp256k1_scalar_add(&soff, &soff, &ssub);
        secp256k1_scalar_get_b32(summed_seckey[i], &soff);
        CHECK(secp256k1_ec_seckey_verify(CTX, summed_seckey[i]) == 1);
    }

    /* Sign/verify with each one */
    if (test_all_keys) {
        for (i = 0; i < n_keys; i++) {
            test_whitelist_end_to_end_internal(summed_seckey[i], online_seckey[i], online_pubkeys, offline_pubkeys, &sub_pubkey, i, n_keys);
        }
    } else {
        uint32_t rand_idx = testrand_int(n_keys-1);
        test_whitelist_end_to_end_internal(summed_seckey[0], online_seckey[0], online_pubkeys, offline_pubkeys, &sub_pubkey, 0, n_keys);
        test_whitelist_end_to_end_internal(summed_seckey[rand_idx], online_seckey[rand_idx], online_pubkeys, offline_pubkeys, &sub_pubkey, rand_idx, n_keys);
        test_whitelist_end_to_end_internal(summed_seckey[n_keys-1], online_seckey[n_keys-1], online_pubkeys, offline_pubkeys, &sub_pubkey, n_keys-1, n_keys);
    }

    for (i = 0; i < n_keys; i++) {
        free(online_seckey[i]);
        free(summed_seckey[i]);
    }
    free(online_seckey);
    free(summed_seckey);
    free(online_pubkeys);
    free(offline_pubkeys);
}

static void test_whitelist_bad_parse(void) {
    secp256k1_whitelist_signature sig;

    const unsigned char serialized0[] = { 1+32*(0+1) };
    const unsigned char serialized1[] = {
        0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
    };
    const unsigned char serialized2[] = {
        0x01,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    /* Empty input */
    CHECK(secp256k1_whitelist_signature_parse(CTX, &sig, serialized0, 0) == 0);
    /* Misses one byte of e0 */
    CHECK(secp256k1_whitelist_signature_parse(CTX, &sig, serialized1, sizeof(serialized1)) == 0);
    /* Enough bytes for e0, but there is no s value */
    CHECK(secp256k1_whitelist_signature_parse(CTX, &sig, serialized2, sizeof(serialized2)) == 0);
}

static void test_whitelist_bad_serialize(void) {
    unsigned char serialized[] = {
        0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    size_t serialized_len;
    secp256k1_whitelist_signature sig;

    CHECK(secp256k1_whitelist_signature_parse(CTX, &sig, serialized, sizeof(serialized)) == 1);
    serialized_len = sizeof(serialized) - 1;
    /* Output buffer is one byte too short */
    CHECK(secp256k1_whitelist_signature_serialize(CTX, serialized, &serialized_len, &sig) == 0);
}

static void test_whitelist_end_to_end_all_internal(void) {
    test_whitelist_end_to_end(1, 1);
    test_whitelist_end_to_end(10, 1);
    test_whitelist_end_to_end(50, 1);
    test_whitelist_end_to_end(SECP256K1_WHITELIST_MAX_N_KEYS, 0);
}

/* Faithful counting probe: unlike DEFINE_SHA256_TRANSFORM_PROBE it does not
 * perturb the output, so a fully ctx-aware signing operation stays bit-identical
 * while the caller's ctx observes every compression it performs. */
static size_t sha256_whitelist_blocks = 0;
static void sha256_whitelist(uint32_t *s, const unsigned char *msg, size_t rounds) {
    sha256_whitelist_blocks += rounds;
    secp256k1_sha256_transform(s, msg, rounds);
}

static void test_whitelist_ctx_sha256(void) {
    /* Whitelist cannot use the plain perturbing-probe pattern used by the other
     * modules. The nonce inputs (msg32 from compute_keys_and_message, seckey32
     * from compute_tweaked_privkey) are produced through hash_ctx already, so a
     * perturbed compression changes the signature whether or not nonce generation
     * itself routes through the caller's ctx. An "output differs" check therefore
     * passes even when the nonce hashing bypasses the caller's ctx (hashing through
     * the static context instead). What actually distinguishes the two cases is how
     * many compressions the caller's ctx observes: the n_keys+1 RFC6979 nonce
     * instantiations are the bulk of them. So use a faithful probe and assert
     * the signature is bit-identical and the ctx observes the exact number
     * of compressions a fully ctx-aware sign performs. */
    const size_t n_keys = 3;
    const size_t signer_i = 0;
    secp256k1_context *ctx = secp256k1_context_clone(CTX);
    unsigned char online_seckey[3][32];
    unsigned char offline_seckey[3][32];
    unsigned char summed_seckey[3][32];
    unsigned char sub_seckey[32];
    secp256k1_pubkey online_pubkeys[3];
    secp256k1_pubkey offline_pubkeys[3];
    secp256k1_pubkey sub_pubkey;
    secp256k1_whitelist_signature sig_default, sig_custom;
    size_t i;

    memset(sub_seckey, 0, sizeof(sub_seckey));
    sub_seckey[31] = 200;
    CHECK(secp256k1_ec_pubkey_create(CTX, &sub_pubkey, sub_seckey) == 1);
    for (i = 0; i < n_keys; i++) {
        memset(online_seckey[i], 0, 32);
        memset(offline_seckey[i], 0, 32);
        online_seckey[i][31] = (unsigned char)(1 + i);
        offline_seckey[i][31] = (unsigned char)(100 + i);
        CHECK(secp256k1_ec_pubkey_create(CTX, &online_pubkeys[i], online_seckey[i]) == 1);
        CHECK(secp256k1_ec_pubkey_create(CTX, &offline_pubkeys[i], offline_seckey[i]) == 1);
        /* summed_seckey corresponds to offline_pubkey + sub_pubkey */
        memcpy(summed_seckey[i], offline_seckey[i], 32);
        CHECK(secp256k1_ec_seckey_tweak_add(CTX, summed_seckey[i], sub_seckey) == 1);
    }

    sha256_whitelist_blocks = 0;

    /* Default signing: no ctx-provided SHA256 compression. */
    CHECK(secp256k1_whitelist_sign(ctx, &sig_default, online_pubkeys, offline_pubkeys, n_keys, &sub_pubkey, online_seckey[signer_i], summed_seckey[signer_i], signer_i) == 1);
    CHECK(sha256_whitelist_blocks == 0);

    /* Install the faithful probe and re-sign with identical inputs. */
    ctx->hash_ctx.fn_sha256_compression = sha256_whitelist;
    sha256_whitelist_blocks = 0;
    CHECK(secp256k1_whitelist_sign(ctx, &sig_custom, online_pubkeys, offline_pubkeys, n_keys, &sub_pubkey, online_seckey[signer_i], summed_seckey[signer_i], signer_i) == 1);

    /* A faithful override must leave the signature bit-identical. */
    CHECK(secp256k1_memcmp_var(sig_default.data, sig_custom.data, 32 * (n_keys + 1)) == 0);
    /* The caller's ctx must observe every compression the sign performs. For these
     * constant inputs a healthy sign runs exactly 104 compressions through the ctx; if
     * the n_keys+1 RFC6979 nonce instantiations instead hash through the static
     * context, the count drops to 16. Pinning the exact count catches the nonce
     * path, or any other hashing path (keys/message, tweaked privkey, borromean),
     * bypassing the caller's ctx, since any of them changes the total. Update this
     * number if whitelist's hashing legitimately changes (constant inputs give a
     * deterministic count). */
    CHECK(sha256_whitelist_blocks == 104);

    secp256k1_context_destroy(ctx);
}

/* --- Test registry --- */
REPEAT_TEST(test_whitelist_end_to_end_all)

static const struct tf_test_entry tests_whitelist[] = {
    CASE1(test_whitelist_bad_parse),
    CASE1(test_whitelist_bad_serialize),
    CASE1(test_whitelist_end_to_end_all),
    CASE1(test_whitelist_ctx_sha256),
};

#endif
