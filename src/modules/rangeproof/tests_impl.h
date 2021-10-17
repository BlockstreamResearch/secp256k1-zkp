/**********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_TESTS
#define SECP256K1_MODULE_RANGEPROOF_TESTS

#include <string.h>

#include "group.h"
#include "scalar.h"
#include "testrand.h"
#include "util.h"

#include "include/secp256k1_rangeproof.h"

static void test_pedersen_api(const secp256k1_context *none, const secp256k1_context *sign, const secp256k1_context *vrfy, const int32_t *ecount) {
    secp256k1_pedersen_commitment commit;
    const secp256k1_pedersen_commitment *commit_ptr = &commit;
    unsigned char blind[32];
    unsigned char blind_out[32];
    const unsigned char *blind_ptr = blind;
    unsigned char *blind_out_ptr = blind_out;
    uint64_t val = secp256k1_testrand32();

    secp256k1_testrand256(blind);
    CHECK(secp256k1_pedersen_commit(none, &commit, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 1);
    CHECK(secp256k1_pedersen_commit(vrfy, &commit, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 2);
    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, secp256k1_generator_h) != 0);
    CHECK(*ecount == 2);

    CHECK(secp256k1_pedersen_commit(sign, NULL, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 3);
    CHECK(secp256k1_pedersen_commit(sign, &commit, NULL, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 4);
    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, NULL) == 0);
    CHECK(*ecount == 5);

    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 1, 1) != 0);
    CHECK(*ecount == 5);
    CHECK(secp256k1_pedersen_blind_sum(none, NULL, &blind_ptr, 1, 1) == 0);
    CHECK(*ecount == 6);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, NULL, 1, 1) == 0);
    CHECK(*ecount == 7);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 0, 1) == 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 0, 0) != 0);
    CHECK(*ecount == 8);

    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, secp256k1_generator_h) != 0);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, &commit_ptr, 1) != 0);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 0, &commit_ptr, 1) == 0);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, NULL, 0) == 0);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 0, NULL, 0) != 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 1, &commit_ptr, 1) == 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, NULL, 1) == 0);
    CHECK(*ecount == 10);

    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 1, 0) != 0);
    CHECK(*ecount == 10);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 1, 1) == 0);
    CHECK(*ecount == 11);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 0, 0) == 0);
    CHECK(*ecount == 12);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, NULL, &blind_ptr, &blind_out_ptr, 1, 0) == 0);
    CHECK(*ecount == 13);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, NULL, &blind_out_ptr, 1, 0) == 0);
    CHECK(*ecount == 14);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, NULL, 1, 0) == 0);
    CHECK(*ecount == 15);
}

static void test_rangeproof_api(const secp256k1_context *none, const secp256k1_context *sign, const secp256k1_context *vrfy, const secp256k1_context *both, const int32_t *ecount) {
    unsigned char proof[5134];
    unsigned char blind[32];
    secp256k1_pedersen_commitment commit;
    uint64_t vmin = secp256k1_testrand32();
    uint64_t val = vmin + secp256k1_testrand32();
    size_t len = sizeof(proof);
    /* we'll switch to dylan thomas for this one */
    const unsigned char message[68] = "My tears are like the quiet drift / Of petals from some magic rose;";
    size_t mlen = sizeof(message);
    const unsigned char ext_commit[72] = "And all my grief flows from the rift / Of unremembered skies and snows.";
    size_t ext_commit_len = sizeof(ext_commit);

    secp256k1_testrand256(blind);
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, val, secp256k1_generator_h));

    CHECK(secp256k1_rangeproof_sign(none, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 1);
    CHECK(secp256k1_rangeproof_sign(sign, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 1);
    CHECK(secp256k1_rangeproof_sign(vrfy, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 2);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    CHECK(*ecount == 2);

    CHECK(secp256k1_rangeproof_sign(both, NULL, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 3);
    CHECK(secp256k1_rangeproof_sign(both, proof, NULL, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 4);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, NULL, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 5);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, NULL, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 6);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, NULL, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 7);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, vmin - 1, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 7);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, 0, secp256k1_generator_h) != 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, 0, NULL) == 0);
    CHECK(*ecount == 10);

    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    {
        int exp;
        int mantissa;
        uint64_t min_value;
        uint64_t max_value;
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, proof, len) != 0);
        CHECK(exp == 0);
        CHECK(((uint64_t) 1 << mantissa) > val - vmin);
        CHECK(((uint64_t) 1 << (mantissa - 1)) <= val - vmin);
        CHECK(min_value == vmin);
        CHECK(max_value >= val);

        CHECK(secp256k1_rangeproof_info(none, NULL, &mantissa, &min_value, &max_value, proof, len) == 0);
        CHECK(*ecount == 11);
        CHECK(secp256k1_rangeproof_info(none, &exp, NULL, &min_value, &max_value, proof, len) == 0);
        CHECK(*ecount == 12);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, NULL, &max_value, proof, len) == 0);
        CHECK(*ecount == 13);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, NULL, proof, len) == 0);
        CHECK(*ecount == 14);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, NULL, len) == 0);
        CHECK(*ecount == 15);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, proof, 0) == 0);
        CHECK(*ecount == 15);
    }
    {
        uint64_t min_value;
        uint64_t max_value;
        CHECK(secp256k1_rangeproof_verify(none, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 1);
        CHECK(secp256k1_rangeproof_verify(sign, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 1);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 15);

        CHECK(secp256k1_rangeproof_verify(vrfy, NULL, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 16);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, NULL, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 17);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, NULL, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 18);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, NULL, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 19);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, 0, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 19);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 20);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, 0, secp256k1_generator_h) == 0);
        CHECK(*ecount == 20);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, 0, NULL) == 0);
        CHECK(*ecount == 21);
    }
    {
        unsigned char blind_out[32];
        unsigned char message_out[68];
        uint64_t value_out;
        uint64_t min_value;
        uint64_t max_value;
        size_t message_len = sizeof(message_out);

        CHECK(secp256k1_rangeproof_rewind(none, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 22);
        CHECK(secp256k1_rangeproof_rewind(sign, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 1);
        CHECK(secp256k1_rangeproof_rewind(vrfy, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 23);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 23);

        CHECK(min_value == vmin);
        CHECK(max_value >= val);
        CHECK(value_out == val);
        CHECK(message_len == sizeof(message_out));
        CHECK(memcmp(message, message_out, sizeof(message_out)) == 0);

        CHECK(secp256k1_rangeproof_rewind(both, NULL, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 23);  /* blindout may be NULL */
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, NULL, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 23);  /* valueout may be NULL */
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 24);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 24);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, NULL, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 25);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, NULL, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 26);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, NULL, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 27);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, NULL, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 28);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, NULL, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 29);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, 0, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 29);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 30);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, 0, secp256k1_generator_h) == 0);
        CHECK(*ecount == 30);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, 0, NULL) == 0);
        CHECK(*ecount == 31);
    }
}

static void test_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int32_t ecount;
    int i;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    for (i = 0; i < count; i++) {
        ecount = 0;
        test_pedersen_api(none, sign, vrfy, &ecount);
        ecount = 0;
        test_rangeproof_api(none, sign, vrfy, both, &ecount);
    }

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

static void test_pedersen(void) {
    secp256k1_pedersen_commitment commits[19];
    const secp256k1_pedersen_commitment *cptr[19];
    unsigned char blinds[32*19];
    const unsigned char *bptr[19];
    secp256k1_scalar s;
    uint64_t values[19];
    int64_t totalv;
    int i;
    int inputs;
    int outputs;
    int total;
    inputs = (secp256k1_testrand32() & 7) + 1;
    outputs = (secp256k1_testrand32() & 7) + 2;
    total = inputs + outputs;
    for (i = 0; i < 19; i++) {
        cptr[i] = &commits[i];
        bptr[i] = &blinds[i * 32];
    }
    totalv = 0;
    for (i = 0; i < inputs; i++) {
        values[i] = secp256k1_testrandi64(0, INT64_MAX - totalv);
        totalv += values[i];
    }
    for (i = 0; i < outputs - 1; i++) {
        values[i + inputs] = secp256k1_testrandi64(0, totalv);
        totalv -= values[i + inputs];
    }
    values[total - 1] = totalv;

    for (i = 0; i < total - 1; i++) {
        random_scalar_order(&s);
        secp256k1_scalar_get_b32(&blinds[i * 32], &s);
    }
    CHECK(secp256k1_pedersen_blind_sum(ctx, &blinds[(total - 1) * 32], bptr, total - 1, inputs));
    for (i = 0; i < total; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i], &blinds[i * 32], values[i], secp256k1_generator_h));
    }
    CHECK(secp256k1_pedersen_verify_tally(ctx, cptr, inputs, &cptr[inputs], outputs));
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[inputs], outputs, cptr, inputs));
    if (inputs > 0 && values[0] > 0) {
        CHECK(!secp256k1_pedersen_verify_tally(ctx, cptr, inputs - 1, &cptr[inputs], outputs));
    }
    random_scalar_order(&s);
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_get_b32(&blinds[i * 32], &s);
    }
    values[0] = INT64_MAX;
    values[1] = 0;
    values[2] = 1;
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i], &blinds[i * 32], values[i], secp256k1_generator_h));
    }
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[0], 1, &cptr[0], 1));
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[1], 1, &cptr[1], 1));
}

static void test_borromean(void) {
    unsigned char e0[32];
    secp256k1_scalar s[64];
    secp256k1_gej pubs[64];
    secp256k1_scalar k[8];
    secp256k1_scalar sec[8];
    secp256k1_ge ge;
    secp256k1_scalar one;
    unsigned char m[32];
    size_t rsizes[8];
    size_t secidx[8];
    size_t nrings;
    size_t i;
    size_t j;
    int c;
    secp256k1_testrand256_test(m);
    nrings = 1 + (secp256k1_testrand32()&7);
    c = 0;
    secp256k1_scalar_set_int(&one, 1);
    if (secp256k1_testrand32()&1) {
        secp256k1_scalar_negate(&one, &one);
    }
    for (i = 0; i < nrings; i++) {
        rsizes[i] = 1 + (secp256k1_testrand32()&7);
        secidx[i] = secp256k1_testrand32() % rsizes[i];
        random_scalar_order(&sec[i]);
        random_scalar_order(&k[i]);
        if(secp256k1_testrand32()&7) {
            sec[i] = one;
        }
        if(secp256k1_testrand32()&7) {
            k[i] = one;
        }
        for (j = 0; j < rsizes[i]; j++) {
            random_scalar_order(&s[c + j]);
            if(secp256k1_testrand32()&7) {
                s[i] = one;
            }
            if (j == secidx[i]) {
                secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubs[c + j], &sec[i]);
            } else {
                random_group_element_test(&ge);
                random_group_element_jacobian_test(&pubs[c + j],&ge);
            }
        }
        c += rsizes[i];
    }
    CHECK(secp256k1_borromean_sign(&ctx->ecmult_gen_ctx, e0, s, pubs, k, sec, rsizes, secidx, nrings, m, 32));
    CHECK(secp256k1_borromean_verify(NULL, e0, s, pubs, rsizes, nrings, m, 32));
    i = secp256k1_testrand32() % c;
    secp256k1_scalar_negate(&s[i],&s[i]);
    CHECK(!secp256k1_borromean_verify(NULL, e0, s, pubs, rsizes, nrings, m, 32));
    secp256k1_scalar_negate(&s[i],&s[i]);
    secp256k1_scalar_set_int(&one, 1);
    for(j = 0; j < 4; j++) {
        i = secp256k1_testrand32() % c;
        if (secp256k1_testrand32() & 1) {
            secp256k1_gej_double_var(&pubs[i],&pubs[i], NULL);
        } else {
            secp256k1_scalar_add(&s[i],&s[i],&one);
        }
        CHECK(!secp256k1_borromean_verify(NULL, e0, s, pubs, rsizes, nrings, m, 32));
    }
}

static void test_rangeproof(void) {
    const uint64_t testvs[11] = {0, 1, 5, 11, 65535, 65537, INT32_MAX, UINT32_MAX, INT64_MAX - 1, INT64_MAX, UINT64_MAX};
    secp256k1_pedersen_commitment commit;
    secp256k1_pedersen_commitment commit2;
    unsigned char proof[5134 + 1]; /* One additional byte to test if trailing bytes are rejected */
    unsigned char blind[32];
    unsigned char blindout[32];
    unsigned char message[4096];
    size_t mlen;
    uint64_t v;
    uint64_t vout;
    uint64_t vmin;
    uint64_t minv;
    uint64_t maxv;
    size_t len;
    size_t i;
    size_t j;
    size_t k;
    /* Short message is a Simone de Beauvoir quote */
    const unsigned char message_short[120] = "When I see my own likeness in the depths of someone else's consciousness,  I always experience a moment of panic.";
    /* Long message is 0xA5 with a bunch of this quote in the middle */
    unsigned char message_long[3968];
    memset(message_long, 0xa5, sizeof(message_long));
    for (i = 1200; i < 3600; i += 120) {
        memcpy(&message_long[i], message_short, sizeof(message_short));
    }

    secp256k1_testrand256(blind);
    for (i = 0; i < 11; i++) {
        v = testvs[i];
        CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, v, secp256k1_generator_h));
        for (vmin = 0; vmin < (i<9 && i > 0 ? 2 : 1); vmin++) {
            const unsigned char *input_message = NULL;
            size_t input_message_len = 0;
            /* vmin is always either 0 or 1; if it is 1, then we have no room for a message.
             * If it's 0, we use "minimum encoding" and only have room for a small message when
             * `testvs[i]` is >= 4; for a large message when it's >= 2^32. */
            if (vmin == 0 && i > 2) {
                input_message = message_short;
                input_message_len = sizeof(message_short);
            }
            if (vmin == 0 && i > 7) {
                input_message = message_long;
                input_message_len = sizeof(message_long);
            }
            len = 5134;
            CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, vmin, &commit, blind, commit.data, 0, 0, v, input_message, input_message_len, NULL, 0, secp256k1_generator_h));
            CHECK(len <= 5134);
            mlen = 4096;
            CHECK(secp256k1_rangeproof_rewind(ctx, blindout, &vout, message, &mlen, commit.data, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
            if (input_message != NULL) {
                CHECK(memcmp(message, input_message, input_message_len) == 0);
            }
            for (j = input_message_len; j < mlen; j++) {
                CHECK(message[j] == 0);
            }
            CHECK(mlen <= 4096);
            CHECK(memcmp(blindout, blind, 32) == 0);
            CHECK(vout == v);
            CHECK(minv <= v);
            CHECK(maxv >= v);
            len = 5134;
            CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, v, &commit, blind, commit.data, -1, 64, v, NULL, 0, NULL, 0, secp256k1_generator_h));
            CHECK(len <= 73);
            CHECK(secp256k1_rangeproof_rewind(ctx, blindout, &vout, NULL, NULL, commit.data, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
            CHECK(memcmp(blindout, blind, 32) == 0);
            CHECK(vout == v);
            CHECK(minv == v);
            CHECK(maxv == v);

            /* Check with a committed message */
            len = 5134;
            CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, v, &commit, blind, commit.data, -1, 64, v, NULL, 0, message_short, sizeof(message_short), secp256k1_generator_h));
            CHECK(len <= 73);
            CHECK(!secp256k1_rangeproof_rewind(ctx, blindout, &vout, NULL, NULL, commit.data, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
            CHECK(!secp256k1_rangeproof_rewind(ctx, blindout, &vout, NULL, NULL, commit.data, &minv, &maxv, &commit, proof, len, message_long, sizeof(message_long), secp256k1_generator_h));
            CHECK(secp256k1_rangeproof_rewind(ctx, blindout, &vout, NULL, NULL, commit.data, &minv, &maxv, &commit, proof, len, message_short, sizeof(message_short), secp256k1_generator_h));
            CHECK(memcmp(blindout, blind, 32) == 0);
            CHECK(vout == v);
            CHECK(minv == v);
            CHECK(maxv == v);
        }
    }
    secp256k1_testrand256(blind);
    v = INT64_MAX - 1;
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, v, secp256k1_generator_h));
    for (i = 0; i < 19; i++) {
        len = 5134;
        CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, 0, &commit, blind, commit.data, i, 0, v, NULL, 0, NULL, 0, secp256k1_generator_h));
        CHECK(secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
        CHECK(len <= 5134);
        CHECK(minv <= v);
        CHECK(maxv >= v);
        /* Make sure it fails when validating with a committed message */
        CHECK(!secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len, message_short, sizeof(message_short), secp256k1_generator_h));
    }
    secp256k1_testrand256(blind);
    {
        /*Malleability test.*/
        v = secp256k1_testrandi64(0, 255);
        CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, v, secp256k1_generator_h));
        len = 5134;
        CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, 0, &commit, blind, commit.data, 0, 3, v, NULL, 0, NULL, 0, secp256k1_generator_h));
        CHECK(len <= 5134);
        /* Test if trailing bytes are rejected. */
        proof[len] = v;
        CHECK(!secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len + 1, NULL, 0, secp256k1_generator_h));
        for (i = 0; i < len*8; i++) {
            proof[i >> 3] ^= 1 << (i & 7);
            CHECK(!secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
            proof[i >> 3] ^= 1 << (i & 7);
        }
        CHECK(secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
        CHECK(minv <= v);
        CHECK(maxv >= v);
    }
    memcpy(&commit2, &commit, sizeof(commit));
    for (i = 0; i < (size_t) count; i++) {
        int exp;
        int min_bits;
        v = secp256k1_testrandi64(0, UINT64_MAX >> (secp256k1_testrand32()&63));
        vmin = 0;
        if ((v < INT64_MAX) && (secp256k1_testrand32()&1)) {
            vmin = secp256k1_testrandi64(0, v);
        }
        secp256k1_testrand256(blind);
        CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, v, secp256k1_generator_h));
        len = 5134;
        exp = (int)secp256k1_testrandi64(0,18)-(int)secp256k1_testrandi64(0,18);
        if (exp < 0) {
            exp = -exp;
        }
        min_bits = (int)secp256k1_testrandi64(0,64)-(int)secp256k1_testrandi64(0,64);
        if (min_bits < 0) {
            min_bits = -min_bits;
        }
        CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, vmin, &commit, blind, commit.data, exp, min_bits, v, NULL, 0, NULL, 0, secp256k1_generator_h));
        CHECK(len <= 5134);
        mlen = 4096;
        CHECK(secp256k1_rangeproof_rewind(ctx, blindout, &vout, message, &mlen, commit.data, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
        for (j = 0; j < mlen; j++) {
            CHECK(message[j] == 0);
        }
        CHECK(mlen <= 4096);
        CHECK(memcmp(blindout, blind, 32) == 0);

        CHECK(minv <= v);
        CHECK(maxv >= v);
        CHECK(secp256k1_rangeproof_rewind(ctx, blindout, &vout, NULL, NULL, commit.data, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
        memcpy(&commit2, &commit, sizeof(commit));
    }
    for (j = 0; j < 3; j++) {
        for (i = 0; i < 96; i++) {
            secp256k1_testrand256(&proof[i * 32]);
        }
        for (k = 0; k < 128; k += 3) {
            len = k;
            CHECK(!secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit2, proof, len, NULL, 0, secp256k1_generator_h));
        }
        len = secp256k1_testrandi64(0, 3072);
        CHECK(!secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit2, proof, len, NULL, 0, secp256k1_generator_h));
    }
}

static void test_single_value_proof(uint64_t val) {
    unsigned char proof[5000];
    secp256k1_pedersen_commitment commit;
    unsigned char blind[32];
    unsigned char blind_out[32];
    unsigned char nonce[32];
    const unsigned char message[1] = " "; /* no message will fit into a single-value proof */
    unsigned char message_out[sizeof(proof)] = { 0 };
    size_t plen = sizeof(proof);
    uint64_t min_val_out = 0;
    uint64_t max_val_out = 0;
    uint64_t val_out = 0;
    size_t m_len_out = 0;

    secp256k1_testrand256(blind);
    secp256k1_testrand256(nonce);
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, val, secp256k1_generator_h));

    CHECK(secp256k1_rangeproof_sign(
        ctx,
        proof, &plen,
        val, /* min_val */
        &commit, blind, nonce,
        -1, /* exp: -1 is magic value to indicate a single-value proof */
        0, /* min_bits */
        val, /* val */
        message, sizeof(message),  /* Will cause this to fail */
        NULL, 0,
        secp256k1_generator_h
    ) == 0);

    plen = sizeof(proof);
    CHECK(secp256k1_rangeproof_sign(
        ctx,
        proof, &plen,
        val, /* min_val */
        &commit, blind, nonce,
        -1, /* exp: -1 is magic value to indicate a single-value proof */
        0, /* min_bits */
        val, /* val */
        NULL, 0,
        NULL, 0,
        secp256k1_generator_h
    ) == 1);

    /* Different proof sizes are unfortunate but is caused by `min_value` of
     * zero being special-cased and encoded more efficiently. */
    if (val == 0) {
        CHECK(plen == 65);
    } else {
        CHECK(plen == 73);
    }

    CHECK(secp256k1_rangeproof_verify(
        ctx,
        &min_val_out, &max_val_out,
        &commit,
        proof, plen,
        NULL, 0,
        secp256k1_generator_h
    ) == 1);
    CHECK(min_val_out == val);
    CHECK(max_val_out == val);

    memset(message_out, 0, sizeof(message_out));
    m_len_out = sizeof(message_out);
    CHECK(secp256k1_rangeproof_rewind(
        ctx,
        blind_out, &val_out,
        message_out, &m_len_out,
        nonce,
        &min_val_out, &max_val_out,
        &commit,
        proof, plen,
        NULL, 0,
        secp256k1_generator_h
    ));
    CHECK(val_out == val);
    CHECK(min_val_out == val);
    CHECK(max_val_out == val);
    CHECK(m_len_out == 0);
    CHECK(memcmp(blind, blind_out, 32) == 0);
    for (m_len_out = 0; m_len_out < sizeof(message_out); m_len_out++) {
        CHECK(message_out[m_len_out] == 0);
    }
}

#define MAX_N_GENS	30
static void test_multiple_generators(void) {
    const size_t n_inputs = (secp256k1_testrand32() % (MAX_N_GENS / 2)) + 1;
    const size_t n_outputs = (secp256k1_testrand32() % (MAX_N_GENS / 2)) + 1;
    const size_t n_generators = n_inputs + n_outputs;
    unsigned char *generator_blind[MAX_N_GENS];
    unsigned char *pedersen_blind[MAX_N_GENS];
    secp256k1_generator generator[MAX_N_GENS];
    secp256k1_pedersen_commitment commit[MAX_N_GENS];
    const secp256k1_pedersen_commitment *commit_ptr[MAX_N_GENS];
    size_t i;
    int64_t total_value;
    uint64_t value[MAX_N_GENS];

    secp256k1_scalar s;

    unsigned char generator_seed[32];
    random_scalar_order(&s);
    secp256k1_scalar_get_b32(generator_seed, &s);
    /* Create all the needed generators */
    for (i = 0; i < n_generators; i++) {
        generator_blind[i] = (unsigned char*) malloc(32);
        pedersen_blind[i] = (unsigned char*) malloc(32);

        random_scalar_order(&s);
        secp256k1_scalar_get_b32(generator_blind[i], &s);
        random_scalar_order(&s);
        secp256k1_scalar_get_b32(pedersen_blind[i], &s);

        CHECK(secp256k1_generator_generate_blinded(ctx, &generator[i], generator_seed, generator_blind[i]));

        commit_ptr[i] = &commit[i];
    }

    /* Compute all the values -- can be positive or negative */
    total_value = 0;
    for (i = 0; i < n_outputs; i++) {
        value[n_inputs + i] = secp256k1_testrandi64(0, INT64_MAX - total_value);
        total_value += value[n_inputs + i];
    }
    for (i = 0; i < n_inputs - 1; i++) {
        value[i] = secp256k1_testrandi64(0, total_value);
        total_value -= value[i];
    }
    value[i] = total_value;

    /* Correct for blinding factors and do the commitments */
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(ctx, value, (const unsigned char * const *) generator_blind, pedersen_blind, n_generators, n_inputs));
    for (i = 0; i < n_generators; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commit[i], pedersen_blind[i], value[i], &generator[i]));
    }

    /* Verify */
    CHECK(secp256k1_pedersen_verify_tally(ctx, &commit_ptr[0], n_inputs, &commit_ptr[n_inputs], n_outputs));

    /* Cleanup */
    for (i = 0; i < n_generators; i++) {
        free(generator_blind[i]);
        free(pedersen_blind[i]);
    }
}

void test_rangeproof_fixed_vectors(void) {
    size_t i;
    unsigned char blind[32];
    uint64_t value;
    uint64_t min_value;
    uint64_t max_value;
    secp256k1_pedersen_commitment pc;
    unsigned char message[4000] = {0};
    size_t m_len = sizeof(message);

    /* Vector 1: no message */
{
    static const unsigned char vector_1[] = {
        0x62, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x02, 0x2a, 0x5c, 0x42, 0x0e, 0x1d,
        0x51, 0xe1, 0xb7, 0xf3, 0x69, 0x04, 0xb5, 0xbb, 0x9b, 0x41, 0x66, 0x14, 0xf3, 0x64, 0x42, 0x26,
        0xe3, 0xa7, 0x6a, 0x06, 0xbb, 0xa8, 0x5a, 0x49, 0x6f, 0x19, 0x76, 0xfb, 0xe5, 0x75, 0x77, 0x88,
        0xab, 0xa9, 0x66, 0x44, 0x80, 0xea, 0x29, 0x95, 0x7f, 0xdf, 0x72, 0x4a, 0xaf, 0x02, 0xbe, 0xdd,
        0x5d, 0x15, 0xd8, 0xae, 0xff, 0x74, 0xc9, 0x8c, 0x1a, 0x67, 0x0e, 0xb2, 0x57, 0x22, 0x99, 0xc3,
        0x21, 0x46, 0x6f, 0x15, 0x58, 0x0e, 0xdb, 0xe6, 0x6e, 0xc4, 0x0d, 0xfe, 0x6f, 0x04, 0x6b, 0x0d,
        0x18, 0x3d, 0x78, 0x40, 0x98, 0x56, 0x4e, 0xe4, 0x4a, 0x74, 0x90, 0xa7, 0xac, 0x9c, 0x16, 0xe0,
        0x3e, 0x81, 0xaf, 0x0f, 0xe3, 0x4f, 0x34, 0x99, 0x52, 0xf7, 0xa7, 0xf6, 0xd3, 0x83, 0xa0, 0x17,
        0x4b, 0x2d, 0xa7, 0xd4, 0xfd, 0xf7, 0x84, 0x45, 0xc4, 0x11, 0x71, 0x3d, 0x4a, 0x22, 0x34, 0x09,
        0x9c, 0xa7, 0xe5, 0xc8, 0xba, 0x04, 0xbf, 0xfd, 0x25, 0x11, 0x7d, 0xa4, 0x43, 0x45, 0xc7, 0x62,
        0x9e, 0x7b, 0x80, 0xf6, 0x09, 0xbb, 0x1b, 0x2e, 0xf3, 0xcd, 0x23, 0xe0, 0xed, 0x81, 0x43, 0x42,
        0xbe, 0xc4, 0x9f, 0x58, 0x8a, 0x0d, 0x66, 0x79, 0x09, 0x70, 0x11, 0x68, 0x3d, 0x87, 0x38, 0x1c,
        0x3c, 0x85, 0x52, 0x5b, 0x62, 0xf7, 0x3e, 0x7e, 0x87, 0xa2, 0x99, 0x24, 0xd0, 0x7d, 0x18, 0x63,
        0x56, 0x48, 0xa4, 0x3a, 0xfe, 0x65, 0xfa, 0xa4, 0xd0, 0x67, 0xaa, 0x98, 0x65, 0x4d, 0xe4, 0x22,
        0x75, 0x45, 0x52, 0xe8, 0x41, 0xc7, 0xed, 0x38, 0xeb, 0xf5, 0x02, 0x90, 0xc9, 0x45, 0xa3, 0xb0,
        0x4d, 0x03, 0xd7, 0xab, 0x43, 0xe4, 0x21, 0xfc, 0x83, 0xd6, 0x12, 0x1d, 0x76, 0xb1, 0x3c, 0x67,
        0x63, 0x1f, 0x52, 0x9d, 0xc3, 0x23, 0x5c, 0x4e, 0xa6, 0x8d, 0x01, 0x4a, 0xba, 0x9a, 0xf4, 0x16,
        0x5b, 0x67, 0xc8, 0xe1, 0xd2, 0x42, 0x6d, 0xdf, 0xcd, 0x08, 0x6a, 0x73, 0x41, 0x6a, 0xc2, 0x84,
        0xc6, 0x31, 0xbe, 0x57, 0xcb, 0x0e, 0xde, 0xbf, 0x71, 0xd5, 0x8a, 0xf7, 0x24, 0xb2, 0xa7, 0x89,
        0x96, 0x62, 0x4f, 0xd9, 0xf7, 0xc3, 0xde, 0x4c, 0xab, 0x13, 0x72, 0xb4, 0xb3, 0x35, 0x04, 0x82,
        0xa8, 0x75, 0x1d, 0xde, 0x46, 0xa8, 0x0d, 0xb8, 0x23, 0x44, 0x00, 0x44, 0xfa, 0x53, 0x6c, 0x2d,
        0xce, 0xd3, 0xa6, 0x80, 0xa1, 0x20, 0xca, 0xd1, 0x63, 0xbb, 0xbe, 0x39, 0x5f, 0x9d, 0x27, 0x69,
        0xb3, 0x33, 0x1f, 0xdb, 0xda, 0x67, 0x05, 0x37, 0xbe, 0x65, 0xe9, 0x7e, 0xa9, 0xc3, 0xff, 0x37,
        0x8a, 0xb4, 0x2d, 0xfe, 0xf2, 0x16, 0x85, 0xc7, 0x0f, 0xd9, 0xbe, 0x14, 0xd1, 0x80, 0x14, 0x9f,
        0x58, 0x56, 0x98, 0x41, 0xf6, 0x26, 0xf7, 0xa2, 0x71, 0x66, 0xb4, 0x7a, 0x9c, 0x12, 0x73, 0xd3,
        0xdf, 0x77, 0x2b, 0x49, 0xe5, 0xca, 0x50, 0x57, 0x44, 0x6e, 0x3f, 0x58, 0x56, 0xbc, 0x21, 0x70,
        0x4f, 0xc6, 0xaa, 0x12, 0xff, 0x7c, 0xa7, 0x3d, 0xed, 0x46, 0xc1, 0x40, 0xe6, 0x58, 0x09, 0x2a,
        0xda, 0xb3, 0x76, 0xab, 0x44, 0xb5, 0x4e, 0xb3, 0x12, 0xe0, 0x26, 0x8a, 0x52, 0xac, 0x49, 0x1d,
        0xe7, 0x06, 0x53, 0x3a, 0x01, 0x35, 0x21, 0x2e, 0x86, 0x48, 0xc5, 0x75, 0xc1, 0xa2, 0x7d, 0x22,
        0x53, 0xf6, 0x3f, 0x41, 0xc5, 0xb3, 0x08, 0x7d, 0xa3, 0x67, 0xc0, 0xbb, 0xb6, 0x8d, 0xf0, 0xd3,
        0x01, 0x72, 0xd3, 0x63, 0x82, 0x01, 0x1a, 0xe7, 0x1d, 0x22, 0xfa, 0x95, 0x33, 0xf6, 0xf2, 0xde,
        0xa2, 0x53, 0x86, 0x55, 0x5a, 0xb4, 0x2e, 0x75, 0x75, 0xc6, 0xd5, 0x93, 0x9c, 0x57, 0xa9, 0x1f,
        0xb9, 0x3e, 0xe8, 0x1c, 0xbf, 0xac, 0x1c, 0x54, 0x6f, 0xf5, 0xab, 0x41, 0xee, 0xb3, 0x0e, 0xd0,
        0x76, 0xc4, 0x1a, 0x45, 0xcd, 0xf1, 0xd6, 0xcc, 0xb0, 0x83, 0x70, 0x73, 0xbc, 0x88, 0x74, 0xa0,
        0x5b, 0xe7, 0x98, 0x10, 0x36, 0xbf, 0xec, 0x23, 0x1c, 0xc2, 0xb5, 0xba, 0x4b, 0x9d, 0x7f, 0x8c,
        0x8a, 0xe2, 0xda, 0x18, 0xdd, 0xab, 0x27, 0x8a, 0x15, 0xeb, 0xb0, 0xd4, 0x3a, 0x8b, 0x77, 0x00,
        0xc7, 0xbb, 0xcc, 0xfa, 0xba, 0xa4, 0x6a, 0x17, 0x5c, 0xf8, 0x51, 0x5d, 0x8d, 0x16, 0xcd, 0xa7,
        0x0e, 0x71, 0x97, 0x98, 0x78, 0x5a, 0x41, 0xb3, 0xf0, 0x1f, 0x87, 0x2d, 0x65, 0xcd, 0x29, 0x49,
        0xd2, 0x87, 0x2c, 0x91, 0xa9, 0x5f, 0xcc, 0xa9, 0xd8, 0xbb, 0x53, 0x18, 0xe7, 0xd6, 0xec, 0x65,
        0xa6, 0x45, 0xf6, 0xce, 0xcf, 0x48, 0xf6, 0x1e, 0x3d, 0xd2, 0xcf, 0xcb, 0x3a, 0xcd, 0xbb, 0x92,
        0x29, 0x24, 0x16, 0x7f, 0x8a, 0xa8, 0x5c, 0x0c, 0x45, 0x71, 0x33
    };
    static const unsigned char commit_1[] = {
        0x08,
        0xf5, 0x1e, 0x0d, 0xc5, 0x86, 0x78, 0x51, 0xa9, 0x00, 0x00, 0xef, 0x4d, 0xe2, 0x94, 0x60, 0x89,
        0x83, 0x04, 0xb4, 0x0e, 0x90, 0x10, 0x05, 0x1c, 0x7f, 0xd7, 0x33, 0x92, 0x1f, 0xe7, 0x74, 0x59
    };
    static const unsigned char blind_1[] = {
        0x98, 0x44, 0xfc, 0x7a, 0x64, 0xa9, 0xca, 0xdf, 0xf3, 0x2f, 0x9f, 0x02, 0xba, 0x46, 0xc7, 0xd9,
        0x77, 0x47, 0xa4, 0xd3, 0x53, 0x17, 0xc6, 0x44, 0x30, 0x73, 0x84, 0xeb, 0x1f, 0xbe, 0xa1, 0xfb
    };

    CHECK(secp256k1_pedersen_commitment_parse(ctx, &pc, commit_1));
    CHECK(secp256k1_rangeproof_verify(
        ctx,
        &min_value, &max_value,
        &pc,
        vector_1, sizeof(vector_1),
        NULL, 0,
        secp256k1_generator_h
    ));
    CHECK(min_value == 86);
    CHECK(max_value == 25586);

    CHECK(secp256k1_rangeproof_rewind(
        ctx,
        blind, &value,
        message, &m_len,
        pc.data,
        &min_value, &max_value,
        &pc,
        vector_1, sizeof(vector_1),
        NULL, 0,
        secp256k1_generator_h
    ));

    CHECK(memcmp(blind, blind_1, 32) == 0);
    CHECK(value == 86);
    CHECK(min_value == 86);
    CHECK(max_value == 25586);
    CHECK(m_len == 448); /* length of the sidechannel in the proof */
    for (i = 0; i < m_len; i++) {
        /* No message encoded in this vector */
        CHECK(message[i] == 0);
    }
}

    /* Vector 2: embedded message */
{
    static const unsigned char vector_2[] = {
        0x40, 0x03, 0x00, 0x90, 0x1a, 0x61, 0x64, 0xbb, 0x85, 0x1a, 0x78, 0x35, 0x1e, 0xe0, 0xd5, 0x96,
        0x71, 0x0f, 0x18, 0x8e, 0xf3, 0x33, 0xf0, 0x75, 0xfe, 0xd6, 0xc6, 0x11, 0x6b, 0x42, 0x89, 0xea,
        0xa2, 0x0c, 0x89, 0x25, 0x37, 0x81, 0x10, 0xf9, 0xf0, 0x9b, 0xda, 0x68, 0x2a, 0xd9, 0x2e, 0x0c,
        0x45, 0x17, 0x54, 0x6d, 0x02, 0xd2, 0x21, 0x5d, 0xbc, 0x10, 0xf8, 0x8f, 0xf1, 0x92, 0x40, 0xa9,
        0xc7, 0x24, 0x00, 0x1b, 0xc8, 0x75, 0x0f, 0xf6, 0x8f, 0x93, 0x8b, 0x78, 0x62, 0x73, 0x3c, 0x86,
        0x4b, 0x61, 0x7c, 0x0f, 0xc6, 0x41, 0xc9, 0xb3, 0xc1, 0x30, 0x7f, 0xd4, 0xee, 0x9f, 0x37, 0x08,
        0x9b, 0x64, 0x23, 0xd5, 0xe6, 0x1a, 0x03, 0x54, 0x74, 0x9b, 0x0b, 0xae, 0x6f, 0x2b, 0x1e, 0xf5,
        0x40, 0x44, 0xaa, 0x12, 0xe8, 0xbd, 0xe0, 0xa6, 0x85, 0x89, 0xf1, 0xa9, 0xd0, 0x3f, 0x2e, 0xc6,
        0x1f, 0x11, 0xf5, 0x44, 0x69, 0x99, 0x31, 0x10, 0x2e, 0x64, 0xc6, 0x44, 0xdb, 0x47, 0x06, 0x6d,
        0xd5, 0xf2, 0x8d, 0x19, 0x00, 0x39, 0xb8, 0xca, 0xda, 0x5c, 0x1d, 0x83, 0xbd, 0xa3, 0x6d, 0xbf,
        0x97, 0xdd, 0x83, 0x86, 0xc9, 0x56, 0xe2, 0xbb, 0x37, 0x4b, 0x2d, 0xb5, 0x9d, 0xf2, 0x7a, 0x6a,
        0x25, 0x47, 0xfa, 0x03, 0x05, 0xc5, 0xda, 0x73, 0xe1, 0x96, 0x15, 0x21, 0x23, 0xe5, 0xef, 0x55,
        0x36, 0xdd, 0xf1, 0xb1, 0x3f, 0x33, 0x1a, 0x91, 0x6c, 0x73, 0x64, 0xd3, 0x88, 0xe7, 0xc6, 0xc9,
        0x04, 0x29, 0xae, 0x55, 0x27, 0xa0, 0x80, 0x60, 0xaf, 0x0c, 0x09, 0x2f, 0xc8, 0x1b, 0xe6, 0x16,
        0x9e, 0xed, 0x29, 0xc7, 0x93, 0xce, 0xc7, 0x0d, 0xdf, 0x1f, 0x28, 0xba, 0xf3, 0x38, 0xc3, 0xaa,
        0x99, 0xd9, 0x21, 0x41, 0xb8, 0x10, 0xa5, 0x48, 0x37, 0xec, 0x60, 0xda, 0x64, 0x5a, 0x73, 0x55,
        0xd7, 0xff, 0x23, 0xfa, 0xf6, 0xc6, 0xf4, 0xe2, 0xca, 0x99, 0x2f, 0x30, 0x36, 0x48, 0x73, 0x8b,
        0x57, 0xa6, 0x62, 0x12, 0xa3, 0xe7, 0x5c, 0xa8, 0xd1, 0xe6, 0x85, 0x05, 0x59, 0xfe, 0x2b, 0x44,
        0xe4, 0x73, 0x1c, 0xc3, 0x56, 0x32, 0x07, 0x65, 0x4a, 0x58, 0xaf, 0x2b, 0x3f, 0x36, 0xca, 0xb4,
        0x1d, 0x5c, 0x2a, 0x46, 0x1f, 0xf7, 0x63, 0x59, 0x4f, 0x2b, 0xd0, 0xf6, 0xfc, 0xcf, 0x04, 0x09,
        0xb7, 0x65, 0x1b
    };
    static const unsigned char commit_2[] = {
        0x09,
        0x25, 0xa4, 0xbd, 0xc4, 0x57, 0x69, 0xeb, 0x4f, 0x34, 0x0f, 0xea, 0xb8, 0xe4, 0x72, 0x04, 0x54,
        0x06, 0xe5, 0xd6, 0x85, 0x15, 0x42, 0xea, 0x6e, 0x1d, 0x11, 0x11, 0x9c, 0x56, 0xf8, 0x10, 0x45
    };
    static const unsigned char blind_2[] = {
        0xdc, 0x79, 0x07, 0x89, 0x2d, 0xc4, 0xe3, 0x76, 0xf9, 0x13, 0x38, 0xd6, 0x4b, 0x46, 0xed, 0x9d,
        0x9b, 0xf6, 0x70, 0x3d, 0x04, 0xcf, 0x96, 0x8c, 0xfd, 0xb5, 0xff, 0x0a, 0x06, 0xc7, 0x08, 0x8b
    };
    static const unsigned char message_2[] = "When I see my own likeness in the depths of someone else's consciousness,  I always experience a moment of panic.";

    CHECK(secp256k1_pedersen_commitment_parse(ctx, &pc, commit_2));
    CHECK(secp256k1_rangeproof_verify(
        ctx,
        &min_value, &max_value,
        &pc,
        vector_2, sizeof(vector_2),
        NULL, 0,
        secp256k1_generator_h
    ));
    CHECK(min_value == 0);
    CHECK(max_value == 15);

    CHECK(secp256k1_rangeproof_rewind(
        ctx,
        blind, &value,
        message, &m_len,
        pc.data,
        &min_value, &max_value,
        &pc,
        vector_2, sizeof(vector_2),
        NULL, 0,
        secp256k1_generator_h
    ));

    CHECK(memcmp(blind, blind_2, 32) == 0);
    CHECK(value == 11);
    CHECK(min_value == 0);
    CHECK(max_value == 15);
    CHECK(m_len == 192); /* length of the sidechannel in the proof */
    CHECK(memcmp(message, message_2, sizeof(message_2)) == 0);
    for (i = sizeof(message_2); i < m_len; i++) {
        /* No message encoded in this vector */
        CHECK(message[i] == 0);
    }
}

    /* Vector 3: single-value proof of UINT64_MAX */
{
    static const unsigned char vector_3[] = {
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdc, 0x7d, 0x0b, 0x79, 0x0e, 0xaf, 0x41,
        0xa5, 0x8e, 0x9b, 0x0c, 0x5b, 0xa3, 0xee, 0x7d, 0xfd, 0x3d, 0x6b, 0xf3, 0xac, 0x04, 0x8a, 0x43,
        0x75, 0xb0, 0xb7, 0x0e, 0x92, 0xd7, 0xdf, 0xf0, 0x76, 0xc4, 0xa5, 0xb6, 0x2f, 0xf1, 0xb5, 0xfb,
        0xb4, 0xb6, 0x29, 0xea, 0x34, 0x9b, 0x16, 0x30, 0x0d, 0x06, 0xf1, 0xb4, 0x3f, 0x0d, 0x73, 0x59,
        0x75, 0xbf, 0x5d, 0x19, 0x59, 0xef, 0x11, 0xf0, 0xbf
    };
    static const unsigned char commit_3[] = {
        0x08,
        0xc7, 0xea, 0x40, 0x7d, 0x26, 0x38, 0xa2, 0x99, 0xb9, 0x40, 0x22, 0x78, 0x17, 0x57, 0x65, 0xb3,
        0x36, 0x82, 0x18, 0x42, 0xc5, 0x57, 0x04, 0x5e, 0x58, 0x5e, 0xf6, 0x40, 0x8b, 0x24, 0x73, 0x10
    };
    static const unsigned char nonce_3[] = {
        0x84, 0x50, 0x94, 0x69, 0xa3, 0x4b, 0x6c, 0x62, 0x1a, 0xc7, 0xe2, 0x0e, 0x07, 0x9a, 0x6f, 0x85,
        0x5f, 0x26, 0x50, 0xcd, 0x88, 0x5a, 0x9f, 0xaa, 0x23, 0x5e, 0x0a, 0xe0, 0x7e, 0xc5, 0xe9, 0xf1
    };
    static const unsigned char blind_3[] = {
        0x68, 0x89, 0x47, 0x8c, 0x77, 0xec, 0xcc, 0x2b, 0x65, 0x01, 0x78, 0x6b, 0x06, 0x8b, 0x38, 0x94,
        0xc0, 0x6b, 0x9b, 0x4c, 0x02, 0xa6, 0xc8, 0xf6, 0xc0, 0x34, 0xea, 0x35, 0x57, 0xf4, 0xe1, 0x37
    };

    CHECK(secp256k1_pedersen_commitment_parse(ctx, &pc, commit_3));
    CHECK(secp256k1_rangeproof_verify(
        ctx,
        &min_value, &max_value,
        &pc,
        vector_3, sizeof(vector_3),
        NULL, 0,
        secp256k1_generator_h
    ));
    CHECK(min_value == UINT64_MAX);
    CHECK(max_value == UINT64_MAX);

    CHECK(secp256k1_rangeproof_rewind(
        ctx,
        blind, &value,
        message, &m_len,
        nonce_3,
        &min_value, &max_value,
        &pc,
        vector_3, sizeof(vector_3),
        NULL, 0,
        secp256k1_generator_h
    ));
    CHECK(memcmp(blind, blind_3, 32) == 0);
    CHECK(value == UINT64_MAX);
    CHECK(min_value == UINT64_MAX);
    CHECK(max_value == UINT64_MAX);
    CHECK(m_len == 0);
}
}

void test_pedersen_commitment_fixed_vector(void) {
    const unsigned char two_g[33] = {
        0x09,
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
        0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
    };
    unsigned char result[33];
    secp256k1_pedersen_commitment parse;

    CHECK(secp256k1_pedersen_commitment_parse(ctx, &parse, two_g));
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, result, &parse));
    CHECK(memcmp(two_g, result, 33) == 0);

    result[0] = 0x08;
    CHECK(secp256k1_pedersen_commitment_parse(ctx, &parse, result));
    result[0] = 0x0c;
    CHECK(!secp256k1_pedersen_commitment_parse(ctx, &parse, result));
}

void run_rangeproof_tests(void) {
    int i;
    test_api();

    test_single_value_proof(0);
    test_single_value_proof(12345678);
    test_single_value_proof(UINT64_MAX);

    test_rangeproof_fixed_vectors();
    test_pedersen_commitment_fixed_vector();
    for (i = 0; i < count / 2 + 1; i++) {
        test_pedersen();
    }
    for (i = 0; i < count / 2 + 1; i++) {
        test_borromean();
    }
    test_rangeproof();
    test_multiple_generators();
}

#endif
