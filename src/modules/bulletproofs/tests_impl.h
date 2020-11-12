/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_TEST_
#define _SECP256K1_MODULE_BULLETPROOFS_TEST_

#include <stdint.h>

#include "include/secp256k1_bulletproofs.h"

static void test_bulletproofs_generators_api(void) {
    /* The BP generator API requires no precomp */
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    secp256k1_bulletproofs_generators *gens;
    unsigned char gens_ser[330];
    size_t len = sizeof(gens_ser);

    int32_t ecount = 0;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);

    /* Create */
    gens = secp256k1_bulletproofs_generators_create(none, 10);
    CHECK(gens != NULL && ecount == 0);

    /* Serialize */
    ecount = 0;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, NULL, gens_ser, &len));
    CHECK(ecount == 1);
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, NULL, &len));
    CHECK(ecount == 2);
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, NULL));
    CHECK(ecount == 3);
    len = 0;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    len = sizeof(gens_ser) - 1;
    CHECK(!secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    len = sizeof(gens_ser);
    CHECK(secp256k1_bulletproofs_generators_serialize(none, gens, gens_ser, &len));
    CHECK(ecount == 3);

    /* Parse */
    ecount = 0;
    secp256k1_bulletproofs_generators_destroy(none, gens); /* avoid leaking memory */
    gens = secp256k1_bulletproofs_generators_parse(none, NULL, sizeof(gens_ser));
    CHECK(gens == NULL && ecount == 1);
    /* Not a multiple of 33 */
    gens = secp256k1_bulletproofs_generators_parse(none, gens_ser, sizeof(gens_ser) - 1);
    CHECK(gens == NULL && ecount == 1);
    gens = secp256k1_bulletproofs_generators_parse(none, gens_ser, sizeof(gens_ser));
    CHECK(gens != NULL && ecount == 1);

    /* Destroy (we allow destroying a NULL context, it's just a noop. like free().) */
    ecount = 0;
    secp256k1_bulletproofs_generators_destroy(none, NULL);
    secp256k1_bulletproofs_generators_destroy(none, gens);
    CHECK(ecount == 0);

    secp256k1_context_destroy(none);
}

static void test_bulletproofs_generators_fixed(void) {
    secp256k1_bulletproofs_generators *gens = secp256k1_bulletproofs_generators_create(ctx, 3);
    unsigned char gens_ser[330];
    const unsigned char fixed_first_3[99] = {
        0x0b,
        0xb3, 0x4d, 0x5f, 0xa6, 0xb8, 0xf3, 0xd1, 0x38,
        0x49, 0xce, 0x51, 0x91, 0xb7, 0xf6, 0x76, 0x18,
        0xfe, 0x5b, 0xd1, 0x2a, 0x88, 0xb2, 0x0e, 0xac,
        0x33, 0x89, 0x45, 0x66, 0x7f, 0xb3, 0x30, 0x56,
        0x0a,
        0x62, 0x86, 0x15, 0x16, 0x92, 0x42, 0x10, 0x9e,
        0x9e, 0x64, 0xd4, 0xcb, 0x28, 0x81, 0x60, 0x9c,
        0x24, 0xb9, 0x89, 0x51, 0x2a, 0xd9, 0x01, 0xae,
        0xff, 0x75, 0x64, 0x9c, 0x37, 0x5d, 0xbd, 0x79,
        0x0a,
        0xed, 0xe0, 0x6e, 0x07, 0x5e, 0x79, 0xd0, 0xf7,
        0x7b, 0x03, 0x3e, 0xb9, 0xa9, 0x21, 0xa4, 0x5b,
        0x99, 0xf3, 0x9b, 0xee, 0xfe, 0xa0, 0x37, 0xa2,
        0x1f, 0xe9, 0xd7, 0x4f, 0x95, 0x8b, 0x10, 0xe2,
    };
    size_t len;

    len = 99;
    CHECK(secp256k1_bulletproofs_generators_serialize(ctx, gens, gens_ser, &len));
    CHECK(memcmp(gens_ser, fixed_first_3, sizeof(fixed_first_3)) == 0);

    len = sizeof(gens_ser);
    CHECK(secp256k1_bulletproofs_generators_serialize(ctx, gens, gens_ser, &len));
    CHECK(memcmp(gens_ser, fixed_first_3, sizeof(fixed_first_3)) == 0);

    secp256k1_bulletproofs_generators_destroy(ctx, gens);
}

static void test_bulletproofs_rangeproof_uncompressed_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_bulletproofs_generators *gens = secp256k1_bulletproofs_generators_create(ctx, 32);
    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 250); /* shouldn't need much */
    unsigned char proof[SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_] = {0};
    size_t plen = sizeof(proof);
    const size_t min_value = 99;
    const size_t value = 100;
    secp256k1_pedersen_commitment commit;
    const unsigned char blind[32] = "help me! i'm bliiiiiiiiiiiiiiind";
    const unsigned char nonce[32] = "nonce? non ce n'est vrai amirite";
    const unsigned char enc_data[32] = "this data is encrypted: ********";
    /* Extra commit is a Joan Shelley lyric */
    const unsigned char extra_commit[] = "Shock of teal blue beneath clouds gathering, and the light of empty black on the waves at the horizon";
    const size_t extra_commit_len = sizeof(extra_commit);

    int ecount;

    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, value, secp256k1_generator_h));

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    /* size estimate */
    ecount = 0;
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(none, 0) == 194);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(none, 1) == 258);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(none, 64)
        == SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(none, 65) == 0);
    CHECK(ecount == 0);

    /* proving */
    ecount = 0;
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, NULL, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, NULL, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, NULL, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, NULL, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 0, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 17, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    plen = sizeof(proof);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 1000, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    plen = sizeof(proof);
    CHECK(ecount == 4); /* bad n_bits is not an API error */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 1);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, value + 1, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 4); /* bad value vs min_value is not an API error */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, NULL, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, NULL, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, NULL, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, NULL, extra_commit, extra_commit_len) == 1);
    CHECK(ecount == 7); /* enc_data can be NULL */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, NULL, extra_commit_len) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, NULL, 0) == 1);
    CHECK(ecount == 8); /* extra_commit can be NULL as long as its length is 0 */

    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(none, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(vrfy, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(sign, gens, secp256k1_generator_h, proof, &plen, 16, value, min_value, &commit, blind, nonce, enc_data, extra_commit, extra_commit_len) == 1);
    CHECK(ecount == 10);

    /* verifying */
    ecount = 0;
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, NULL, gens, secp256k1_generator_h, proof, plen, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, NULL, secp256k1_generator_h, proof, plen, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, NULL, proof, plen, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, NULL, plen, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, 0, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen + 1, min_value, &commit, extra_commit, extra_commit_len) == 0);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen + 64, min_value, &commit, extra_commit, extra_commit_len) == 0);
    /* TODO wrong min_value will pass until we implement the EC check */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen, min_value + 1, &commit, extra_commit, extra_commit_len) == 1);
    CHECK(ecount == 4);  /* bad plen, min_value are not API errors */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen, min_value, NULL, extra_commit, extra_commit_len) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen, min_value, &commit, NULL, extra_commit_len) == 0);
    CHECK(ecount == 6);
    /* TODO wrong extra_commitment will also pass until we implement the EC check */
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen, min_value, &commit, NULL, 0) == 1);
    CHECK(ecount == 6); /* zeroed out extra_commitment is not an API error */

    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(none, scratch, gens, secp256k1_generator_h, proof, plen, min_value, &commit, NULL, 0) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(sign, scratch, gens, secp256k1_generator_h, proof, plen, min_value, &commit, NULL, 0) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(vrfy, scratch, gens, secp256k1_generator_h, proof, plen, min_value, &commit, extra_commit, extra_commit_len) == 1);
    CHECK(ecount == 8);

    secp256k1_bulletproofs_generators_destroy(ctx, gens);
    secp256k1_scratch_space_destroy(ctx, scratch);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

void run_bulletproofs_tests(void) {
    test_bulletproofs_generators_api();
    test_bulletproofs_generators_fixed();
    test_bulletproofs_rangeproof_uncompressed_api();
}

#endif
