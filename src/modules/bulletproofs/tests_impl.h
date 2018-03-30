/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_TESTS
#define SECP256K1_MODULE_BULLETPROOF_TESTS

#include <string.h>

#include "group.h"
#include "scalar.h"
#include "testrand.h"
#include "util.h"

#include "include/secp256k1_bulletproofs.h"

static void test_bulletproof_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);
    secp256k1_generator value_gen;
    secp256k1_bulletproof_generators *gens;
    secp256k1_pedersen_commitment pcommit[4];
    const secp256k1_pedersen_commitment *pcommit_arr[1];
    unsigned char proof[2000];
    const unsigned char *proof_ptr = proof;
    const unsigned char blind[32] = "   i am not a blinding factor   ";
    const unsigned char *blind_ptr[4];
    size_t blindlen = sizeof(blind);
    size_t plen = sizeof(proof);
    uint64_t value[4] = { 1234, 4567, 8910, 1112 } ;
    uint64_t min_value[4] = { 1000, 4567, 0, 5000 } ;
    const uint64_t *mv_ptr = min_value;
    unsigned char rewind_blind[32];
    size_t rewind_v;

    const char circ_desc_good[] = "2,0,0,4; L0 = 17; 2*L1 - L0 = 21; O0 = 1; O1 = 1;";
    const char circ_desc_bad[] = "2,0,0,4; L0 = 17; 2*L1 - L0 = 21; O0 = 1; O1 x 1;";
    secp256k1_bulletproof_circuit *circ;

    int32_t ecount = 0;

    blind_ptr[0] = blind;
    blind_ptr[1] = blind;
    blind_ptr[2] = blind;
    blind_ptr[3] = blind;
    pcommit_arr[0] = pcommit;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    CHECK(secp256k1_generator_generate(both, &value_gen, blind) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[0], blind, value[0], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[1], blind, value[1], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[2], blind, value[2], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[3], blind, value[3], &value_gen, &secp256k1_generator_const_h) != 0);

    /* generators */
    gens = secp256k1_bulletproof_generators_create(none, NULL, 256);
    CHECK(gens == NULL && ecount == 1);
    gens = secp256k1_bulletproof_generators_create(none, &secp256k1_generator_const_h, 256);
    CHECK(gens != NULL && ecount == 1);

    /* rangeproof_prove */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_prove(none, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_prove(sign, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_prove(vrfy, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 1);
    CHECK(ecount == 3);
    plen = 2000;
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 2, &value_gen, 64, blind, NULL, 0) == 1);
    CHECK(ecount == 3);
    plen = 2000;
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 4, &value_gen, 64, blind, NULL, 0) == 0); /* too few gens */
    CHECK(ecount == 4);

    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, min_value, blind_ptr, 2, &value_gen, 64, blind, NULL, 0) == 1); /* mv = v, ok */
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, &value[1], &min_value[1], blind_ptr, 2, &value_gen, 64, blind, NULL, 0) == 1); /* mv = 0, ok */
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, &value[2], &min_value[2], blind_ptr, 2, &value_gen, 64, blind, NULL, 0) == 0); /* mv > v, !ok */
    CHECK(ecount == 4);

    CHECK(secp256k1_bulletproof_rangeproof_prove(both, NULL, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, NULL, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, NULL, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, NULL, value, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, blind_ptr, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, NULL, 1, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 0, &value_gen, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, NULL, 64, blind, NULL, 0) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 0, blind, NULL, 0) == 0);
    CHECK(ecount == 13);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 65, blind, NULL, 0) == 0);
    CHECK(ecount == 14);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, -1, blind, NULL, 0) == 0);
    CHECK(ecount == 15);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, NULL, NULL, 0) == 0);
    CHECK(ecount == 16);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 1, &value_gen, 64, blind, blind, 0) == 1);
    CHECK(ecount == 16);
    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, min_value, blind_ptr, 1, &value_gen, 64, blind, blind, 32) == 1);
    CHECK(ecount == 16);

    /* rangeproof_verify */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_verify(none, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify(sign, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(vrfy, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 1);
    CHECK(ecount == 2);

    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen - 1, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, 0, min_value, pcommit, 1, 63, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 31) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, NULL, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 2, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 4, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_bulletproof_rangeproof_verify(both, NULL, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, NULL, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, NULL, plen, min_value, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, NULL, pcommit, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, NULL, 1, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 0, 64, &value_gen, blind, 32) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 65, &value_gen, blind, 32) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 0, &value_gen, blind, 32) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, NULL, blind, 32) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, NULL, 32) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, min_value, pcommit, 1, 64, &value_gen, blind, 0) == 0);
    CHECK(ecount == 12);

    /* verify_multi */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(none, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(sign, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(vrfy, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 1);
    CHECK(ecount == 2);

    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, NULL, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, NULL, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, NULL, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 0, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, NULL, pcommit_arr, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, NULL, 1, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, NULL, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, NULL, &blindlen) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, blind_ptr, NULL) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 64, &value_gen, NULL, NULL) == 0);
    CHECK(ecount == 10);

    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 0, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 65, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 63, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 1, 0, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 13);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 2, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 13);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(both, scratch, gens, &proof_ptr, 1, plen, &mv_ptr, pcommit_arr, 4, 64, &value_gen, blind_ptr, &blindlen) == 0);
    CHECK(ecount == 14);

    /* Rewind */
    ecount = 0;
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, 32) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, NULL, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, NULL, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, NULL, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, NULL, plen, min_value[0], pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, 0, min_value[0], pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, 0, pcommit, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], NULL, &value_gen, blind, blind, 32) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, NULL, blind, blind, 32) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, NULL, blind, 32) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, NULL, 32) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, blind, 0) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_bulletproof_rangeproof_rewind(none, gens, &rewind_v, rewind_blind, proof, plen, min_value[0], pcommit, &value_gen, blind, NULL, 0) == 0);
    CHECK(ecount == 8);

    /* Circuit stuff */
    ecount = 0;
    circ = secp256k1_bulletproof_circuit_parse(none, NULL);
    CHECK(circ == NULL && ecount == 1);
    circ = secp256k1_bulletproof_circuit_parse(none, circ_desc_bad);
    CHECK(circ == NULL && ecount == 1);
    circ = secp256k1_bulletproof_circuit_parse(none, circ_desc_good);
    CHECK(circ != NULL && ecount == 1);
    secp256k1_bulletproof_circuit_destroy(none, circ);
    secp256k1_bulletproof_circuit_destroy(none, NULL);

    secp256k1_bulletproof_generators_destroy(none, gens);
    secp256k1_bulletproof_generators_destroy(none, NULL);
    secp256k1_scratch_destroy(scratch);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

#define MAX_WIDTH (1ul << 20)
typedef struct {
    const secp256k1_scalar *a;
    const secp256k1_scalar *b;
    const secp256k1_ge *g;
    const secp256k1_ge *h;
    size_t n;
} test_bulletproof_ecmult_context;

static int test_bulletproof_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    test_bulletproof_ecmult_context *ecctx = (test_bulletproof_ecmult_context *) data;
    if (idx < ecctx->n) {
        *sc = ecctx->a[idx];
        *pt = ecctx->g[idx];
    } else {
        VERIFY_CHECK(idx < 2*ecctx->n);
        *sc = ecctx->b[idx - ecctx->n];
        *pt = ecctx->h[idx - ecctx->n];
    }
    return 1;
}

typedef struct {
    secp256k1_scalar offs;
    secp256k1_scalar ext_sc;
    secp256k1_scalar skew_sc;
    secp256k1_ge ext_pt;
    secp256k1_ge p;
    size_t n;
    int parity;
} test_bulletproof_offset_context;

static int test_bulletproof_offset_vfy_callback(secp256k1_scalar *sc, secp256k1_ge *pt, secp256k1_scalar *randomizer, size_t idx, void *data) {
    test_bulletproof_offset_context *ecctx = (test_bulletproof_offset_context *) data;
    secp256k1_scalar_set_int(&ecctx->offs, 1);
    if (idx < 2 * ecctx->n) {
        secp256k1_scalar idxsc;
        secp256k1_scalar_set_int(&idxsc, idx);
        secp256k1_scalar_mul(sc, &ecctx->skew_sc, &idxsc);
    } else {
        if (ecctx->parity) {
            *sc = ecctx->ext_sc;
            *pt = ecctx->ext_pt;
        } else {
            secp256k1_scalar_set_int(sc, 1);
            *pt = ecctx->p;
        }
    }
    secp256k1_scalar_mul(sc, sc, randomizer);
    ecctx->parity = !ecctx->parity;
    return 1;
}

typedef struct {
    const secp256k1_scalar *a_arr;
    const secp256k1_scalar *b_arr;
} secp256k1_bulletproof_ip_test_abgh_data;


static int secp256k1_bulletproof_ip_test_abgh_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_ip_test_abgh_data *cbctx = (secp256k1_bulletproof_ip_test_abgh_data *) data;
    const int is_g = idx % 2 == 0;

    (void) pt;
    if (is_g) {
        *sc = cbctx->a_arr[idx / 2];
    } else {
        *sc = cbctx->b_arr[idx / 2];
    }
    return 1;
}

void test_bulletproof_inner_product(size_t n, const secp256k1_bulletproof_generators *gens) {
    const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0,0,0,0,0,0,0,0);
    secp256k1_gej pj;
    secp256k1_gej tmpj, tmpj2;
    secp256k1_scalar *a_arr = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, n * sizeof(*a_arr));
    secp256k1_scalar *b_arr = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, n * sizeof(*b_arr));
    unsigned char commit[32] = "hash of P, c, etc. all that jazz";
    secp256k1_scalar one;
    size_t j;
    test_bulletproof_offset_context offs_ctx;
    secp256k1_bulletproof_ip_test_abgh_data abgh_data;
    secp256k1_bulletproof_innerproduct_context innp_ctx;
    unsigned char proof[2000];
    size_t plen = sizeof(proof);

    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 100000 + 256 * (2 * n + 2));

    for (j = 0; j < n; j++) {
        random_scalar_order(&a_arr[j]);
        random_scalar_order(&b_arr[j]);
    }

    abgh_data.a_arr = a_arr;
    abgh_data.b_arr = b_arr;

    random_group_element_test(&offs_ctx.ext_pt);
    random_scalar_order(&offs_ctx.ext_sc);
    secp256k1_scalar_clear(&offs_ctx.skew_sc);
    offs_ctx.n = n;

    secp256k1_scalar_set_int(&one, 1);
    CHECK(secp256k1_bulletproof_inner_product_prove_impl(&ctx->ecmult_ctx, scratch, proof, &plen, gens, &one, n, secp256k1_bulletproof_ip_test_abgh_callback, (void *) &abgh_data, commit) == 1);

    innp_ctx.proof = proof;
    memcpy(innp_ctx.commit, commit, 32);
    secp256k1_scalar_set_int(&innp_ctx.yinv, 1);
    innp_ctx.n_extra_rangeproof_points = 1;
    innp_ctx.rangeproof_cb = test_bulletproof_offset_vfy_callback;
    innp_ctx.rangeproof_cb_data = (void *) &offs_ctx;

    /* Manually do the multiexp to obtain the point P which commits to the inner product.
     * The prover never computes this because it is implicit in the range/circuit proofs. */
    {
        test_bulletproof_ecmult_context ecmult_data;
        ecmult_data.n = n;
        ecmult_data.a = a_arr;
        ecmult_data.b = b_arr;
        ecmult_data.g = gens->gens;
        ecmult_data.h = gens->gens + gens->n/2;
        CHECK(secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &pj, &zero, test_bulletproof_ecmult_callback, (void*) &ecmult_data, 2 * n));
        secp256k1_ge_set_gej(&offs_ctx.p, &pj);
    }

    /* Check proof with no offsets or other baubles */
    offs_ctx.parity = 0;
    secp256k1_scalar_clear(&innp_ctx.p_offs);
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* skew P by a random amount and instruct the verifier to offset it */
    random_scalar_order(&innp_ctx.p_offs);
    secp256k1_gej_set_ge(&tmpj2, &gens->blinding_gen[0]);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmpj, &tmpj2, &innp_ctx.p_offs, &zero);
    secp256k1_gej_add_var(&pj, &pj, &tmpj, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &pj);

    /* wrong p_offs should fail */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 0);

    secp256k1_scalar_negate(&innp_ctx.p_offs, &innp_ctx.p_offs);

    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);
    /* check that verification did not trash anything */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);
    /* check that adding a no-op rangeproof skew function doesn't break anything */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Offset P by some random point and then try to undo this in the verification */
    secp256k1_gej_set_ge(&tmpj2, &offs_ctx.ext_pt);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmpj, &tmpj2, &offs_ctx.ext_sc, &zero);
    secp256k1_gej_neg(&tmpj, &tmpj);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &offs_ctx.p, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &tmpj);
    offs_ctx.parity = 0;
    innp_ctx.n_extra_rangeproof_points = 2;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Offset each basis by some random point and try to undo this in the verification */
    secp256k1_gej_set_infinity(&tmpj2);
    for (j = 0; j < n; j++) {
        size_t k;
        /* Offset by k-times the kth G basis and (k+n)-times the kth H basis */
        for (k = 0; k < j; k++) {
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j], NULL);
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j + gens->n/2], NULL);
        }
        for (k = 0; k < n; k++) {
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &gens->gens[j + gens->n/2], NULL);
        }
    }
    random_scalar_order(&offs_ctx.skew_sc);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmpj, &tmpj2, &offs_ctx.skew_sc, &zero);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &offs_ctx.p, NULL);
    secp256k1_ge_set_gej(&offs_ctx.p, &tmpj);
    secp256k1_scalar_negate(&offs_ctx.skew_sc, &offs_ctx.skew_sc);

    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, &innp_ctx, 1, plen, 1) == 1);

    /* Try to validate the same proof twice */
{
    test_bulletproof_offset_context offs_ctxs[2];
    secp256k1_bulletproof_innerproduct_context innp_ctxs[2];
    offs_ctx.parity = 1;  /* set parity to 1 so the common point will be returned first, as required by the multi-proof verifier */
    memcpy(&innp_ctxs[0], &innp_ctx, sizeof(innp_ctx));
    memcpy(&innp_ctxs[1], &innp_ctx, sizeof(innp_ctx));
    memcpy(&offs_ctxs[0], &offs_ctx, sizeof(offs_ctx));
    memcpy(&offs_ctxs[1], &offs_ctx, sizeof(offs_ctx));
    innp_ctxs[0].rangeproof_cb_data = (void *)&offs_ctxs[0];
    innp_ctxs[1].rangeproof_cb_data = (void *)&offs_ctxs[1];
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, innp_ctxs, 2, plen, 1) == 1);
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, gens, n, innp_ctxs, 2, plen, 0) == 1);
}

    free(a_arr);
    free(b_arr);
    secp256k1_scratch_destroy(scratch);
}

void test_bulletproof_rangeproof(size_t nbits, size_t expected_size, const secp256k1_bulletproof_generators *gens) {
    secp256k1_scalar blind;
    secp256k1_scalar blind_recovered;
    unsigned char proof[1024];
    unsigned char proof2[1024];
    unsigned char proof3[1024];
    const unsigned char *proof_ptr[3];
    size_t plen = sizeof(proof);
    uint64_t v = 123456;
    uint64_t v_recovered;
    secp256k1_gej commitj;
    secp256k1_ge commitp;
    secp256k1_ge commitp2;
    secp256k1_pedersen_commitment pcommit;
    const secp256k1_ge *commitp_ptr[3];
    secp256k1_ge value_gen[3];
    unsigned char nonce[32] = "my kingdom for some randomness!!";

    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 10000000);

    if (v >> nbits > 0) {
        v = 0;
    }

    proof_ptr[0] = proof;
    proof_ptr[1] = proof2;
    proof_ptr[2] = proof3;

    secp256k1_generator_load(&value_gen[0], &secp256k1_generator_const_g);
    secp256k1_generator_load(&value_gen[1], &secp256k1_generator_const_g);
    secp256k1_generator_load(&value_gen[2], &secp256k1_generator_const_h);
    random_scalar_order(&blind);

    secp256k1_pedersen_ecmult(&commitj, &blind, v, &value_gen[0], &gens->blinding_gen[0]);
    secp256k1_ge_set_gej(&commitp, &commitj);
    secp256k1_pedersen_ecmult(&commitj, &blind, v, &value_gen[2], &gens->blinding_gen[0]);
    secp256k1_ge_set_gej(&commitp2, &commitj);
    commitp_ptr[0] = commitp_ptr[1] = &commitp;
    commitp_ptr[2] = &commitp2;
    secp256k1_pedersen_commitment_save(&pcommit, &commitp);

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_ctx, scratch, proof, &plen, nbits, &v, NULL, &blind, &commitp, 1, &value_gen[0], gens, nonce, NULL, 0) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 1;
    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_ctx, scratch, proof2, &plen, nbits, &v, NULL, &blind, &commitp, 1, &value_gen[1], gens, nonce, NULL, 0) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 2;
    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_ctx, scratch, proof3, &plen, nbits, &v, NULL, &blind, &commitp2, 1, &value_gen[2], gens, nonce, NULL, 0) == 1);
    CHECK(plen == expected_size);
    nonce[0] ^= 3;
    /* Verify once */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, proof_ptr, 1, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);
    /* Verify twice at once to test batch validation */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, proof_ptr, 2, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);
    /* Verify thrice at once where one has a different asset type */
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, proof_ptr, 3, plen, nbits, NULL, commitp_ptr, 1, value_gen, gens, NULL, 0) == 1);

    /* Rewind */
    CHECK(secp256k1_bulletproof_rangeproof_rewind_impl(&v_recovered, &blind_recovered, proof, plen, 0, &pcommit, &secp256k1_generator_const_g, gens->blinding_gen, nonce, NULL, 0) == 1);
    CHECK(v_recovered == v);
    CHECK(secp256k1_scalar_eq(&blind_recovered, &blind) == 1);

    nonce[0] ^= 111;
    CHECK(secp256k1_bulletproof_rangeproof_rewind_impl(&v_recovered, &blind_recovered, proof, plen, 0, &pcommit, &secp256k1_generator_const_g, gens->blinding_gen, nonce, NULL, 0) == 0);

    secp256k1_scratch_destroy(scratch);
}

void test_bulletproof_rangeproof_aggregate(size_t nbits, size_t n_commits, size_t expected_size, const secp256k1_bulletproof_generators *gens) {
    unsigned char proof[1024];
    const unsigned char *proof_ptr = proof;
    size_t plen = sizeof(proof);
    secp256k1_scalar *blind = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, n_commits * sizeof(*blind));
    uint64_t *v = (uint64_t *)checked_malloc(&ctx->error_callback, n_commits * sizeof(*v));
    secp256k1_ge *commitp = (secp256k1_ge *)checked_malloc(&ctx->error_callback, n_commits * sizeof(*commitp));
    const secp256k1_ge *constptr = commitp;
    secp256k1_ge value_gen;
    unsigned char commit[32] = {0};
    unsigned char nonce[32] = "mary, mary quite contrary how do";
    size_t i;

    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 10000000);

    secp256k1_generator_load(&value_gen, &secp256k1_generator_const_g);
    for (i = 0; i < n_commits; i++) {
        secp256k1_scalar vs;
        secp256k1_gej commitj;

        v[i] = 223 * i; /* dice-roll random # */
        if (v[i] >> nbits > 0) {
            v[i] = 0;
        }
        secp256k1_scalar_set_u64(&vs, v[i]);
        random_scalar_order(&blind[i]);
        secp256k1_pedersen_ecmult(&commitj, &blind[i], v[i], &value_gen, &gens->blinding_gen[0]);
        secp256k1_ge_set_gej(&commitp[i], &commitj);

        secp256k1_bulletproof_update_commit(commit, &commitp[i], &value_gen);
    }

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_ctx, scratch, proof, &plen, nbits, v, NULL, blind, commitp, n_commits, &value_gen, gens, nonce, NULL, 0) == 1);
    CHECK(plen == expected_size);
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, &proof_ptr, 1, plen, nbits, NULL, &constptr, n_commits, &value_gen, gens, NULL, 0) == 1);

    secp256k1_scratch_destroy(scratch);
    free(commitp);
    free(v);
    free(blind);
}

void test_bulletproof_circuit(const secp256k1_bulletproof_generators *gens) {
    secp256k1_bulletproof_circuit_assignment assn;
    unsigned char proof[2000];
    const unsigned char nonce[32] = "ive got a bit won't tell u which";
    const unsigned char *proof_ptr = proof;
    size_t plen = sizeof(proof);
    secp256k1_scalar one;
    secp256k1_scalar challenge;
    secp256k1_scalar answer;
    secp256k1_scalar commitv;
    secp256k1_gej commitj;
    secp256k1_ge commitp;
    const secp256k1_ge *commitp_ptr;
    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 10 * 1024 * 1024);
    secp256k1_ge value_gen;

    static const char pedersen_3_desc[] = "8,0,3,11; "
        "-L3 + L0 = 0; "
        "-R3 + L1 = 0; "
        "O3 + 43761614841181848836640060563436836929981077120207297347288494535014373124598*L4 + 32269103446714936439983769262136990710725469005847626272964912432556195438855*L0 + 53470148824566042419568143658779164645897136432324031591105781651996231383599*L1 = -29906057699896301565330867720293440045651680527210179749355355245466869592774; "
        "R4 - 2*L2 = -1; "
        "O4 - O5 = -5790157963784981660191168841374597722972181776698071254377150704077242214507; "
        "R5 - 25758063836554693196908199229504721621729641941971332474184303138909611379443*L0 + 11291233376911191389536694739885054786695386896193593308033244950342020590185*L1 + 3363265264840957283186157428945612617240329097799939360463518825408167634185*L4 = -29614996938732799633661547612064662376197030231215982466591901560589852461284; "
        "L5 - L6 = 0; "
        "L5 - R6 = 0; "
        "L5 - L7 = 0; "
        "O6 + R7 - 51516127673109386393816398459009443243459283883942664948368606277819222758886*L0 + 22582466753822382779073389479770109573390773792387186616066489900684041180370*L1 + 6726530529681914566372314857891225234480658195599878720927037650816335268370*L4 = -25204003405338345315301650454981416603166816758113955371299998112889962854657; "
        "O6 - 25758063836554693196908199229504721621729641941971332474184303138909611379443*L0 + 11291233376911191389536694739885054786695386896193593308033244950342020590185*L1 + 3363265264840957283186157428945612617240329097799939360463518825408167634185*L4 = 10482191031782654019194619252232560984851404783271171686897023817875267510226;";
    secp256k1_scalar pedersen_3_al[8] = {
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0x8622f5f9, 0x83a711d6, 0x35530e80, 0x298ac2f1, 0x287824b2, 0xf76f6474, 0x7f4919d6, 0x2e300537),
        SECP256K1_SCALAR_CONST(0x1fc757ec, 0xbddbbeb9, 0xd4f41473, 0xb24f6530, 0x743a1437, 0x46963ca9, 0x0a83f80c, 0x1ee5328b),
        SECP256K1_SCALAR_CONST(0x1fc757ec, 0xbddbbeb9, 0xd4f41473, 0xb24f6530, 0x743a1437, 0x46963ca9, 0x0a83f80c, 0x1ee5328b),
        SECP256K1_SCALAR_CONST(0x1fc757ec, 0xbddbbeb9, 0xd4f41473, 0xb24f6530, 0x743a1437, 0x46963ca9, 0x0a83f80c, 0x1ee5328b)
    };
    secp256k1_scalar pedersen_3_ar[8] = {
        SECP256K1_SCALAR_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364140),
        SECP256K1_SCALAR_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364140),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1),
        SECP256K1_SCALAR_CONST(0x31c8eae3, 0xf71d7572, 0x260f2848, 0xe9f7209d, 0x7366b59e, 0x073e490d, 0x279d8c48, 0x656e329f),
        SECP256K1_SCALAR_CONST(0x1fc757ec, 0xbddbbeb9, 0xd4f41473, 0xb24f6530, 0x743a1437, 0x46963ca9, 0x0a83f80c, 0x1ee5328b),
        SECP256K1_SCALAR_CONST(0x245cbdd4, 0xef485258, 0xba62e0d9, 0x26e672d2, 0x83d1988a, 0x3c3a1e2f, 0x6639ec10, 0x39c6a2b0)
    };
    secp256k1_scalar pedersen_3_ao[8] = {
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        SECP256K1_SCALAR_CONST(0x8622f5f9, 0x83a711d6, 0x35530e80, 0x298ac2f1, 0x287824b2, 0xf76f6474, 0x7f4919d6, 0x2e300537),
        SECP256K1_SCALAR_CONST(0x92f012f8, 0xd76c6bd9, 0x7cdaa7c4, 0x6a848512, 0xed249960, 0xc58efb11, 0x48945d26, 0x186dada2),
        SECP256K1_SCALAR_CONST(0x8a6f1f26, 0x6b9c02e6, 0x8cb97c20, 0xd04aab71, 0xf4024826, 0xeb84f19f, 0xa13641ee, 0xe3f3db55),
        SECP256K1_SCALAR_CONST(0xc4e18e86, 0x9b53aabc, 0x22891520, 0x299684a8, 0x75ad4a2e, 0xc4e1e6af, 0x2556146f, 0xb25f219e)
    };

    const char inv_17_19_circ[] = "2,1,0,5; L0 = 17; 2*L1 - L0 = 21; O0 = 1; O1 = 1; V0 - L0 = 100;";
    secp256k1_bulletproof_circuit *simple = secp256k1_parse_circuit(ctx, inv_17_19_circ);
    secp256k1_bulletproof_circuit *pedersen_3 = secp256k1_parse_circuit(ctx, pedersen_3_desc);

    CHECK(simple != NULL);
    CHECK(pedersen_3 != NULL);

    CHECK(secp256k1_scratch_allocate_frame (scratch, 3072 * sizeof(secp256k1_scalar), 3));
    assn.al = secp256k1_scratch_alloc(scratch, 1024 * sizeof(*assn.al));
    assn.ar = secp256k1_scratch_alloc(scratch, 1024 * sizeof(*assn.al));
    assn.ao = secp256k1_scratch_alloc(scratch, 1024 * sizeof(*assn.al));

    CHECK (simple != NULL);

    secp256k1_scalar_set_int(&challenge, 17);
    secp256k1_scalar_inverse(&answer, &challenge);
    secp256k1_scalar_set_int(&one, 1);

    /* Try to prove with input 0, 1, 0 */
    assn.al[0] = assn.al[1] = challenge;
    assn.ar[0] = assn.ar[1] = answer;
    assn.ao[0] = assn.ao[1] = one;

    secp256k1_scalar_set_int(&commitv, 117);
    secp256k1_scalar_set_int(&challenge, 19);
    secp256k1_scalar_inverse(&answer, &challenge);
    assn.al[1] = challenge;
    assn.ar[1] = answer;
    assn.v = &commitv;
    assn.n_gates = 2;
    assn.n_commits = 1;

    /* Use one as the blinding factor */
    secp256k1_generator_load(&value_gen, &secp256k1_generator_const_g);
    secp256k1_pedersen_ecmult(&commitj, &one, 117, &value_gen, &gens->blinding_gen[0]);
    secp256k1_ge_set_gej(&commitp, &commitj);
    commitp_ptr = &commitp;

    CHECK(secp256k1_bulletproof_relation66_prove_impl(
        &ctx->ecmult_ctx,
        scratch,
        proof, &plen,
        &assn,
        &commitp, &one, 1,
        &value_gen,
        simple,
        gens,
        nonce,
        NULL, 0
    ));

    CHECK(secp256k1_bulletproof_relation66_verify_impl(
        &ctx->ecmult_ctx,
        scratch,
        &proof_ptr, 1, plen,
        &commitp_ptr, &assn.n_commits,
        &value_gen,
        (const secp256k1_bulletproof_circuit* const*) &simple,
        gens,
        NULL, 0
    ));

    plen = 2000;
    assn.al = pedersen_3_al;
    assn.ar = pedersen_3_ar;
    assn.ao = pedersen_3_ao;
    assn.n_gates = pedersen_3->n_gates;
    assn.n_commits = 0;
    CHECK(secp256k1_bulletproof_relation66_prove_impl(
        &ctx->ecmult_ctx,
        scratch,
        proof, &plen,
        &assn,
        NULL, NULL, 0,
        &value_gen,
        pedersen_3,
        gens,
        nonce,
        NULL, 0
    ));

    CHECK(secp256k1_bulletproof_relation66_verify_impl(
        &ctx->ecmult_ctx,
        scratch,
        &proof_ptr, 1, plen,
        NULL, NULL,
        &value_gen,
        (const secp256k1_bulletproof_circuit* const*) &pedersen_3,
        gens,
        NULL, 0
    ));

    secp256k1_bulletproof_circuit_destroy(ctx, simple);
    secp256k1_bulletproof_circuit_destroy(ctx, pedersen_3);
    secp256k1_scratch_deallocate_frame(scratch);
    secp256k1_scratch_destroy(scratch);
}

void run_bulletproofs_tests(void) {
    size_t i;

    /* Make a ton of generators */
    secp256k1_bulletproof_generators *gens = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, 32768);
    test_bulletproof_api();

    /* sanity checks */
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(0) == 32);  /* encoding of 1 */
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(1) == 96);  /* encoding a*b, a, b */
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(2) == 160); /* dot prod, a, b, L, R, parity of L, R */
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(4) == 225); /* dot prod, a, b, a, b, L, R, parity of L, R */
    CHECK(secp256k1_bulletproof_innerproduct_proof_length(8) == 289); /* dot prod, a, b, a, b, L, R, L, R, parity of L, R */

    test_bulletproof_inner_product(0, gens);
    test_bulletproof_inner_product(1, gens);
    test_bulletproof_inner_product(2, gens);
    test_bulletproof_inner_product(4, gens);
    test_bulletproof_inner_product(8, gens);
    for (i = 0; i < (size_t) count; i++) {
        test_bulletproof_inner_product(32, gens);
        test_bulletproof_inner_product(64, gens);
    }
    test_bulletproof_inner_product(1024, gens);

    test_bulletproof_rangeproof(1, 289, gens);
    test_bulletproof_rangeproof(2, 353, gens);
    test_bulletproof_rangeproof(16, 546, gens);
    test_bulletproof_rangeproof(32, 610, gens);
    test_bulletproof_rangeproof(64, 675, gens);

    test_bulletproof_rangeproof_aggregate(64, 1, 675, gens);
    test_bulletproof_rangeproof_aggregate(8, 2, 546, gens);
    test_bulletproof_rangeproof_aggregate(8, 4, 610, gens);

    test_bulletproof_circuit(gens);

    secp256k1_bulletproof_generators_destroy(ctx, gens);
}
#undef MAX_WIDTH

#endif
