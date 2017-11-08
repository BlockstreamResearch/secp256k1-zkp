/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
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

#include "modules/bulletproof/generators.h"

#include "include/secp256k1_bulletproof.h"

#define MAX_WIDTH (sizeof(secp256k1_ge_const_gi) / sizeof(secp256k1_ge_const_gi[0]) / 2)
typedef struct {
    const secp256k1_scalar *a;
    const secp256k1_scalar *b;
    size_t n;
} test_bulletproof_ecmult_context;

static int test_bulletproof_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    test_bulletproof_ecmult_context *ecctx = (test_bulletproof_ecmult_context *) data;
    if (idx < ecctx->n) {
        *sc = ecctx->a[idx];
        *pt = secp256k1_ge_const_gi[idx];
    } else {
        VERIFY_CHECK(idx < 2*ecctx->n);
        *sc = ecctx->b[idx - ecctx->n];
        *pt = secp256k1_ge_const_gi[idx + MAX_WIDTH - ecctx->n];
    }
    return 1;
}

typedef struct {
    secp256k1_scalar offs;
    secp256k1_scalar ext_sc;
    secp256k1_scalar skew_sc;
    secp256k1_ge ext_pt;
    size_t n;
    int parity;
} test_bulletproof_offset_context;

static int test_bulletproof_offset_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    test_bulletproof_offset_context *ecctx = (test_bulletproof_offset_context *) data;
    secp256k1_scalar_set_int(&ecctx->offs, 1);
    if (idx < ecctx->n) {
        secp256k1_scalar idxsc;
        secp256k1_scalar_set_int(&idxsc, idx);
        *sc = ecctx->skew_sc;
        secp256k1_scalar_mul(sc, sc, &idxsc);
        if (ecctx->parity) {
            secp256k1_scalar_add(sc, sc, sc);
        }
    } else {
        *sc = ecctx->ext_sc;
        *pt = ecctx->ext_pt;
    }
    ecctx->parity = !ecctx->parity;
    return 1;
}

void test_bulletproof_inner_product(size_t depth) {
    const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0,0,0,0,0,0,0,0);
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_gej tmpj, tmpj2;
    secp256k1_scalar a, b, p_offs;
    secp256k1_ge lpt[MAX_WIDTH];
    secp256k1_ge rpt[MAX_WIDTH];
    secp256k1_scalar a_arr[MAX_WIDTH];
    secp256k1_scalar b_arr[MAX_WIDTH];
    secp256k1_scalar c;
    unsigned char commit[32] = "hash of P, c, etc. all that jazz";
    size_t j;
    test_bulletproof_offset_context offs_ctx;

    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 1000000, 10000000);

    CHECK(depth < SECP256K1_BULLETPROOF_MAX_DEPTH);
    CHECK(1u << depth <= MAX_WIDTH);

    for (j = 0; j < 1u << depth; j++) {
        random_scalar_order(&a_arr[j]);
        random_scalar_order(&b_arr[j]);
    }
    random_scalar_order(&p_offs);
    random_group_element_test(&offs_ctx.ext_pt);
    random_scalar_order(&offs_ctx.ext_sc);
    secp256k1_scalar_clear(&offs_ctx.skew_sc);
    offs_ctx.n = 1 << depth;

    CHECK(secp256k1_bulletproof_inner_product_prove_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &pj, &a, &b, lpt, rpt, depth, a_arr, b_arr, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], commit) == 1);
    secp256k1_scalar_dot_product(&c, a_arr, b_arr, 1 << depth);

    {
        secp256k1_gej exp_p;
        test_bulletproof_ecmult_context ecmult_data;
        ecmult_data.n = 1 << depth;
        ecmult_data.a = a_arr;
        ecmult_data.b = b_arr;
        CHECK(secp256k1_ecmult_multi(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &exp_p, &zero, test_bulletproof_ecmult_callback, (void*) &ecmult_data, 2 << depth));
        secp256k1_gej_neg(&exp_p, &exp_p);
        secp256k1_gej_add_var(&exp_p, &exp_p, &pj, NULL);
        CHECK(secp256k1_gej_is_infinity(&exp_p));
    }

    /* skew P by a random amount and instruct the verifier to offset it */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmpj, &p_offs);
    secp256k1_gej_add_var(&pj, &pj, &tmpj, NULL);
    secp256k1_ge_set_gej(&p, &pj);

    /* wrong p_offs should fail */
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, NULL, NULL, 0, &a, &b, lpt, rpt, depth, commit) == 0);

    secp256k1_scalar_negate(&p_offs, &p_offs);

    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, NULL, NULL, 0, &a, &b, lpt, rpt, depth, commit) == 1);
    /* check that verification did not trash anything */
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, NULL, NULL, 0, &a, &b, lpt, rpt, depth, commit) == 1);
    /* check that adding a no-op rangeproof skew function doesn't break anything */
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, test_bulletproof_offset_callback, (void*)&offs_ctx, 0, &a, &b, lpt, rpt, depth, commit) == 1);

    /* Offset P by some random point and then try to undo this in the verification */
    secp256k1_gej_set_ge(&tmpj2, &offs_ctx.ext_pt);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmpj, &tmpj2, &offs_ctx.ext_sc, &zero);
    secp256k1_gej_neg(&tmpj, &tmpj);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &p, NULL);
    secp256k1_ge_set_gej(&p, &tmpj);
    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, test_bulletproof_offset_callback, (void*)&offs_ctx, 1, &a, &b, lpt, rpt, depth, commit) == 1);

    /* Offset each basis by some random point and try to undo this in the verification */
    secp256k1_gej_set_infinity(&tmpj2);
    for (j = 0; j < 1u << depth; j++) {
        size_t k;
        /* Offset G-basis k by k times the random point, H-basis k by 2k times, to ensure
         * that each index has a different skew */
        for (k = 0; k < j; k++) {
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &secp256k1_ge_const_gi[j], NULL);
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &secp256k1_ge_const_gi[MAX_WIDTH + j], NULL);
            secp256k1_gej_add_ge_var(&tmpj2, &tmpj2, &secp256k1_ge_const_gi[MAX_WIDTH + j], NULL);
        }
    }
    random_scalar_order(&offs_ctx.skew_sc);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmpj, &tmpj2, &offs_ctx.skew_sc, &zero);
    secp256k1_gej_add_ge_var(&tmpj, &tmpj, &p, NULL);
    secp256k1_ge_set_gej(&p, &tmpj);
    secp256k1_scalar_negate(&offs_ctx.skew_sc, &offs_ctx.skew_sc);

    offs_ctx.parity = 0;
    CHECK(secp256k1_bulletproof_inner_product_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, &secp256k1_ge_const_gi[0], &secp256k1_ge_const_gi[MAX_WIDTH], &c, &p, &p_offs, test_bulletproof_offset_callback, (void*)&offs_ctx, 1, &a, &b, lpt, rpt, depth, commit) == 1);

    secp256k1_scratch_destroy(scratch);
}

void test_bulletproof_rangeproof(size_t nbits, size_t expected_size) {
    secp256k1_scalar blind;
    unsigned char proof[1024];
    size_t plen = sizeof(proof);
    uint64_t v = 0;
    secp256k1_gej commitj;
    secp256k1_ge commitp;
    secp256k1_scalar vs;
    secp256k1_gej altgen;
    unsigned char commit[32] = {0};
    unsigned char nonce[32] = "my kingdom for some randomness!!";

    secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 1000000, 10000000);

    secp256k1_gej_set_ge(&altgen, &secp256k1_ge_const_g2);
    random_scalar_order(&blind);
    secp256k1_scalar_set_u64(&vs, v);
    secp256k1_ecmult(&ctx->ecmult_ctx, &commitj, &altgen, &vs, &blind);
    secp256k1_ge_set_gej(&commitp, &commitj);

    secp256k1_bulletproof_update_commit(commit, &commitp, &secp256k1_ge_const_g2);

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_gen_ctx, &ctx->ecmult_ctx, scratch, &ctx->error_callback, proof, &plen, nbits, v, &blind, &commitp, &secp256k1_ge_const_g2, nonce, NULL, 0) == 1);
    CHECK(plen == expected_size);
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, proof, plen, nbits, &commitp, &secp256k1_ge_const_g2, NULL, 0) == 1);

    secp256k1_scratch_destroy(scratch);
}
#undef MAX_WIDTH

void run_bulletproof_tests(void) {
    int i;

    /* sanity checks */
    test_bulletproof_inner_product(0);
    test_bulletproof_inner_product(1);
    test_bulletproof_inner_product(2);
    for (i = 0; i < count; i++) {
        test_bulletproof_inner_product(5);
        test_bulletproof_inner_product(6);
    }

    test_bulletproof_rangeproof(1, 289);
    test_bulletproof_rangeproof(2, 353);
    test_bulletproof_rangeproof(16, 546);
    test_bulletproof_rangeproof(32, 610);
    test_bulletproof_rangeproof(64, 674);
}

#endif
