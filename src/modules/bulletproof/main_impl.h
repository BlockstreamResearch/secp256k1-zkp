/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL
#define SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL

#include "group.h"

#include "modules/rangeproof/main_impl.h"
#include "modules/rangeproof/pedersen_impl.h"

#include "modules/bulletproof/generators.h"
#include "modules/bulletproof/inner_product_impl.h"
#include "modules/bulletproof/rangeproof_impl.h"
#include "modules/bulletproof/util.h"

int secp256k1_bulletproof_rangeproof_verify(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const unsigned char *proof, size_t plen,
 const secp256k1_pedersen_commitment* commit, size_t nbits, const secp256k1_generator* gen, const unsigned char *extra_commit, size_t extra_commit_len) {
    secp256k1_ge genp;
    secp256k1_ge commitp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));

    secp256k1_generator_load(&genp, gen);
    secp256k1_pedersen_commitment_load(&commitp, commit);

    return secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, &ctx->error_callback, proof, plen, nbits, &commitp, &genp, extra_commit, extra_commit_len);
}

int secp256k1_bulletproof_rangeproof_prove(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, unsigned char *proof, size_t *plen, uint64_t value, const unsigned char *blind,
 const secp256k1_generator* gen, size_t nbits, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len) {
    secp256k1_ge commitp;
    secp256k1_gej commitj;
    secp256k1_ge genp;
    secp256k1_scalar blinds;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(nbits <= 64);
    ARG_CHECK(nbits == 64 || value < (1ull << nbits));
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    secp256k1_generator_load(&genp, gen);

    secp256k1_scalar_set_b32(&blinds, blind, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&blinds)) {
        return 0;
    }
    secp256k1_pedersen_ecmult(&ctx->ecmult_gen_ctx, &commitj, &blinds, value, &genp);
    secp256k1_ge_set_gej(&commitp, &commitj);

    return secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_gen_ctx, &ctx->ecmult_ctx, scratch, &ctx->error_callback,
        proof, plen, nbits, value, &blinds, &commitp, &genp, nonce, extra_commit, extra_commit_len);
}

#endif
