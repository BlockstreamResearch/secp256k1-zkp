/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN_H
#define SECP256K1_MODULE_RANGEPROOF_MAIN_H

#include "../../group.h"

#include "../generator/main_impl.h"
#include "../rangeproof/borromean_impl.h"
#include "../rangeproof/rangeproof_impl.h"

int secp256k1_rangeproof_info(const secp256k1_context* ctx, int *exp, int *mantissa,
 uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen) {
    size_t offset;
    uint64_t scale;
    ARG_CHECK(exp != NULL);
    ARG_CHECK(mantissa != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(proof != NULL);
    offset = 0;
    scale = 1;
    (void)ctx;
    return secp256k1_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}

int secp256k1_rangeproof_rewind(const secp256k1_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    const secp256k1_hash_ctx *hash_ctx = &ctx->hash_ctx;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(message_out != NULL || outlen == NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(hash_ctx, &ctx->ecmult_gen_ctx,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_verify(const secp256k1_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    const secp256k1_hash_ctx *hash_ctx = &ctx->hash_ctx;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(hash_ctx, NULL,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_sign(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen){
    const secp256k1_hash_ctx *hash_ctx = &ctx->hash_ctx;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(message != NULL || msg_len == 0);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_sign_impl(hash_ctx, &ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

size_t secp256k1_rangeproof_max_size(const secp256k1_context* ctx, uint64_t max_value, int min_bits) {
    const int val_mantissa = max_value > 0 ? 64 - secp256k1_clz64_var(max_value) : 1;
    const int mantissa = min_bits > val_mantissa ? min_bits : val_mantissa;
    const size_t rings = (mantissa + 1) / 2;
    const size_t npubs = rings * 4 - 2 * (mantissa % 2);

    VERIFY_CHECK(ctx != NULL);
    (void) ctx;

    return 10 + 32 * (npubs + rings - 1) + 32 + ((rings - 1 + 7) / 8);
}

int secp256k1_borromean_verify(const secp256k1_context* ctx, const unsigned char *e0, const unsigned char *s,
 const unsigned char *m, size_t mlen, const secp256k1_pubkey * const *pubkeys, size_t n_pubkeys,
 const size_t *rsizes, size_t nrings) {
    secp256k1_gej pubs[128];
    secp256k1_scalar sv[128];
    size_t total;
    size_t i;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(e0 != NULL);
    ARG_CHECK(s != NULL);
    ARG_CHECK(m != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);
    ARG_CHECK(n_pubkeys <= 128);
    ARG_CHECK(rsizes != NULL);
    ARG_CHECK(nrings > 0);
    ARG_CHECK(nrings <= 32);

    /* Validate the ring shape before touching pubkeys or s through it. */
    total = 0;
    for (i = 0; i < nrings; i++) {
        total += rsizes[i];
    }
    ARG_CHECK(total == n_pubkeys);

    for (i = 0; i < n_pubkeys; i++) {
        ARG_CHECK(pubkeys[i] != NULL);
    }

    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_ge ge;
        if (!secp256k1_pubkey_load(ctx, &ge, pubkeys[i])) {
            return 0;
        }
        secp256k1_gej_set_ge(&pubs[i], &ge);
        secp256k1_scalar_set_b32(&sv[i], &s[i * 32], &overflow);
        if (overflow) {
            return 0;
        }
    }

    return secp256k1_borromean_verify_impl(&ctx->hash_ctx, NULL, e0, sv, pubs, rsizes, nrings, m, mlen);
}

#endif
