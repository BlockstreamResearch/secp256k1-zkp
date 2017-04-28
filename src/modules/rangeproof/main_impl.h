/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "group.h"
#include "extra_generators.h"

#include "modules/rangeproof/pedersen_impl.h"
#include "modules/rangeproof/borromean_impl.h"
#include "modules/rangeproof/rangeproof_impl.h"

static void secp256k1_context_to_rangeproof(secp256k1_rangeproof_context_pointers* r, const secp256k1_context* ctx, int soundness) {
    r->ecmult_ctx = &ctx->ecmult_ctx;
    r->ecmult_gen_ctx = &ctx->ecmult_gen_ctx;
    if (soundness) {
        r->ndigits = ctx->ndigits;
        r->alt_ecmult_ctx = &ctx->alt_ecmult_ctx;
        r->alt_ecmult_gen_ctx = &ctx->alt_ecmult_gen_ctx;
        r->digit_ecmult_ctx = ctx->digit_ecmult_ctx;
        r->digit_ecmult_gen_ctx = ctx->digit_ecmult_gen_ctx;
    } else {
        r->ndigits = 0;
        r->digit_ecmult_ctx = &ctx->ecmult_ctx;
        r->digit_ecmult_gen_ctx = &ctx->ecmult_gen_ctx;
    }
}

void secp256k1_context_initialize_for_sound_rangeproof(secp256k1_context *ctx, const size_t ndigits) {
    size_t i;
    secp256k1_gej running_sumj;
    secp256k1_ge running_sum;

    if (EXPECT(ndigits > 32, 0)) {
        secp256k1_callback_call(&ctx->illegal_callback, "invalid number of digits");
    }

    /* FIXME: reuse contexts when changing the number of digits */
    if (ctx->ndigits > 0) {
        for (i = 0; i < ctx->ndigits; i++) {
            secp256k1_ecmult_context_clear(&ctx->digit_ecmult_ctx[i]);
            secp256k1_ecmult_gen_context_clear(&ctx->digit_ecmult_gen_ctx[i]);
        }
        free(ctx->digit_ecmult_gen_ctx);
        free(ctx->digit_ecmult_ctx);
    }
    ctx->ndigits = ndigits;
    if (ndigits == 0) {
        return;
    }

    ctx->digit_ecmult_ctx = (secp256k1_ecmult_context*)checked_malloc(&default_error_callback, ndigits * sizeof(*ctx->digit_ecmult_ctx));
    ctx->digit_ecmult_gen_ctx = (secp256k1_ecmult_gen_context*)checked_malloc(&default_error_callback, ndigits * sizeof(*ctx->digit_ecmult_gen_ctx));

    secp256k1_gej_set_infinity(&running_sumj);
    /* NUMS "alternate" generator used for El Gamal commitments */
    secp256k1_ecmult_context_init(&ctx->alt_ecmult_ctx);
    secp256k1_ecmult_gen_context_init(&ctx->alt_ecmult_gen_ctx);
    secp256k1_ecmult_context_build(&ctx->alt_ecmult_ctx, &secp256k1_ge_const_g2, &ctx->error_callback);
    secp256k1_ecmult_gen_context_build(&ctx->alt_ecmult_gen_ctx, &secp256k1_ge_const_g2, &ctx->error_callback);
    /* NUMS digit generators */
    for (i = 0; i < ndigits - 1; i++) {
        secp256k1_ecmult_context_init(&ctx->digit_ecmult_ctx[i]);
        secp256k1_ecmult_gen_context_init(&ctx->digit_ecmult_gen_ctx[i]);
        secp256k1_ecmult_context_build(&ctx->digit_ecmult_ctx[i], &secp256k1_ge_const_gi[i], &ctx->error_callback);
        secp256k1_ecmult_gen_context_build(&ctx->digit_ecmult_gen_ctx[i], &secp256k1_ge_const_gi[i], &ctx->error_callback);
        secp256k1_gej_add_ge(&running_sumj, &running_sumj, &secp256k1_ge_const_gi[i]);
    }
    /* set final generator so they all sum to G */
    secp256k1_gej_neg(&running_sumj, &running_sumj);
    secp256k1_gej_add_ge_var(&running_sumj, &running_sumj, &secp256k1_ge_const_g, NULL);
    secp256k1_ge_set_gej(&running_sum, &running_sumj);
    secp256k1_ecmult_context_init(&ctx->digit_ecmult_ctx[i]);
    secp256k1_ecmult_gen_context_init(&ctx->digit_ecmult_gen_ctx[i]);
    secp256k1_ecmult_context_build(&ctx->digit_ecmult_ctx[i], &running_sum, &ctx->error_callback);
    secp256k1_ecmult_gen_context_build(&ctx->digit_ecmult_gen_ctx[i], &running_sum, &ctx->error_callback);
}

size_t secp256k1_context_sound_rangeproof_n_digits(const secp256k1_context *ctx) {
    VERIFY_CHECK(ctx != NULL);
    return ctx->ndigits;
}

/** Alternative generator for secp256k1.
 *  This is the sha256 of 'g' after DER encoding (without compression),
 *  which happens to be a point on the curve.
 *  sage: G2 = EllipticCurve ([F (0), F (7)]).lift_x(int(hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex')).hexdigest(),16))
 *  sage: '%x %x' % (11 - G2.xy()[1].is_square(), G2.xy()[0])
 */
static const secp256k1_generator secp256k1_generator_h_internal = {{
    0x11,
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
}};

const secp256k1_generator *secp256k1_generator_h = &secp256k1_generator_h_internal;

static void secp256k1_pedersen_commitment_load(secp256k1_ge* ge, const secp256k1_pedersen_commitment* commit) {
    secp256k1_fe fe;
    secp256k1_fe_set_b32(&fe, &commit->data[1]);
    secp256k1_ge_set_xquad(ge, &fe);
    if (commit->data[0] & 1) {
        secp256k1_ge_neg(ge, ge);
    }
}

static void secp256k1_pedersen_commitment_save(secp256k1_pedersen_commitment* commit, secp256k1_ge* ge) {
    secp256k1_fe_normalize(&ge->x);
    secp256k1_fe_get_b32(&commit->data[1], &ge->x);
    commit->data[0] = 9 ^ secp256k1_fe_is_quad_var(&ge->y);
}

int secp256k1_pedersen_commitment_parse(const secp256k1_context* ctx, secp256k1_pedersen_commitment* commit, const unsigned char *input) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(input != NULL);
    if ((input[0] & 0xFE) != 8) {
        return 0;
    }
    memcpy(commit->data, input, sizeof(commit->data));
    return 1;
}

int secp256k1_pedersen_commitment_serialize(const secp256k1_context* ctx, unsigned char *output, const secp256k1_pedersen_commitment* commit) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(commit != NULL);
    memcpy(output, commit->data, sizeof(commit->data));
    return 1;
}

/* Generates a pedersen commitment: *commit = blind * G + value * G2. The blinding factor is 32 bytes.*/
int secp256k1_pedersen_commit(const secp256k1_context* ctx, secp256k1_pedersen_commitment *commit, const unsigned char *blind, uint64_t value, const secp256k1_generator* gen) {
    secp256k1_ge genp;
    secp256k1_gej rj;
    secp256k1_ge r;
    secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    secp256k1_generator_load(&genp, gen);
    secp256k1_scalar_set_b32(&sec, blind, &overflow);
    if (!overflow) {
        secp256k1_pedersen_ecmult(&ctx->ecmult_gen_ctx, &rj, &sec, value, &genp);
        if (!secp256k1_gej_is_infinity(&rj)) {
            secp256k1_ge_set_gej(&r, &rj);
            secp256k1_pedersen_commitment_save(commit, &r);
            ret = 1;
        }
        secp256k1_gej_clear(&rj);
        secp256k1_ge_clear(&r);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

/** Takes a list of n pointers to 32 byte blinding values, the first negs of which are treated with positive sign and the rest
 *  negative, then calculates an additional blinding value that adds to zero.
 */
int secp256k1_pedersen_blind_sum(const secp256k1_context* ctx, unsigned char *blind_out, const unsigned char * const *blinds, size_t n, size_t npositive) {
    secp256k1_scalar acc;
    secp256k1_scalar x;
    size_t i;
    int overflow;
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(blind_out != NULL);
    ARG_CHECK(blinds != NULL);
    secp256k1_scalar_set_int(&acc, 0);
    for (i = 0; i < n; i++) {
        secp256k1_scalar_set_b32(&x, blinds[i], &overflow);
        if (overflow) {
            return 0;
        }
        if (i >= npositive) {
            secp256k1_scalar_negate(&x, &x);
        }
        secp256k1_scalar_add(&acc, &acc, &x);
    }
    secp256k1_scalar_get_b32(blind_out, &acc);
    secp256k1_scalar_clear(&acc);
    secp256k1_scalar_clear(&x);
    return 1;
}

/* Takes two lists of commitments and sums the first set and subtracts the second and verifies that they sum to excess. */
int secp256k1_pedersen_verify_tally(const secp256k1_context* ctx, const secp256k1_pedersen_commitment * const* commits, size_t pcnt, const secp256k1_pedersen_commitment * const* ncommits, size_t ncnt) {
    secp256k1_gej accj;
    secp256k1_ge add;
    size_t i;
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(!pcnt || (commits != NULL));
    ARG_CHECK(!ncnt || (ncommits != NULL));
    secp256k1_gej_set_infinity(&accj);
    for (i = 0; i < ncnt; i++) {
        secp256k1_pedersen_commitment_load(&add, ncommits[i]);
        secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    secp256k1_gej_neg(&accj, &accj);
    for (i = 0; i < pcnt; i++) {
        secp256k1_pedersen_commitment_load(&add, commits[i]);
        secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    return secp256k1_gej_is_infinity(&accj);
}

int secp256k1_pedersen_blind_generator_blind_sum(const secp256k1_context* ctx, const uint64_t *value, const unsigned char* const* generator_blind, unsigned char* const* blinding_factor, size_t n_total, size_t n_inputs) {
    secp256k1_scalar sum;
    secp256k1_scalar tmp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(n_total == 0 || value != NULL);
    ARG_CHECK(n_total == 0 || generator_blind != NULL);
    ARG_CHECK(n_total == 0 || blinding_factor != NULL);
    ARG_CHECK(n_total > n_inputs);
    (void) ctx;

    if (n_total == 0) {
        return 1;
    }

    secp256k1_scalar_set_int(&sum, 0);
    for (i = 0; i < n_total; i++) {
        int overflow = 0;
        secp256k1_scalar addend;
        secp256k1_scalar_set_u64(&addend, value[i]);  /* s = v */

        secp256k1_scalar_set_b32(&tmp, generator_blind[i], &overflow);
        if (overflow == 1) {
            secp256k1_scalar_clear(&tmp);
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&sum);
            return 0;
        }
        secp256k1_scalar_mul(&addend, &addend, &tmp); /* s = vr */

        secp256k1_scalar_set_b32(&tmp, blinding_factor[i], &overflow);
        if (overflow == 1) {
            secp256k1_scalar_clear(&tmp);
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&sum);
            return 0;
        }
        secp256k1_scalar_add(&addend, &addend, &tmp); /* s = vr + r' */
        secp256k1_scalar_cond_negate(&addend, i < n_inputs);  /* s is negated if it's an input */
        secp256k1_scalar_add(&sum, &sum, &addend);    /* sum += s */
        secp256k1_scalar_clear(&addend);
    }

    /* Right now tmp has the last pedersen blinding factor. Subtract the sum from it. */
    secp256k1_scalar_negate(&sum, &sum);
    secp256k1_scalar_add(&tmp, &tmp, &sum);
    secp256k1_scalar_get_b32(blinding_factor[n_total - 1], &tmp);

    secp256k1_scalar_clear(&tmp);
    secp256k1_scalar_clear(&sum);
    return 1;
}

int secp256k1_rangeproof_info(const secp256k1_context* ctx, int *exp, int *mantissa,
 uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen) {
    size_t offset;
    uint64_t scale;
    ARG_CHECK(exp != NULL);
    ARG_CHECK(mantissa != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    offset = 0;
    scale = 1;
    (void)ctx;
    return secp256k1_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}

int secp256k1_rangeproof_rewind(const secp256k1_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 0);
    return secp256k1_rangeproof_verify_impl(&ctxp,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, NULL, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_verify(const secp256k1_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 0);
    return secp256k1_rangeproof_verify_impl(&ctxp,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, NULL, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_sign(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen){
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge genp;
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 0);
    return secp256k1_rangeproof_sign_impl(&ctxp,
     proof, plen, min_value, &commitp, NULL, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

static void secp256k1_elgamal_commitment_load(secp256k1_ge* ge, secp256k1_ge* ge2, const secp256k1_elgamal_commitment* commit) {
    secp256k1_fe fe;
    secp256k1_fe_set_b32(&fe, &commit->data[1]);
    secp256k1_ge_set_xquad(ge, &fe);
    secp256k1_fe_set_b32(&fe, &commit->data[33]);
    secp256k1_ge_set_xquad(ge2, &fe);
    if (commit->data[0] & 1) {
        secp256k1_ge_neg(ge, ge);
    }
    if (commit->data[0] & 2) {
        secp256k1_ge_neg(ge2, ge2);
    }
}

static void secp256k1_elgamal_commitment_save(secp256k1_elgamal_commitment* commit, secp256k1_ge* ge, secp256k1_ge* ge2) {
    secp256k1_fe_normalize(&ge->x);
    secp256k1_fe_normalize(&ge2->x);
    secp256k1_fe_get_b32(&commit->data[1], &ge->x);
    secp256k1_fe_get_b32(&commit->data[33], &ge2->x);
    commit->data[0] = 27 ^ secp256k1_fe_is_quad_var(&ge->y) ^ (secp256k1_fe_is_quad_var(&ge2->y) << 1);
}

int secp256k1_elgamal_commit(const secp256k1_context* ctx, secp256k1_elgamal_commitment *commit, const unsigned char *blind, uint64_t value, const secp256k1_generator* asset_gen) {
    secp256k1_ge asset_genp;
    secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(asset_gen != NULL);
    secp256k1_generator_load(&asset_genp, asset_gen);
    secp256k1_scalar_set_b32(&sec, blind, &overflow);
    if (!overflow) {
        secp256k1_gej rj;
        secp256k1_ge r1;
        secp256k1_ge r2;
        secp256k1_pedersen_ecmult(&ctx->ecmult_gen_ctx, &rj, &sec, value, &asset_genp);
        if (!secp256k1_gej_is_infinity(&rj)) {
            secp256k1_ge_set_gej(&r1, &rj);
            ret = 1;
        }
        secp256k1_ecmult_gen(&ctx->alt_ecmult_gen_ctx, &rj, &sec);
        if (ret && !secp256k1_gej_is_infinity(&rj)) {
            secp256k1_ge_set_gej(&r2, &rj);
            secp256k1_elgamal_commitment_save(commit, &r1, &r2);
        }
        secp256k1_gej_clear(&rj);
        secp256k1_ge_clear(&r1);
        secp256k1_ge_clear(&r2);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_elgamal_rangeproof_rewind(const secp256k1_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const secp256k1_elgamal_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge commitp2;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ctx->ndigits > 0);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    secp256k1_elgamal_commitment_load(&commitp, &commitp2, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 1);
    return secp256k1_rangeproof_verify_impl(&ctxp,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, &commitp2, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_elgamal_rangeproof_verify(const secp256k1_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const secp256k1_elgamal_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge commitp2;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ctx->ndigits > 0);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    secp256k1_elgamal_commitment_load(&commitp, &commitp2, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 1);
    return secp256k1_rangeproof_verify_impl(&ctxp,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, &commitp2, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_elgamal_rangeproof_sign(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_elgamal_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen){
    secp256k1_rangeproof_context_pointers ctxp;
    secp256k1_ge commitp;
    secp256k1_ge commitp2;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ctx->ndigits > 0);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    secp256k1_elgamal_commitment_load(&commitp, &commitp2, commit);
    secp256k1_generator_load(&genp, gen);
    secp256k1_context_to_rangeproof(&ctxp, ctx, 1);
    return secp256k1_rangeproof_sign_impl(&ctxp,
     proof, plen, min_value, &commitp, &commitp2, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

#endif
