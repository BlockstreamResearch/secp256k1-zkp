/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "group.h"

#include "modules/rangeproof/pedersen_impl.h"
#include "modules/rangeproof/borromean_impl.h"
#include "modules/rangeproof/rangeproof_impl.h"

/** Alternative generator for secp256k1.
 *  This is the sha256 of 'g' after standard encoding (without compression),
 *  which happens to be a point on the curve. More precisely, the generator is
 *  derived by running the following script with the sage mathematics software.

    import hashlib
    F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    G = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    H = EllipticCurve ([F (0), F (7)]).lift_x(F(int(hashlib.sha256(G.decode('hex')).hexdigest(),16)))
    print('%x %x' % H.xy())
 */
static const secp256k1_generator secp256k1_generator_h_internal = {{
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
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
    secp256k1_fe x;
    secp256k1_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(input != NULL);
    (void) ctx;

    if ((input[0] & 0xFE) != 8 ||
        !secp256k1_fe_set_b32(&x, &input[1]) ||
        !secp256k1_ge_set_xquad(&ge, &x)) {
        return 0;
    }
    if (input[0] & 1) {
        secp256k1_ge_neg(&ge, &ge);
    }
    secp256k1_pedersen_commitment_save(commit, &ge);
    return 1;
}

int secp256k1_pedersen_commitment_serialize(const secp256k1_context* ctx, unsigned char *output, const secp256k1_pedersen_commitment* commit) {
    secp256k1_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(commit != NULL);

    secp256k1_pedersen_commitment_load(&ge, commit);

    output[0] = 9 ^ secp256k1_fe_is_quad_var(&ge.y);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_get_b32(&output[1], &ge.x);
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
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(gen != NULL);
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
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(blind_out != NULL);
    ARG_CHECK(blinds != NULL);
    ARG_CHECK(npositive <= n);
    (void) ctx;
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
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(!pcnt || (commits != NULL));
    ARG_CHECK(!ncnt || (ncommits != NULL));
    (void) ctx;
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
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_verify(const secp256k1_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen) {
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(&ctx->ecmult_ctx, NULL,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_sign(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen){
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
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_sign_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

size_t secp256k1_ring_signature_length(const secp256k1_context* ctx, size_t n_keys) {
    (void) ctx;
    if (SIZE_MAX / 32 < n_keys + 1)
        return 0;
    return 32 * (n_keys + 1);
}

size_t secp256k1_ring_signature_scratch_space_size(const secp256k1_context* ctx, size_t n_keys) {
    (void) ctx;
    if (SIZE_MAX / (sizeof(secp256k1_gej) + sizeof(secp256k1_scalar)) < n_keys) {
        return 0;
    } else {
        size_t gej_len = ROUND_TO_ALIGN(sizeof(secp256k1_gej) * n_keys);
        size_t sca_len = ROUND_TO_ALIGN(sizeof(secp256k1_scalar) * n_keys);
        if (gej_len + sca_len < gej_len) {
            return 0;
        }
        return gej_len + sca_len;
    }
}

int secp256k1_ring_sign(const secp256k1_context* ctx, secp256k1_scratch_space* scratch, unsigned char* sig, size_t* sig_len, unsigned char* author_proof, const secp256k1_pubkey* pubkeys, size_t n_pubkeys, const unsigned char *sec_key, size_t sec_idx, const unsigned char *nonce, const unsigned char *message) {
    size_t scratch_checkpoint;
    secp256k1_rfc6979_hmac_sha256 rng;
    int overflow;
    secp256k1_scalar x;
    secp256k1_scalar k;
    secp256k1_scalar *s;
    secp256k1_gej *pubs;
    secp256k1_sha256 sha2eng;
    unsigned char buf[32];
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sig_len != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(sec_key != NULL);
    ARG_CHECK(message != NULL);

    /* Check for overflow, or 0 pubkeys (which is technically ok but probably
     * more confusing than meaningful) */
    if (secp256k1_ring_signature_length(ctx, n_pubkeys) == 0 || secp256k1_ring_signature_scratch_space_size(ctx, n_pubkeys) == 0) {
        return 0;
    }
    if (*sig_len >= secp256k1_ring_signature_length(ctx, n_pubkeys)) {
        *sig_len = secp256k1_ring_signature_length(ctx, n_pubkeys);
    } else {
        return 0;
    }

    secp256k1_scalar_set_b32(&x, sec_key, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        return 0;
    }

    /* Directly derive `k` from the nonce */
    secp256k1_sha256_initialize(&sha2eng);
    secp256k1_sha256_write(&sha2eng, (unsigned char*)"ringsig/k", 9);
    secp256k1_sha256_finalize(&sha2eng, buf);

    secp256k1_sha256_initialize(&sha2eng);
    secp256k1_sha256_write(&sha2eng, buf, 32);
    secp256k1_sha256_write(&sha2eng, buf, 32);
    secp256k1_sha256_write(&sha2eng, sec_key, 32);
    secp256k1_sha256_write(&sha2eng, message, 32);
    if (nonce != NULL) {
        secp256k1_sha256_write(&sha2eng, nonce, 32);
    }
    secp256k1_sha256_finalize(&sha2eng, buf);

    secp256k1_scalar_set_b32(&k, buf, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    /* Use a different tagged hash to get a seed for the `s` values */
    secp256k1_sha256_initialize(&sha2eng);
    secp256k1_sha256_write(&sha2eng, (unsigned char*)"ringsig/s", 9);
    secp256k1_sha256_finalize(&sha2eng, buf);

    secp256k1_sha256_initialize(&sha2eng);
    secp256k1_sha256_write(&sha2eng, buf, 32);
    secp256k1_sha256_write(&sha2eng, buf, 32);
    secp256k1_sha256_write(&sha2eng, sec_key, 32);
    secp256k1_sha256_write(&sha2eng, message, 32);
    if (nonce != NULL) {
        secp256k1_sha256_write(&sha2eng, nonce, 32);
    }
    secp256k1_sha256_finalize(&sha2eng, buf);

    if (author_proof != NULL) {
        memcpy(author_proof, buf, 32);
    }

    /* Generate s values from the author proof (and unpack pubkeys while we're at it) */
    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    s = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, n_pubkeys * sizeof(*s));
    pubs = (secp256k1_gej*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, n_pubkeys * sizeof(*pubs));
    if (s == NULL || pubs == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, buf, 32);
    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_ge pubp;
        CHECK (secp256k1_pubkey_load(ctx, &pubp, &pubkeys[i]));
        secp256k1_gej_set_ge(&pubs[i], &pubp);

        do {
            secp256k1_rfc6979_hmac_sha256_generate(&rng, buf, 32);
            secp256k1_scalar_set_b32(&s[i], buf, &overflow);
        } while (overflow || secp256k1_scalar_is_zero(&s[i]));
    }

    /* Produce the proof -- will update the `s` array and output `e0` in `buf` */
    if (!secp256k1_borromean_sign(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx, buf, s, pubs, &k, &x, &n_pubkeys, &sec_idx, 1, message, 32)) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);

    /* Serialize it */
    memcpy(sig, buf, 32);
    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_scalar_get_b32(&sig[32 * (1 + i)], &s[i]);
    }

    return 1;
}

int secp256k1_ring_verify(const secp256k1_context* ctx, secp256k1_scratch_space* scratch, const unsigned char* sig, size_t sig_len, const secp256k1_pubkey* pubkeys, size_t n_pubkeys, const unsigned char *message) {
    size_t scratch_checkpoint;
    secp256k1_scalar *s;
    secp256k1_gej *pubs;
    size_t i;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(message != NULL);

    /* Check for overflow, or 0 pubkeys (which is technically ok but probably
     * more confusing than meaningful) */
    if (secp256k1_ring_signature_length(ctx, n_pubkeys) == 0 || secp256k1_ring_signature_scratch_space_size(ctx, n_pubkeys) == 0) {
        return 0;
    }
    if (sig_len != secp256k1_ring_signature_length(ctx, n_pubkeys)) {
        return 0;
    }

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    s = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, n_pubkeys * sizeof(*s));
    pubs = (secp256k1_gej*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, n_pubkeys * sizeof(*pubs));
    if (s == NULL || pubs == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_ge pubp;
        CHECK (secp256k1_pubkey_load(ctx, &pubp, &pubkeys[i]));
        secp256k1_gej_set_ge(&pubs[i], &pubp);

        secp256k1_scalar_set_b32(&s[i], &sig[32 * (1 + i)], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&s[i])) {
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
    }

    if (!secp256k1_borromean_verify(&ctx->ecmult_ctx, NULL, sig, s, pubs, &n_pubkeys, 1, message, 32)) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
    return 1;
}

int secp256k1_ring_deanonymize(const secp256k1_context* ctx, size_t *author_idx, const unsigned char* sig, size_t sig_len, const unsigned char* author_proof, const secp256k1_pubkey* pubkeys, size_t n_pubkeys) {
    secp256k1_rfc6979_hmac_sha256 rng;
    int found = 0;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(author_idx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(author_proof != NULL);
    ARG_CHECK(pubkeys != NULL);

    if (sig_len == 0 || sig_len != secp256k1_ring_signature_length(ctx, n_pubkeys)) {
        return 0;
    }

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, author_proof, 32);
    for (i = 0; i < n_pubkeys; i++) {
        unsigned char buf[32];
        secp256k1_scalar ref;
        int overflow;

        do {
            secp256k1_rfc6979_hmac_sha256_generate(&rng, buf, 32);
            secp256k1_scalar_set_b32(&ref, buf, &overflow);
        } while (overflow || secp256k1_scalar_is_zero(&ref));

        /* FIXME this should not be var-time since author_proof may be secret */
        if (secp256k1_memcmp_var(&sig[32 * (i + 1)], buf, 32) != 0) {
            if (found == 1) {
                return 0;
            }
            found = 1;
            *author_idx = i;
        }
    }

    return 1;
}

#endif
