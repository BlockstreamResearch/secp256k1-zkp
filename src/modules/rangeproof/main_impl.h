/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "../../group.h"

#include "pedersen_impl.h"
#include "borromean_impl.h"
#include "rangeproof_impl.h"

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

    /* Here, n_total > 0. Thus the loop runs at least once.
       Thus we may use a do-while loop, which checks the loop
       condition only at the end.

       The do-while loop helps GCC prove that the loop runs at least
       once and suppresses a -Wmaybe-uninitialized warning. */
    i = 0;
    do {
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

        i++;
    } while (i < n_total);

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
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(&ctx->ecmult_gen_ctx,
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
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_impl(NULL,
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
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_sign_impl(&ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

int secp256k1_rangeproof_verify_exact(const secp256k1_context* ctx, const unsigned char* proof, size_t plen, uint64_t value, const secp256k1_pedersen_commitment* commit, const secp256k1_generator* gen) {
    secp256k1_ge commitp;
    secp256k1_ge genp;
    secp256k1_gej tmpj;
    secp256k1_gej xj;
    secp256k1_ge rp;
    secp256k1_scalar es;
    secp256k1_scalar ss;
    secp256k1_sha256 sha2;
    unsigned char tmpch[33];
    unsigned char pp_comm[32];
    size_t offset;
    size_t sz;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(gen != NULL);

    if (plen != 73 && plen != 65) {
        return 0;
    }
    /* 0x80 must be unset for any rangeproof; 0x40 indicates "has nonzero range"
     * so must also be unset for single-value proofs */
    if ((proof[0] & 0xC0) != 0x00) {
        return 0;
    }

    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    /* Verify that value in the header is what we expect; 0x20 is "has nonzero min-value" */
    if ((proof[0] & 0x20) == 0x00) {
        if (value != 0) {
            return 0;
        }
        offset = 1;
    } else {
        uint64_t claimed = 0;
        /* Iterate from 0 to 8, setting `offset` to 9 as a side-effect */
        for (offset = 1; offset < 9; offset++) {
            claimed = (claimed << 8) | proof[offset];
        }
        if (value != claimed) {
            return 0;
        }
    }
    /* Subtract value from commitment; store modified commitment in xj */
    secp256k1_pedersen_ecmult_small(&tmpj, value, &genp);
    secp256k1_gej_neg(&tmpj, &tmpj);
    secp256k1_gej_add_ge_var(&xj, &tmpj, &commitp, NULL);

    /* Now we just have a Schnorr signature in (e, s) form. The verification
     * equation is e == H(sG - eX || proof params) */

    /* 0. Compute slow/overwrought commitment to proof params */
    secp256k1_sha256_initialize(&sha2);
    secp256k1_rangeproof_serialize_point(tmpch, &commitp);
    secp256k1_sha256_write(&sha2, tmpch, 33);
    secp256k1_rangeproof_serialize_point(tmpch, &genp);
    secp256k1_sha256_write(&sha2, tmpch, 33);
    secp256k1_sha256_write(&sha2, proof, offset);
    secp256k1_sha256_finalize(&sha2, pp_comm);

    /* ... feed this into our hash */
    secp256k1_borromean_hash(tmpch, pp_comm, 32, &proof[offset], 32, 0, 0);
    secp256k1_scalar_set_b32(&es, tmpch, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&es)) {
        return 0;
    }

    /* 1. Compute R = sG + eX */
    secp256k1_scalar_set_b32(&ss, &proof[offset + 32], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&ss)) {
        return 0;
    }
    secp256k1_ecmult(&tmpj, &xj, &es, &ss);
    if (secp256k1_gej_is_infinity(&tmpj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&rp, &tmpj);
    secp256k1_eckey_pubkey_serialize(&rp, tmpch, &sz, 1);

    /* 2. Compute e = H(R || proof params) */
    secp256k1_sha256_initialize(&sha2);
    secp256k1_sha256_write(&sha2, tmpch, sz);
    secp256k1_sha256_write(&sha2, pp_comm, sizeof(pp_comm));
    secp256k1_sha256_finalize(&sha2, tmpch);

    /* 3. Check computed e against original e */
    return !secp256k1_memcmp_var(tmpch, &proof[offset], 32);
}

int secp256k1_rangeproof_create_exact(const secp256k1_context* ctx, unsigned char* proof, size_t* plen, uint64_t value, const unsigned char* blind, const secp256k1_pedersen_commitment* commit, const secp256k1_generator* gen) {
    secp256k1_ge commitp;
    secp256k1_ge genp;
    secp256k1_gej tmpj;
    secp256k1_ge tmpp;
    secp256k1_scalar es;
    secp256k1_scalar ks;
    secp256k1_scalar xs;
    secp256k1_sha256 sha2;
    unsigned char tmpch[33];
    unsigned char pp_comm[32];
    size_t offset;
    size_t sz;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(gen != NULL);

    if (*plen < (value == 0 ? 65 : 73)) {
        return 0;
    }
    *plen = value == 0 ? 65 : 73;

    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);

    /* Encode header */
    if (value > 0) {
        proof[0] = 0x20;
        proof[1] = value >> 56;
        proof[2] = value >> 48;
        proof[3] = value >> 40;
        proof[4] = value >> 32;
        proof[5] = value >> 24;
        proof[6] = value >> 16;
        proof[7] = value >> 8;
        proof[8] = value;
        offset = 9;
    } else {
        proof[0] = 0x00;
        offset = 1;
    }

    /* Now we have to make a Schnorr signature in (e, s) form. */

    /* 1. Compute slow/overwrought commitment to proof params */
    secp256k1_sha256_initialize(&sha2);
    secp256k1_rangeproof_serialize_point(tmpch, &commitp);
    secp256k1_sha256_write(&sha2, tmpch, 33);
    secp256k1_rangeproof_serialize_point(tmpch, &genp);
    secp256k1_sha256_write(&sha2, tmpch, 33);
    secp256k1_sha256_write(&sha2, proof, offset);
    secp256k1_sha256_finalize(&sha2, pp_comm);

    /* 2. Compute random k */
    secp256k1_sha256_initialize(&sha2);
    secp256k1_sha256_write(&sha2, blind, 32);
    secp256k1_sha256_write(&sha2, proof, offset);
    secp256k1_sha256_write(&sha2, pp_comm, 32);
    secp256k1_sha256_finalize(&sha2, tmpch);
    secp256k1_scalar_set_b32(&ks, tmpch, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&ks)) {
        secp256k1_scalar_clear(&ks);
        memset(tmpch, 0, sizeof(tmpch));
        return 0;
    }

    /* 3. Compute R = kG */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmpj, &ks);
    secp256k1_ge_set_gej(&tmpp, &tmpj);

    /* 4. Compute e0 = H(R || proof params) and serialize it into the proof */
    secp256k1_sha256_initialize(&sha2);
    secp256k1_eckey_pubkey_serialize(&tmpp, tmpch, &sz, 1);
    secp256k1_sha256_write(&sha2, tmpch, sz);
    secp256k1_sha256_write(&sha2, pp_comm, sizeof(pp_comm));
    secp256k1_sha256_finalize(&sha2, &proof[offset]);

    /* ... feed this into our hash e, along with e0 */
    secp256k1_borromean_hash(tmpch, pp_comm, 32, &proof[offset], 32, 0, 0);
    secp256k1_scalar_set_b32(&es, tmpch, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&es)) {
        secp256k1_scalar_clear(&ks);
        secp256k1_scalar_clear(&es);
        return 0;
    }

    /* 5. Compute k - ex from this, and serialize it */
    secp256k1_scalar_set_b32(&xs, blind, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&xs)) {
        secp256k1_scalar_clear(&ks);
        secp256k1_scalar_clear(&xs);
        secp256k1_scalar_clear(&es);
        return 0;
    }
    secp256k1_scalar_mul(&es, &es, &xs);
    secp256k1_scalar_negate(&es, &es);
    secp256k1_scalar_add(&es, &es, &ks);
    secp256k1_scalar_get_b32(&proof[offset + 32], &es);

    secp256k1_scalar_clear(&ks);
    secp256k1_scalar_clear(&xs);
    return 1;
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

#endif
