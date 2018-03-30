/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL
#define SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL

#include "group.h"
#include "scalar.h"

#include "include/secp256k1_bulletproofs.h"
#include "modules/commitment/main_impl.h"

typedef struct {
    int special;
    secp256k1_scalar scal;
} secp256k1_fast_scalar;

typedef struct {
    size_t idx;
    secp256k1_fast_scalar scal;
} secp256k1_bulletproof_wmatrix_entry;

typedef struct {
    size_t size;
    secp256k1_bulletproof_wmatrix_entry *entry;
} secp256k1_bulletproof_wmatrix_row;

struct secp256k1_bulletproof_circuit {
    size_t n_gates; /* n */
    size_t n_commits; /* m */
    size_t n_constraints; /* Q */
    size_t n_bits; /* number of implicit bit-constraints */
    secp256k1_bulletproof_wmatrix_row *wl;
    secp256k1_bulletproof_wmatrix_row *wr;
    secp256k1_bulletproof_wmatrix_row *wo;
    secp256k1_bulletproof_wmatrix_row *wv;
    secp256k1_fast_scalar *c;

    secp256k1_bulletproof_wmatrix_entry *entries;
};

struct secp256k1_bulletproof_circuit_assignment {
    size_t n_gates;
    size_t n_commits;
    secp256k1_scalar *al;
    secp256k1_scalar *ar;
    secp256k1_scalar *ao;
    secp256k1_scalar *v;
};

struct secp256k1_bulletproof_generators {
    size_t n;
    /* `G_i`, `H_i` generators, `n` each of them which are generated when creating this struct */
    secp256k1_ge *gens;
    /* `H` "alternate" generator, used in Pedersen commitments. Passed in by caller to
     * `secp256k1_bulletproof_generators_create`; stored in this structure to allow consistent
     * generators between functions using `secp256k1_bulletproof_generators` and functions
     * using the Pedersen commitment module. */
    secp256k1_ge *blinding_gen;
};

#include "modules/bulletproofs/parser_impl.h"
#include "modules/bulletproofs/inner_product_impl.h"
#include "modules/bulletproofs/circuit_compress_impl.h"
#include "modules/bulletproofs/circuit_impl.h"
#include "modules/bulletproofs/rangeproof_impl.h"
#include "modules/bulletproofs/util.h"

secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(const secp256k1_context *ctx, const secp256k1_generator *blinding_gen, size_t n) {
    secp256k1_bulletproof_generators *ret;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    secp256k1_gej precompj;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(blinding_gen != NULL);

    ret = (secp256k1_bulletproof_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge *)checked_malloc(&ctx->error_callback, (n + 1) * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->blinding_gen = &ret->gens[n];
    ret->n = n;

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        unsigned char tmp[32] = { 0 };
        secp256k1_generator gen;
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);

        secp256k1_gej_set_ge(&precompj, &ret->gens[i]);
    }

    secp256k1_generator_load(&ret->blinding_gen[0], blinding_gen);
    secp256k1_gej_set_ge(&precompj, &ret->blinding_gen[0]);

    return ret;
}

void secp256k1_bulletproof_generators_destroy(const secp256k1_context* ctx, secp256k1_bulletproof_generators *gens) {
    (void) ctx;
    if (gens != NULL) {
        free(gens->gens);
        free(gens);
    }
}

int secp256k1_bulletproof_rangeproof_verify(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const unsigned char *proof, size_t plen,
 const uint64_t *min_value, const secp256k1_pedersen_commitment* commit, size_t n_commits, size_t nbits, const secp256k1_generator *value_gen, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    size_t i;
    secp256k1_ge *commitp;
    secp256k1_ge value_genp;
    const secp256k1_ge *commitp_ptr;
    const uint64_t *minvalue_ptr;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(n_commits > 0);
    ARG_CHECK(nbits > 0);
    ARG_CHECK(nbits <= 64);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, 2 * n_commits * sizeof(secp256k1_ge), 1)) {
        return 0;
    }

    commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(secp256k1_ge));
    for (i = 0; i < n_commits; i++) {
        secp256k1_pedersen_commitment_load(&commitp[i], &commit[i]);
    }
    secp256k1_generator_load(&value_genp, value_gen);

    commitp_ptr = commitp;
    minvalue_ptr = min_value;
    ret = secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, &proof, 1, plen, nbits, &minvalue_ptr, &commitp_ptr, n_commits, &value_genp, gens, &extra_commit, &extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

int secp256k1_bulletproof_rangeproof_verify_multi(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const unsigned char* const* proof, size_t n_proofs, size_t plen, const uint64_t* const* min_value, const secp256k1_pedersen_commitment* const* commit, size_t n_commits, size_t nbits, const secp256k1_generator *value_gen, const unsigned char* const* extra_commit, size_t *extra_commit_len) {
    int ret;
    secp256k1_ge **commitp;
    secp256k1_ge *value_genp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(n_proofs > 0);
    ARG_CHECK(n_commits > 0);
    ARG_CHECK(nbits > 0);
    ARG_CHECK(nbits <= 64);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK((extra_commit_len == NULL) == (extra_commit == NULL));
    if (extra_commit != NULL) {
        for (i = 0; i < n_proofs; i++) {
            ARG_CHECK(extra_commit[i] != NULL || extra_commit_len[i] == 0);
        }
    }
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, n_proofs * (sizeof(*value_genp) + sizeof(*commitp) + n_commits * sizeof(**commitp)), 1 + n_proofs)) {
        return 0;
    }

    commitp = (secp256k1_ge **)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*commitp));
    value_genp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*value_genp));
    for (i = 0; i < n_proofs; i++) {
        size_t j;
        commitp[i] = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp[i]));
        for (j = 0; j < n_commits; j++) {
            secp256k1_pedersen_commitment_load(&commitp[i][j], &commit[i][j]);
        }
        secp256k1_generator_load(&value_genp[i], &value_gen[i]);
    }

    ret = secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, proof, n_proofs, plen, nbits, min_value, (const secp256k1_ge **) commitp, n_commits, value_genp, gens, extra_commit, extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

int secp256k1_bulletproof_rangeproof_rewind(const secp256k1_context* ctx, const secp256k1_bulletproof_generators *gens, uint64_t *value, unsigned char *blind, const unsigned char *proof, size_t plen, uint64_t min_value, const secp256k1_pedersen_commitment* commit, const secp256k1_generator *value_gen, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len) {
    secp256k1_scalar blinds;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(value != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);

    ret = secp256k1_bulletproof_rangeproof_rewind_impl(value, &blinds, proof, plen, min_value, commit, value_gen, gens->blinding_gen, nonce, extra_commit, extra_commit_len);
    if (ret == 1) {
        secp256k1_scalar_get_b32(blind, &blinds);
    }
    return ret;
}

int secp256k1_bulletproof_rangeproof_prove(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, unsigned char *proof, size_t *plen, const uint64_t *value, const uint64_t *min_value, const unsigned char* const* blind, size_t n_commits, const secp256k1_generator *value_gen, size_t nbits, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    secp256k1_ge *commitp;
    secp256k1_scalar *blinds;
    secp256k1_ge value_genp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(value != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(n_commits > 0 && n_commits);
    ARG_CHECK(nbits <= 64);
    if (nbits < 64) {
        for (i = 0; i < n_commits; i++) {
            ARG_CHECK(value[i] < (1ull << nbits));
            ARG_CHECK(blind[i] != NULL);
        }
    }
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, n_commits * (sizeof(*commitp) + sizeof(*blinds)), 2)) {
        return 0;
    }
    commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp));
    blinds = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*blinds));

    secp256k1_generator_load(&value_genp, value_gen);
    for (i = 0; i < n_commits; i++) {
        int overflow;
        secp256k1_gej commitj;
        secp256k1_scalar_set_b32(&blinds[i], blind[i], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&blinds[i])) {
            return 0;
        }
        secp256k1_pedersen_ecmult(&commitj, &blinds[i], value[i], &value_genp, &gens->blinding_gen[0]);
        secp256k1_ge_set_gej(&commitp[i], &commitj);
    }

    ret = secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_ctx, scratch, proof, plen, nbits, value, min_value, blinds, commitp, n_commits, &value_genp, gens, nonce, extra_commit, extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

secp256k1_bulletproof_circuit *secp256k1_bulletproof_circuit_parse(const secp256k1_context *ctx, const char *description) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(description != NULL);
    return secp256k1_parse_circuit(ctx, description);
}

int secp256k1_bulletproof_circuit_prove(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const secp256k1_bulletproof_circuit *circ, unsigned char *proof, size_t *plen, const secp256k1_bulletproof_circuit_assignment *assn, const unsigned char** blind, size_t n_commits, const unsigned char *nonce, const secp256k1_generator *value_gen, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    secp256k1_ge value_genp;
    secp256k1_ge *commitp;
    secp256k1_scalar *blinds;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(circ != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * circ->n_gates);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(assn != NULL);
    ARG_CHECK(blind != NULL || n_commits == 0);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);

    if (assn->n_commits != circ->n_commits) {
        return 0;
    }

    secp256k1_generator_load(&value_genp, value_gen);
    if (n_commits == 0) {
        commitp = NULL;
        blinds = NULL;
    } else {
        size_t i;
        if (!secp256k1_scratch_allocate_frame(scratch, n_commits * (sizeof(*commitp) + sizeof(*blinds)), 2)) {
            return 0;
        }
        commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp));
        blinds = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*blinds));
        for (i = 0; i < n_commits; i++) {
            int overflow;
            secp256k1_gej commitj;
            secp256k1_scalar_set_b32(&blinds[i], blind[i], &overflow);
            if (overflow || secp256k1_scalar_is_zero(&blinds[i])) {
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            secp256k1_pedersen_ecmult_scalar(&commitj, &blinds[i], &assn->v[i], &value_genp, gens->blinding_gen);
            secp256k1_ge_set_gej(&commitp[i], &commitj);
        }
    }

    ret = secp256k1_bulletproof_relation66_prove_impl(
        &ctx->ecmult_ctx,
        scratch,
        proof, plen,
        assn,
        commitp, blinds, n_commits,
        &value_genp,
        circ,
        gens,
        nonce,
        extra_commit, extra_commit_len
    );
    if (n_commits != 0) {
        secp256k1_scratch_deallocate_frame(scratch);
    }
    return ret;
}

int secp256k1_bulletproof_circuit_verify(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const secp256k1_bulletproof_circuit *circ, const unsigned char *proof, size_t plen, const secp256k1_pedersen_commitment* commit, size_t n_commits, const secp256k1_generator *value_gen, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    secp256k1_ge value_genp;
    secp256k1_ge *commitp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(circ != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * circ->n_gates);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);

    secp256k1_generator_load(&value_genp, value_gen);
    if (n_commits == 0) {
        commitp = NULL;
    } else {
        size_t i;
        if (!secp256k1_scratch_allocate_frame(scratch, n_commits * sizeof(*commitp), 1)) {
            return 0;
        }
        commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp));
        for (i = 0; i < n_commits; i++) {
            secp256k1_pedersen_commitment_load(&commitp[i], &commit[i]);
        }
    }

    ret = secp256k1_bulletproof_relation66_verify_impl(
        &ctx->ecmult_ctx,
        scratch,
        &proof, 1, plen,
        (const secp256k1_ge* const*)&commitp, n_commits == 0 ? NULL : &n_commits,
        &value_genp,
        &circ,
        gens,
        &extra_commit, &extra_commit_len
    );
    if (n_commits != 0) {
        secp256k1_scratch_deallocate_frame(scratch);
    }
    return ret;
}

int secp256k1_bulletproof_circuit_verify_multi(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const secp256k1_bulletproof_circuit* const* circ, const unsigned char* const* proof, size_t n_proofs, size_t plen, const secp256k1_pedersen_commitment** commit, size_t *n_commits, const secp256k1_generator *value_gen, const unsigned char **extra_commit, size_t *extra_commit_len) {
    secp256k1_ge value_genp;
    secp256k1_ge **commitp;
    size_t i;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(circ != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * circ[0]->n_gates);
    ARG_CHECK(value_gen != NULL);
    ARG_CHECK((extra_commit_len == NULL) == (extra_commit == NULL));
    if (extra_commit != NULL) {
        for (i = 0; i < n_proofs; i++) {
            ARG_CHECK(extra_commit[i] != NULL || extra_commit_len[i] == 0);
        }
    }

    for (i = 1; i < n_proofs; i++) {
        ARG_CHECK(circ[i]->n_gates == circ[0]->n_gates);
    }

    if (n_commits == NULL) {
        commitp = NULL;
    } else {
        size_t total_n_commits = 0;
        for (i = 0; i < n_proofs; i++) {
            total_n_commits += n_commits[i];
        }

        if (!secp256k1_scratch_allocate_frame(scratch, sizeof(*commitp) + total_n_commits * sizeof(**commitp), 1 + n_proofs)) {
            return 0;
        }
        commitp = (secp256k1_ge **)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*commitp));
        for (i = 0; i < n_proofs; i++) {
            size_t j;
            commitp[i] = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits[i] * sizeof(*commitp[i]));
            for (j = 0; j < n_commits[i]; j++) {
                secp256k1_pedersen_commitment_load(&commitp[i][j], &commit[i][j]);
            }
        }
    }

    secp256k1_generator_load(&value_genp, value_gen);
    ret = secp256k1_bulletproof_relation66_verify_impl(
        &ctx->ecmult_ctx,
        scratch,
        proof, n_proofs, plen,
        (const secp256k1_ge* const*)commitp, n_commits,
        &value_genp,
        circ,
        gens,
        extra_commit, extra_commit_len
    );
    if (n_commits != NULL) {
        secp256k1_scratch_deallocate_frame(scratch);
    }
    return ret;
}

secp256k1_bulletproof_circuit *secp256k1_bulletproof_circuit_decode(const secp256k1_context *ctx, const char *fname) {
    FILE *fh;
    unsigned char buf[0x3f];
    size_t n;
    size_t row_width;
    secp256k1_bulletproof_circuit *ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(fname != NULL);

    fh = fopen(fname, "rb");
    if (fh == NULL) {
        return NULL;
    }

    /* Read header and allocate memory */
    if (secp256k1_bulletproof_circuit_allocate_memory(ctx, fh, &ret) != 1) {
        fclose(fh);
        return NULL;
    }
    row_width = secp256k1_bulletproof_encoding_width(ret->n_gates);

    /* Read matrices */
    n = 0;
    if (secp256k1_bulletproof_matrix_decode(fh, ret->wl, ret->entries, &n, ret->n_gates, row_width) != 1 ||
        secp256k1_bulletproof_matrix_decode(fh, ret->wr, ret->entries, &n, ret->n_gates, row_width) != 1 ||
        secp256k1_bulletproof_matrix_decode(fh, ret->wo, ret->entries, &n, ret->n_gates, row_width) != 1 ||
        secp256k1_bulletproof_matrix_decode(fh, ret->wv, ret->entries, &n, ret->n_commits, row_width) != 1) {
        goto fail;
    }

    /* Negate every entry of the WV matrix since it is on the opposite side of the
     * circuit equation from the WL/WR/WO matrices */
    for (n = 0; n < ret->n_commits; n++) {
        size_t i;
        for (i = 0; i < ret->wv[n].size; i++) {
            secp256k1_scalar_negate(&ret->wv[n].entry[i].scal.scal, &ret->wv[n].entry[i].scal.scal);
            ret->wv[n].entry[i].scal.special *= -1;
        }
    }

    /* Read C */
    for (n = 0; n < ret->n_constraints; n++) {
        if (fread(buf, 1, 1, fh) != 1 ||
            ((buf[0] & 0x3f) > 0 && fread(buf + 1, buf[0] & 0x3f, 1, fh) != 1) ||
            secp256k1_scalar_decode(&ret->c[n], buf) != 1) {
            goto fail;
        }
    }

    fclose(fh);
    return ret;

fail:
    fclose(fh);
    if (ret != NULL) {
        free(ret->entries);
        free(ret->wl);
        free(ret->c);
        free(ret);
    }
    return NULL;
}

secp256k1_bulletproof_circuit_assignment *secp256k1_bulletproof_circuit_assignment_decode(const secp256k1_context *ctx, const char *fname) {
    FILE *fh;
    unsigned char buf[33];
    secp256k1_bulletproof_circuit_assignment *ret = NULL;
    size_t version;
    size_t n_gates;
    size_t n_commits;
    size_t total_mem;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(fname != NULL);

    fh = fopen(fname, "rb");
    if (fh == NULL) {
        return NULL;
    }

    if (fread(buf, 16, 1, fh) != 1) {
        goto fail;
    }

    version = secp256k1_decode(&buf[0], 4);  /* read version and flags as one word */
    if (version != SECP256K1_BULLETPROOF_CIRCUIT_VERSION) {
        goto fail;
    }
    n_commits = secp256k1_decode(&buf[4], 4);
    n_gates = secp256k1_decode(&buf[8], 8);

    /* Number of c entries is implied by n_constraints */
    total_mem = sizeof(*ret) + (3 * n_gates + n_commits) * sizeof(*ret->al);
    if (total_mem > SECP256K1_BULLETPROOF_MAX_CIRCUIT) {
        goto fail;
    }

    ret = (secp256k1_bulletproof_circuit_assignment *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        goto fail;
    }
    ret->al = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, (3 * n_gates + n_commits) * sizeof(*ret->al));
    if (ret->al == NULL) {
        goto fail;
    }
    ret->ar = &ret->al[1 * n_gates];
    ret->ao = &ret->al[2 * n_gates];
    ret->v = &ret->al[3 * n_gates];
    ret->n_gates = n_gates;
    ret->n_commits = n_commits;

    /* Because al, ar, ao and v are contiguous in memory we can just read them all in one loop */
    for (i = 0; i < 3 * n_gates + n_commits; i++) {
        size_t j;
        int overflow;

        memset(buf, 0, 33);
        if (fread(buf, 1, 1, fh) != 1 ||
            ((buf[0] & 0x3f) > 0 && fread(buf + 1, buf[0] & 0x3f, 1, fh) != 1)) {
            goto fail;
        }

        for (j = 0; j < 16; j++) {
            unsigned char tmp = buf[j + 1];
            buf[j + 1] = buf[32 - j];
            buf[32 - j] = tmp;
        }
        secp256k1_scalar_set_b32(&ret->al[i], buf + 1, &overflow);
        if (overflow) {
            goto fail;
        }
        if (buf[0] & 0x80) {
            secp256k1_scalar_negate(&ret->al[i], &ret->al[i]);
        }
    }

    fclose(fh);
    return ret;

fail:
    fclose(fh);
    if (ret != NULL) {
        free(ret->al);
        free(ret);
    }
    return NULL;
}


void secp256k1_bulletproof_circuit_destroy(const secp256k1_context *ctx, secp256k1_bulletproof_circuit *circ) {
    VERIFY_CHECK(ctx != NULL);
    if (circ != NULL) {
        free(circ->entries);
        free(circ->wl);
        free(circ->c);
        free(circ);
    }
}

void secp256k1_bulletproof_circuit_assignment_destroy(const secp256k1_context *ctx, secp256k1_bulletproof_circuit_assignment *assn) {
    (void) ctx;
    if (assn != NULL) {
        free(assn->al);
        free(assn);
    }
}

#endif
