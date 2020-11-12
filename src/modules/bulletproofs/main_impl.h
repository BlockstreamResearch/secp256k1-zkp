/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_MAIN_
#define _SECP256K1_MODULE_BULLETPROOFS_MAIN_

/* this type must be completed before any of the modules/bulletproofs includes */
struct secp256k1_bulletproofs_generators {
    size_t n;
    /* `G_i`, `H_i` generators, `n` each of them which are generated when creating this struct */
    secp256k1_ge* gens;
};

#include "include/secp256k1_bulletproofs.h"
#include "include/secp256k1_generator.h"
#include "modules/bulletproofs/rangeproof_uncompressed_impl.h"
#include "modules/generator/main_impl.h" /* for generator_{load, save} */
#include "hash.h"
#include "util.h"

secp256k1_bulletproofs_generators *secp256k1_bulletproofs_generators_create(const secp256k1_context *ctx, size_t n) {
    secp256k1_bulletproofs_generators *ret;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    size_t i;

    VERIFY_CHECK(ctx != NULL);

    ret = (secp256k1_bulletproofs_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->n = n;

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        secp256k1_generator gen;
        unsigned char tmp[32] = { 0 };
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);
    }

    return ret;
}

secp256k1_bulletproofs_generators* secp256k1_bulletproofs_generators_parse(const secp256k1_context* ctx, const unsigned char* data, size_t data_len) {
    size_t n = data_len / 33;
    secp256k1_bulletproofs_generators* ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);

    if (data_len % 33 != 0) {
        return NULL;
    }

    ret = (secp256k1_bulletproofs_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }

    while (n--) {
        secp256k1_generator gen;
        if (!secp256k1_generator_parse(ctx, &gen, &data[33 * n])) {
            free(ret->gens);
            free(ret);
        }
        secp256k1_generator_load(&ret->gens[n], &gen);
    }
    return ret;
}

int secp256k1_bulletproofs_generators_serialize(const secp256k1_context* ctx, secp256k1_bulletproofs_generators* gens, unsigned char* data, size_t *data_len) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(data_len != NULL);

    memset(data, 0, *data_len);
    if (*data_len < 33 * gens->n) {
        return 0;
    }
    for (i = 0; i < gens->n; i++) {
        secp256k1_generator gen;
        secp256k1_generator_save(&gen, &gens->gens[i]);
        if (!secp256k1_generator_serialize(ctx, &data[33 * i], &gen)) {
            return 0;
        }
    }

    return 1;
}

void secp256k1_bulletproofs_generators_destroy(const secp256k1_context* ctx, secp256k1_bulletproofs_generators *gens) {
    VERIFY_CHECK(ctx != NULL);
    (void) ctx;
    if (gens != NULL) {
        free(gens->gens);
        free(gens);
    }
}

#endif
