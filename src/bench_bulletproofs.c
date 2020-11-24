/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "include/secp256k1.h"
#include "include/secp256k1_bulletproofs.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context* ctx;
    secp256k1_bulletproofs_generators* gens;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment commit;
    unsigned char proof[SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_];
    unsigned char blind[32];
    unsigned char nonce[32];
    size_t proof_len;
    size_t n_bits;
    uint64_t min_value;
    uint64_t value;
} bench_bulletproofs_data;

static void bench_bulletproofs_setup(void* arg) {
    bench_bulletproofs_data *data = (bench_bulletproofs_data*)arg;

    data->min_value = 99;
    data->value = 100;
    data->proof_len = sizeof(data->proof);
    memset(data->blind, 0x77, 32);
    memset(data->nonce, 0x0, 32);
    CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit, data->blind, data->value, secp256k1_generator_h));

    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(data->ctx, data->gens, secp256k1_generator_h, data->proof, &data->proof_len, data->n_bits, data->value, data->min_value, &data->commit, data->blind, data->nonce, NULL, NULL, 0));
    CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proof, data->proof_len, data->min_value, &data->commit, NULL, 0));
}

static void bench_bulletproofs_prove(void* arg, int iters) {
    bench_bulletproofs_data *data = (bench_bulletproofs_data*)arg;
    int i;

    for (i = 0; i < iters; i++) {
        data->nonce[1] = i;
        data->nonce[2] = i >> 8;
        data->nonce[3] = i >> 16;
        data->proof_len = sizeof(data->proof);
        CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_prove(data->ctx, data->gens, secp256k1_generator_h, data->proof, &data->proof_len, data->n_bits, data->value, data->min_value, &data->commit, data->blind, data->nonce, NULL, NULL, 0));
    }
}

static void bench_bulletproofs_verify(void* arg, int iters) {
    bench_bulletproofs_data *data = (bench_bulletproofs_data*)arg;
    int i;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_bulletproofs_rangeproof_uncompressed_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proof, data->proof_len, data->min_value, &data->commit, NULL, 0));
    }
}

int main(void) {
    bench_bulletproofs_data data;
    int iters = get_iters(32);
    int i;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.gens = secp256k1_bulletproofs_generators_create(data.ctx, 128);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 100 * 1024);

    for (i = 0; i <= 6; i++) {
        char test_name[64];
        data.n_bits = 1ul << i;
        sprintf(test_name, "bulletproofs_uncompressed_prove_%i", 1 << i);
        run_benchmark(test_name, bench_bulletproofs_prove, bench_bulletproofs_setup, NULL, &data, 20, iters);
    }

    for (i = 0; i <= 6; i++) {
        char test_name[64];
        data.n_bits = 1ul << i;
        sprintf(test_name, "bulletproofs_uncompressed_verif_%i", 1 << i);
        run_benchmark(test_name, bench_bulletproofs_verify, bench_bulletproofs_setup, NULL, &data, 20, iters);
    }

    secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    secp256k1_bulletproofs_generators_destroy(data.ctx, data.gens);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
