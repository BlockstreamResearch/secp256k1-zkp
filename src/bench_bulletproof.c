/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "include/secp256k1_generator.h"
#include "include/secp256k1_bulletproof.h"
#include "include/secp256k1_rangeproof.h"
#include "util.h"
#include "bench.h"

#define WIDTH 64
#define VALUE 0

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment commit;
    secp256k1_generator altgen;
    unsigned char proof[800];
    size_t plen;
} bench_bulletproof_t;

static void bench_bulletproof_setup(void* arg) {
    bench_bulletproof_t *data = (bench_bulletproof_t*)arg;

    unsigned char nonce[32] = "my kingdom for some randomness!!";
    unsigned char blind[32] = "and my kingdom too for a blinder";
    unsigned char genbd[32] = "yet more blinding, for the asset";

    CHECK(secp256k1_generator_generate(data->ctx, &data->altgen, genbd));
    CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit, blind, VALUE, &data->altgen));

    data->plen = sizeof(data->proof);
    CHECK(secp256k1_bulletproof_rangeproof_prove(data->ctx, data->scratch, data->proof, &data->plen, VALUE, blind, &data->altgen, WIDTH, nonce, NULL, 0) == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify(data->ctx, data->scratch, data->proof, data->plen, &data->commit, WIDTH, &data->altgen, NULL, 0) == 1);
}

static void bench_bulletproof(void* arg) {
    int i;
    bench_bulletproof_t *data = (bench_bulletproof_t*)arg;

    for (i = 0; i < 1000; i++) {
        CHECK(secp256k1_bulletproof_rangeproof_verify(data->ctx, data->scratch, data->proof, data->plen, &data->commit, WIDTH, &data->altgen, NULL, 0) == 1);
    }
}

int main(void) {
    bench_bulletproof_t data;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 10000000, 10000000);  /* 10M should be waay overkill */

    run_benchmark("bulletproof_verify", bench_bulletproof, bench_bulletproof_setup, NULL, &data, 10, 1000);

    secp256k1_scratch_space_destroy(data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
