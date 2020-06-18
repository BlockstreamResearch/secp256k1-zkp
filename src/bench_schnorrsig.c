/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>
#include <stdlib.h>

#include "include/secp256k1.h"
#include "include/secp256k1_schnorrsig.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    int n;
    const unsigned char **pk;
    const secp256k1_schnorrsig **sigs;
    const unsigned char **msgs;
} bench_schnorrsig_data;

void bench_schnorrsig_sign(void* arg, int iters) {
    bench_schnorrsig_data *data = (bench_schnorrsig_data *)arg;
    int i;
    unsigned char sk[32] = "benchmarkexample secrettemplate";
    unsigned char msg[32] = "benchmarkexamplemessagetemplate";
    secp256k1_schnorrsig sig;

    for (i = 0; i < iters; i++) {
        msg[0] = i;
        msg[1] = i >> 8;
        sk[0] = i;
        sk[1] = i >> 8;
        CHECK(secp256k1_schnorrsig_sign(data->ctx, &sig, NULL, msg, sk, NULL, NULL));
    }
}

void bench_schnorrsig_verify(void* arg, int iters) {
    bench_schnorrsig_data *data = (bench_schnorrsig_data *)arg;
    int i;

    for (i = 0; i < iters; i++) {
        secp256k1_pubkey pk;
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pk, data->pk[i], 33) == 1);
        CHECK(secp256k1_schnorrsig_verify(data->ctx, data->sigs[i], data->msgs[i], &pk));
    }
}

void bench_schnorrsig_verify_n(void* arg, int iters) {
    bench_schnorrsig_data *data = (bench_schnorrsig_data *)arg;
    int i, j;
    const secp256k1_pubkey **pk = (const secp256k1_pubkey **)malloc(data->n * sizeof(*pk));

    CHECK(pk != NULL);
    for (j = 0; j < iters/data->n; j++) {
        for (i = 0; i < data->n; i++) {
            secp256k1_pubkey *pk_nonconst = (secp256k1_pubkey *)malloc(sizeof(*pk_nonconst));
            CHECK(secp256k1_ec_pubkey_parse(data->ctx, pk_nonconst, data->pk[i], 33) == 1);
            pk[i] = pk_nonconst;
        }
        CHECK(secp256k1_schnorrsig_verify_batch(data->ctx, data->scratch, data->sigs, data->msgs, pk, data->n));
        for (i = 0; i < data->n; i++) {
            free((void *)pk[i]);
        }
    }
    free(pk);
}

int main(void) {
    int i;
    bench_schnorrsig_data data;
    int iters = get_iters(1000);

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 1024 * 1024 * 1024);
    data.pk = (const unsigned char **)malloc(iters * sizeof(unsigned char *));
    data.msgs = (const unsigned char **)malloc(iters * sizeof(unsigned char *));
    data.sigs = (const secp256k1_schnorrsig **)malloc(iters * sizeof(secp256k1_schnorrsig *));

    for (i = 0; i < iters; i++) {
        unsigned char sk[32];
        unsigned char *msg = (unsigned char *)malloc(32);
        secp256k1_schnorrsig *sig = (secp256k1_schnorrsig *)malloc(sizeof(*sig));
        unsigned char *pk_char = (unsigned char *)malloc(33);
        secp256k1_pubkey pk;
        size_t pk_len = 33;
        msg[0] = sk[0] = i;
        msg[1] = sk[1] = i >> 8;
        msg[2] = sk[2] = i >> 16;
        msg[3] = sk[3] = i >> 24;
        memset(&msg[4], 'm', 28);
        memset(&sk[4], 's', 28);

        data.pk[i] = pk_char;
        data.msgs[i] = msg;
        data.sigs[i] = sig;

        CHECK(secp256k1_ec_pubkey_create(data.ctx, &pk, sk));
        CHECK(secp256k1_ec_pubkey_serialize(data.ctx, pk_char, &pk_len, &pk, SECP256K1_EC_COMPRESSED) == 1);
        CHECK(secp256k1_schnorrsig_sign(data.ctx, sig, NULL, msg, sk, NULL, NULL));
    }

    run_benchmark("schnorrsig_sign", bench_schnorrsig_sign, NULL, NULL, (void *) &data, 10, iters);
    run_benchmark("schnorrsig_verify", bench_schnorrsig_verify, NULL, NULL, (void *) &data, 10, iters);
    for (i = 1; i <= iters; i *= 2) {
        char name[64];
        int divisible_iters;
        sprintf(name, "schnorrsig_batch_verify_%d", (int) i);

        data.n = i;
        divisible_iters = iters - (iters % data.n);
        run_benchmark(name, bench_schnorrsig_verify_n, NULL, NULL, (void *) &data, 3, divisible_iters);
    }

    for (i = 0; i < iters; i++) {
        free((void *)data.pk[i]);
        free((void *)data.msgs[i]);
        free((void *)data.sigs[i]);
    }
    free(data.pk);
    free(data.msgs);
    free(data.sigs);

    secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
