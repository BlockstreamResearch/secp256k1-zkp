/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_UTIL_
#define _SECP256K1_MODULE_BULLETPROOFS_UTIL_

#include "field.h"
#include "group.h"
#include "hash.h"

/* Outputs a pair of points, amortizing the parity byte between them
 * Assumes both points' coordinates have been normalized.
 */
static void secp256k1_bulletproofs_serialize_points(unsigned char *output, const secp256k1_ge *lpt, const secp256k1_ge *rpt) {
    output[0] = (secp256k1_fe_is_odd(&lpt->y) << 1) + secp256k1_fe_is_odd(&rpt->y);
    secp256k1_fe_get_b32(&output[1], &lpt->x);
    secp256k1_fe_get_b32(&output[33], &rpt->x);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("Bulletproofs/commitment")||SHA256("Bulletproofs/commitment"). */
static void secp256k1_bulletproofs_sha256_tagged_commitment(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x50b6a879ul;
    sha->s[1] = 0x0d9a7470ul;
    sha->s[2] = 0xb4400e54ul;
    sha->s[3] = 0x32d29ac7ul;
    sha->s[4] = 0xde938408ul;
    sha->s[5] = 0x923fc797ul;
    sha->s[6] = 0x29f973a6ul;
    sha->s[7] = 0xa25e1a1cul;

    sha->bytes = 64;
}

/* little-endian encodes a uint64 */
static void secp256k1_bulletproofs_le64(unsigned char *output, const uint64_t n) {
    output[0] = n;
    output[1] = n >> 8;
    output[2] = n >> 16;
    output[3] = n >> 24;
    output[4] = n >> 32;
    output[5] = n >> 40;
    output[6] = n >> 48;
    output[7] = n >> 56;
}

static void secp256k1_bulletproofs_commit_initial_data(
    unsigned char* commit,
    const uint64_t n_bits,
    const uint64_t min_value,
    const secp256k1_ge* commitp,
    const secp256k1_ge* asset_genp,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    unsigned char scratch[65];
    secp256k1_sha256 sha256;
    secp256k1_bulletproofs_sha256_tagged_commitment(&sha256);
    secp256k1_bulletproofs_le64(scratch, n_bits);
    secp256k1_sha256_write(&sha256, scratch, 8);
    secp256k1_bulletproofs_le64(scratch, min_value);
    secp256k1_sha256_write(&sha256, scratch, 8);
    secp256k1_bulletproofs_serialize_points(scratch, commitp, asset_genp);
    secp256k1_sha256_write(&sha256, scratch, 65);
    if (extra_commit != NULL) {
        secp256k1_bulletproofs_le64(scratch, (uint64_t) extra_commit_len);
        secp256k1_sha256_write(&sha256, scratch, 8);
        secp256k1_sha256_write(&sha256, extra_commit, extra_commit_len);
    }
    secp256k1_sha256_finalize(&sha256, commit);
}

/* Iterator which produces each l,r pair in succession with a minimum
 * of scalar operations */
typedef struct {
    const unsigned char *nonce;
    const secp256k1_scalar *y;
    const secp256k1_scalar *z;
    secp256k1_scalar yn;
    secp256k1_scalar z22n;
    uint64_t val_less_min;
    size_t count;
} secp256k1_bulletproofs_bulletproofs_lrgen;

static void secp256k1_bulletproofs_lrgen_init(secp256k1_bulletproofs_bulletproofs_lrgen *generator, const unsigned char *nonce, const secp256k1_scalar *y, const secp256k1_scalar *z, const uint64_t val_less_min) {
    generator->nonce = nonce;
    generator->y = y;
    generator->z = z;
    secp256k1_scalar_set_int(&generator->yn, 1);
    generator->val_less_min = val_less_min;
    generator->count = 0;
}

/* Serializes yn and z22n as a 64-byte char array */
static void secp256k1_bulletproofs_lrgen_serialize(unsigned char* output, const secp256k1_bulletproofs_bulletproofs_lrgen *generator) {
    secp256k1_scalar_get_b32(&output[0], &generator->yn);
    secp256k1_scalar_get_b32(&output[32], &generator->z22n);
}

/* Deserializes yn and z22n from a 64-byte char array, otherwise the same as `secp256k1_bulletproofs_lrgen_init` */
static int secp256k1_bulletproofs_lrgen_deserialize(secp256k1_bulletproofs_bulletproofs_lrgen *generator, const unsigned char *saved_state, size_t idx, const unsigned char *nonce, const secp256k1_scalar *y, const secp256k1_scalar *z, const uint64_t val_less_min) {
    int overflow;
    secp256k1_bulletproofs_lrgen_init(generator, nonce, y, z, val_less_min);
    secp256k1_scalar_set_b32(&generator->yn, &saved_state[0], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&generator->yn)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&generator->z22n, &saved_state[32], &overflow);
    if (overflow || secp256k1_scalar_is_zero(&generator->z22n)) {
        return 0;
    }
    generator->count = idx;
    return 1;
}

static void secp256k1_lr_generate(secp256k1_bulletproofs_bulletproofs_lrgen *generator, secp256k1_scalar *lout, secp256k1_scalar *rout, const secp256k1_scalar *x) {
    const int al = (generator->val_less_min >> generator->count) & 1;
    secp256k1_scalar sl, sr;
    secp256k1_scalar negz;

    if (generator->count == 0) {
        secp256k1_scalar_sqr(&generator->z22n, generator->z);
    }

    secp256k1_scalar_chacha20(&sl, &sr, generator->nonce, generator->count + 2);
    secp256k1_scalar_mul(&sl, &sl, x);
    secp256k1_scalar_mul(&sr, &sr, x);

    secp256k1_scalar_set_int(lout, al);
    secp256k1_scalar_negate(&negz, generator->z);
    secp256k1_scalar_add(lout, lout, &negz);
    secp256k1_scalar_add(lout, lout, &sl);

    secp256k1_scalar_set_int(rout, 1 - al);
    secp256k1_scalar_negate(rout, rout);
    secp256k1_scalar_add(rout, rout, generator->z);
    secp256k1_scalar_add(rout, rout, &sr);
    secp256k1_scalar_mul(rout, rout, &generator->yn);
    secp256k1_scalar_add(rout, rout, &generator->z22n);

    generator->count++;
    secp256k1_scalar_mul(&generator->yn, &generator->yn, generator->y);
    secp256k1_scalar_add(&generator->z22n, &generator->z22n, &generator->z22n);
}

/* Computes delta(y, z) as defined in eq (39) of the BPs paper and adds it to `inout` */
static void secp256k1_bulletproofs_add_delta(secp256k1_scalar* inout, const secp256k1_scalar* y, const secp256k1_scalar* z, const secp256k1_scalar* z_sq, size_t n) {
    size_t i;
    secp256k1_scalar term = *z_sq;

    /* (z - z^2) */
    secp256k1_scalar_negate(&term, &term);
    secp256k1_scalar_add(&term, &term, z);
    /* (z - z^2) * (1^n dot y^n) */
    secp256k1_scalar_add(inout, inout, &term);
    for (i = 1; i < n; i++) {  /* iterate n-1 times */
        secp256k1_scalar_mul(&term, &term, y);
        secp256k1_scalar_add(inout, inout, &term);
    }
    /* z^3 * (1^n dot 2^n) */
    if (n == 64) {
        secp256k1_scalar_set_u64(&term, ~(uint64_t)0);
    } else {
        secp256k1_scalar_set_u64(&term, ((uint64_t)1 << n) - 1);
    }
    secp256k1_scalar_mul(&term, &term, z);
    secp256k1_scalar_mul(&term, &term, z_sq);
    secp256k1_scalar_negate(&term, &term);
    /* Sum of the previous two expressions */
    secp256k1_scalar_add(inout, inout, &term);
}

#endif
