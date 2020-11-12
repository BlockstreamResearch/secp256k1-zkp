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
    unsigned char* scratch,
    const uint64_t n_bits,
    const uint64_t min_value,
    const secp256k1_ge* commitp,
    const secp256k1_ge* asset_genp,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    /* FIXME use tagged hash here */
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

#endif
