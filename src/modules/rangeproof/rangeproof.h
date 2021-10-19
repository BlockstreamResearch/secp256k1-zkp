/**********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_RANGEPROOF_H_
#define _SECP256K1_RANGEPROOF_H_

#include "scalar.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

/** Structure representing data directly encoded into a rangeproof header
 *
 * A rangeproof is a proof, associated with a Pedersen commitment, that a
 * "proven value" in is the range [0, 2^mantissa]. The committed value is
 * related to the proven value by the contents of this header, as
 *
 *    committed = min_value + 10^exp * proven
 */
typedef struct secp256k1_rangeproof_header {
    /** Power of ten to multiply the proven value by, or -1 for an exact proof
     *
     * Encoded in the header. */
    int exp;
    /** Number of bits used to represent the proven value
     *
     * Encoded in the header. */
    int mantissa;
    /** 10 to the power of exp, or 1 for a proof of an exact value.
     *
     * Implied by `exp`, not encoded. */
    uint64_t scale;
    /** Minimum value for the range (added to the proven value).
     *
     * Encoded in the header. */
    uint64_t min_value;
    /** Maximum value for the range (min_value + 10^exp * 2^mantissa).
     *
     * Implied by `min_value`, `exp`, `mantissa`. Not encoded. */
    uint64_t max_value;
    /** Number of rings to use in the underlying borromean ring signature
     *
     * Implied by `mantissa`. Not encoded. */
    size_t n_rings;
    /** Number of public keys to use in the underlying borromean ring signature
     *
     * Implied by `mantissa`. Not encoded. */
    size_t n_pubs;
    /** Number of keys in each ring
     *
     * Implied by `mantissa`. Not encoded. */
    size_t rsizes[32];
} secp256k1_rangeproof_header;

/** Parses out a rangeproof header from a rangeproof and fills in all fields
 *
 * Returns: 1 on success, 0 on failure
 * Out: header: the parsed header
 *      offset: the number of bytes of `proof` that the header occupied
 * In:   proof: the proof to parse the header out of
 *        plen: the length of the proof
 */
static int secp256k1_rangeproof_header_parse(
    secp256k1_rangeproof_header* header,
    size_t* offset,
    const unsigned char* proof,
    size_t plen
);

static int secp256k1_rangeproof_verify_impl(const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *blindout, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value, const secp256k1_ge *commit, const unsigned char *proof, size_t plen,
 const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_ge* genp);

#endif
