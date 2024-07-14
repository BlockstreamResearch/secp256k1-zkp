#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.
 * IT IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!
 *
 * This module implements a variant of Flexible Round-Optimized Schnorr
 * Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/).
 */

/** Opaque data structures
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. If you
 *  need to convert to a format suitable for storage, transmission, or
 *  comparison, use the corresponding serialization and parsing functions.
 */

/** Opaque data structure that holds a signer's _secret_ share.
 *
 *  Guaranteed to be 36 bytes in size. Serialized and parsed with
 *  `frost_share_serialize` and `frost_share_parse`.
 */
typedef struct {
    unsigned char data[36];
} secp256k1_frost_share;

/** Serialize a FROST share
 *
 *  Returns: 1 when the share could be serialized, 0 otherwise
 *  Args:    ctx: pointer to a context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized share
 *  In:    share: pointer to the share
 */
SECP256K1_API int secp256k1_frost_share_serialize(
    const secp256k1_context *ctx,
    unsigned char *out32,
    const secp256k1_frost_share *share
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST share.
 *
 *  Returns: 1 when the share could be parsed, 0 otherwise.
 *  Args:    ctx: pointer to a context object
 *  Out:   share: pointer to a share object
 *  In:     in32: pointer to the 32-byte share to be parsed
 */
SECP256K1_API int secp256k1_frost_share_parse(
    const secp256k1_context *ctx,
    secp256k1_frost_share *share,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Creates key shares
 *
 *  To generate a key, each participant generates a share for each other
 *  participant. For example, in the case of 2 particpants, Alice and Bob, they
 *  each generate 2 shares, distribute 1 share to each other using a secure
 *  channel, and keep 1 for themselves.
 *
 *  Each participant must transmit shares over secure channels to each other
 *  participant.
 *
 *  Each call to this function must have a UNIQUE and uniformly RANDOM seed32
 *  that must that must NOT BE REUSED in subsequent calls to this function and
 *  must be KEPT SECRET (even from other participants).
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object
 *  Out:          shares: pointer to the key shares
 *        vss_commitment: pointer to the VSS commitment
 *                 pok64: pointer to the proof of knowledge
 *   In:          seed32: 32-byte random seed as explained above. Must be
 *                        unique to this call to secp256k1_frost_shares_gen
 *                        and must be uniformly random.
 *             threshold: the minimum number of signers required to produce a
 *                        signature
 *        n_participants: the total number of participants
 *                 ids33: array of 33-byte participant IDs
 */
SECP256K1_API int secp256k1_frost_shares_gen(
    const secp256k1_context *ctx,
    secp256k1_frost_share *shares,
    secp256k1_pubkey *vss_commitment,
    unsigned char *pok64,
    const unsigned char *seed32,
    size_t threshold,
    size_t n_participants,
    const unsigned char * const* ids33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(8);

/** Aggregates shares
 *
 *  As part of the key generation protocol, each participant receives a share
 *  from each participant, including a share they "receive" from themselves.
 *  This function verifies those shares against their VSS commitments,
 *  aggregates the shares, and then aggregates the commitments to each
 *  participant's first polynomial coefficient to derive the aggregate public
 *  key.
 *
 *  If this function returns an error, `secp256k1_frost_share_verify` can be
 *  called on each share to determine which participants submitted faulty
 *  shares.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
 *           the resulting signature verifies).
 *  Args:         ctx: pointer to a context object
 *  Out:    agg_share: the aggregated share
 *             agg_pk: the aggregated x-only public key
 *  In:        shares: all key generation shares for the partcipant's index
 *    vss_commitments: coefficient commitments of all participants ordered by
 *                     the x-only pubkeys of the participants
 *           n_shares: the total number of shares
 *          threshold: the minimum number of shares required to produce a
 *                     signature
 *               id33: the 33-byte ID of the participant whose shares are being
 *                     aggregated
 */
SECP256K1_API int secp256k1_frost_share_agg(
    const secp256k1_context *ctx,
    secp256k1_frost_share *agg_share,
    secp256k1_xonly_pubkey *agg_pk,
    const secp256k1_frost_share * const *shares,
    const secp256k1_pubkey * const *vss_commitments,
    size_t n_shares,
    size_t threshold,
    const unsigned char *id33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(8);

/** Verifies a share received during a key generation session
 *
 *  The signature is verified against the VSS commitment received with the
 *  share. This is only useful for purposes of determining which share(s) are
 *  invalid if share_agg returns an error.
 *
 *  Returns: 0 if the arguments are invalid or the share does not verify, 1
 *           otherwise
 *  Args         ctx: pointer to a context object
 *  In:    threshold: the minimum number of signers required to produce a
 *                    signature
 *              id33: the 33-byte participant ID of the share recipient
 *             share: pointer to a key generation share
 *    vss_commitment: the VSS commitment associated with the share
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_share_verify(
    const secp256k1_context *ctx,
    size_t threshold,
    const unsigned char *id33,
    const secp256k1_frost_share *share,
    const secp256k1_pubkey * const *vss_commitment
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Computes a public verification share used for verifying partial signatures
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out:    pubshare: pointer to a struct to store the public verification
 *                    share
 *  In:    threshold: the minimum number of signers required to produce a
 *                    signature
 *              id33: the 33-byte participant ID of the participant whose
 *                    partial signature will be verified with the pubshare
 *   vss_commitments: coefficient commitments of all participants
 *    n_participants: the total number of participants
 */
SECP256K1_API int secp256k1_frost_compute_pubshare(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubshare,
    size_t threshold,
    const unsigned char *id33,
    const secp256k1_pubkey * const *vss_commitments,
    size_t n_participants
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif
