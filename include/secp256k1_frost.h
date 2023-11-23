#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.  IT
 * IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

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
 *  Args:    ctx: a secp256k1 context object
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
 *  Args:    ctx: a secp256k1 context object
 *  Out:   share: pointer to a share object
 *  In:     in32: pointer to the 32-byte share to be parsed
 */
SECP256K1_API int secp256k1_frost_share_parse(
    const secp256k1_context *ctx,
    secp256k1_frost_share *share,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Creates key generation shares
 *
 *  To generate a key, a trusted dealer generates a share for each other
 *  participant.
 *
 *  Each participant _must_ have a secure channel with the trusted dealer with
 *  which they can transmit shares to each other.
 *
 *  A new seed32 _must_ be used for each key generation session. The trusted
 *  dealer must NOT REUSE their respective seed32 again for subsequent key
 *  generation sessions. If a trusted dealer fails to complete this session or
 *  start a new session to generate a new key, they must NOT REUSE their
 *  respective seed32 again, but instead generate a new one. It is recommended
 *  to always choose seed32 uniformly at random to avoid their reuse.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object
 *  Out:          shares: pointer to the key generation shares
 *             pubshares: pointer to the public verification shares
 *                    pk: pointer to the x-only public key
 *   In:          seed32: a 32-byte seed as explained above
 *             threshold: the minimum number of signers required to produce a
 *                        signature
 *        n_participants: the total number of participants
 */
SECP256K1_API int secp256k1_frost_shares_trusted_gen(
    const secp256k1_context *ctx,
    secp256k1_frost_share *shares,
    secp256k1_pubkey *pubshares,
    secp256k1_xonly_pubkey *pk,
    const unsigned char *seed32,
    size_t threshold,
    size_t n_participants
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif
