#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/** This code is currently a work in progress. It's not secure nor stable.
 * IT IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!
 *
 * This module implements a variant of Flexible Round-Optimized Schnorr
 * Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/).
 *
 * The module also supports BIP-341 ("Taproot") and BIP-32 ("ordinary") public
 * key tweaking.
 */

/** Opaque data structures
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. If you
 *  need to convert to a format suitable for storage, transmission, or
 *  comparison, use the corresponding serialization and parsing functions.
 */

/** Opaque data structure that caches information about key tweaking.
 *
 *  Guaranteed to be 101 bytes in size. It can be safely copied/moved. No
 *  serialization and parsing functions.
 */
typedef struct {
    unsigned char data[101];
} secp256k1_frost_keygen_cache;

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
 *  To generate a key, a trusted dealer generates a share for each participant.
 *
 *  The trusted dealer must transmit shares over secure channels to each
 *  participant.
 *
 *  Each call to this function must have a UNIQUE and uniformly RANDOM seed32
 *  that must that must NOT BE REUSED in subsequent calls to this function and
 *  must be KEPT SECRET (even from participants).
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object
 *  Out:          shares: pointer to the key shares
 *        vss_commitment: pointer to the VSS commitment
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
    const unsigned char *seed32,
    size_t threshold,
    size_t n_participants,
    const unsigned char * const *ids33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);

/** Verifies a share received during a key generation session
 *
 *  The signature is verified against the VSS commitment received with the
 *  share.
 *
 *  Returns: 0 if the arguments are invalid or the share does not verify, 1
 *           otherwise
 *  Args         ctx: pointer to a context object
 *  In:    threshold: the minimum number of signers required to produce a
 *                    signature
 *              id33: the 33-byte participant ID of the share recipient
 *             share: pointer to a key generation share
 *    vss_commitment: input array of the elements of the VSS commitment
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_share_verify(
    const secp256k1_context *ctx,
    size_t threshold,
    const unsigned char *id33,
    const secp256k1_frost_share *share,
    const secp256k1_pubkey *vss_commitment
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
 *    vss_commitment: input array of the elements of the VSS commitment
 *    n_participants: the total number of participants
 */
SECP256K1_API int secp256k1_frost_compute_pubshare(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubshare,
    size_t threshold,
    const unsigned char *id33,
    const secp256k1_pubkey *vss_commitment
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Computes a group public key and uses it to initialize a keygen_cache
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:         ctx: pointer to a context object
 *  Out: keygen_cache: pointer to a frost_keygen_cache struct that is required
 *                     for signing (or observing the signing session and
 *                     verifying partial signatures).
 *  In:     pubshares: input array of pointers to the public verification
 *                     shares of the participants ordered by the IDs of the
 *                     participants
 *        n_pubshares: the total number of public verification shares
 *              ids33: array of the 33-byte participant IDs of the signers
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_gen(
    const secp256k1_context *ctx,
    secp256k1_frost_keygen_cache *keygen_cache,
    const secp256k1_pubkey * const *pubshares,
    size_t n_pubshares,
    const unsigned char * const *ids33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Obtain the group public key from a keygen_cache.
 *
 *  This is only useful if you need the non-xonly public key, in particular for
 *  plain (non-xonly) tweaking or batch-verifying multiple key aggregations
 *  (not implemented).
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out:          pk: the FROST group public key.
 *  In: keygen_cache: pointer to a `frost_keygen_cache` struct initialized by
 *                    `frost_pubkey_gen`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pk,
    const secp256k1_frost_keygen_cache *keygen_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Apply ordinary "EC" tweaking to a public key in a given keygen_cache by
 *  adding the generator multiplied with `tweak32` to it. This is useful for
 *  deriving child keys from a group public key via BIP32.
 *
 *  The tweaking method is the same as `secp256k1_ec_pubkey_tweak_add`. So after
 *  the following pseudocode buf and buf2 have identical contents (absent
 *  earlier failures).
 *
 *  secp256k1_frost_pubkey_gen(..., keygen_cache, ...)
 *  secp256k1_frost_pubkey_tweak(..., keygen_cache, xonly_pk)
 *  secp256k1_frost_pubkey_ec_tweak_add(..., output_pk, keygen_cache, tweak32)
 *  secp256k1_ec_pubkey_serialize(..., buf, output_pk)
 *  secp256k1_frost_pubkey_get(..., ec_pk, xonly_pk)
 *  secp256k1_ec_pubkey_tweak_add(..., ec_pk, tweak32)
 *  secp256k1_ec_pubkey_serialize(..., buf2, ec_pk)
 *
 *  This function is required if you want to _sign_ for a tweaked group key.
 *  On the other hand, if you are only computing a public key, but not intending
 *  to create a signature for it, you can just use
 *  `secp256k1_ec_pubkey_tweak_add`.
 *
 *  Returns: 0 if the arguments are invalid or the resulting public key would be
 *           invalid (only when the tweak is the negation of the corresponding
 *           secret key). 1 otherwise.
 *  Args:            ctx: pointer to a context object
 *  Out:   output_pubkey: pointer to a public key to store the result. Will be set
 *                        to an invalid value if this function returns 0. If you
 *                        do not need it, this arg can be NULL.
 *  In/Out:  keygen_cache: pointer to a `frost_keygen_cache` struct initialized by
 *                       `frost_pubkey_tweak`
 *  In:          tweak32: pointer to a 32-byte tweak. If the tweak is invalid
 *                        according to `secp256k1_ec_seckey_verify`, this function
 *                        returns 0. For uniformly random 32-byte arrays the
 *                        chance of being invalid is negligible (around 1 in
 *                        2^128).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_keygen_cache *keygen_cache,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Apply x-only tweaking to a public key in a given keygen_cache by adding the
 *  generator multiplied with `tweak32` to it. This is useful for creating
 *  Taproot outputs.
 *
 *  The tweaking method is the same as `secp256k1_xonly_pubkey_tweak_add`. So in
 *  the following pseudocode xonly_pubkey_tweak_add_check (absent earlier
 *  failures) returns 1.
 *
 *  secp256k1_frost_pubkey_gen(..., keygen_cache, ..., ..., ...)
 *  secp256k1_frost_pubkey_xonly_tweak_add(..., output_pk, keygen_cache, tweak32)
 *  secp256k1_xonly_pubkey_serialize(..., buf, output_pk)
 *  secp256k1_frost_pubkey_get(..., pk, keygen_cache)
 *  secp256k1_xonly_pubkey_tweak_add_check(..., buf, ..., pk, tweak32)
 *
 *  This function is required if you want to _sign_ for a tweaked group key.
 *  On the other hand, if you are only computing a public key, but not intending
 *  to create a signature for it, you can just use
 *  `secp256k1_xonly_pubkey_tweak_add`.
 *
 *  Returns: 0 if the arguments are invalid or the resulting public key would be
 *           invalid (only when the tweak is the negation of the corresponding
 *           secret key). 1 otherwise.
 *  Args:            ctx: pointer to a context object
 *  Out:   output_pubkey: pointer to a public key to store the result. Will be set
 *                        to an invalid value if this function returns 0. If you
 *                        do not need it, this arg can be NULL.
 *  In/Out:  keygen_cache: pointer to a `frost_keygen_cache` struct initialized by
 *                       `frost_pubkey_tweak`
 *  In:          tweak32: pointer to a 32-byte tweak. If the tweak is invalid
 *                        according to secp256k1_ec_seckey_verify, this function
 *                        returns 0. For uniformly random 32-byte arrays the
 *                        chance of being invalid is negligible (around 1 in
 *                        2^128).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_keygen_cache *keygen_cache,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
