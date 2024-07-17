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
 *
 * The module also supports BIP-341 ("Taproot") and BIP-32 ("ordinary") public
 * key tweaking.
 *
 * Following the convention used in the MuSig module, the API uses the singular
 * term "nonce" to refer to the two "nonces" used by the FROST scheme.
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
} secp256k1_frost_tweak_cache;

/** Opaque data structure that holds a signer's _secret_ share.
 *
 *  Guaranteed to be 36 bytes in size. Serialized and parsed with
 *  `frost_share_serialize` and `frost_share_parse`.
 */
typedef struct {
    unsigned char data[36];
} secp256k1_frost_share;

/** Opaque data structure that holds a signer's _secret_ nonce.
 *
 *  Guaranteed to be 68 bytes in size.
 *
 *  WARNING: This structure MUST NOT be copied or read or written to directly.
 *  A signer who is online throughout the whole process and can keep this
 *  structure in memory can use the provided API functions for a safe standard
 *  workflow. See
 *  https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
 *  more details about the risks associated with serializing or deserializing
 *  this structure.
 *
 *  We repeat, copying this data structure can result in nonce reuse which will
 *  leak the secret signing key.
 */
typedef struct {
    unsigned char data[68];
} secp256k1_frost_secnonce;

/** Opaque data structure that holds a signer's public nonce.
*
*  Guaranteed to be 132 bytes in size. It can be safely copied/moved.
*  Serialized and parsed with `frost_pubnonce_serialize` and
*  `frost_pubnonce_parse`.
*/
typedef struct {
    unsigned char data[132];
} secp256k1_frost_pubnonce;

/** Parse a signer's public nonce.
 *
 *  Returns: 1 when the nonce could be parsed, 0 otherwise.
 *  Args:    ctx: pointer to a context object
 *  Out:   nonce: pointer to a nonce object
 *  In:     in66: pointer to the 66-byte nonce to be parsed
 */
SECP256K1_API int secp256k1_frost_pubnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_frost_pubnonce *nonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a signer's public nonce
 *
 *  Returns: 1 when the nonce could be serialized, 0 otherwise
 *  Args:    ctx: pointer to a context object
 *  Out:   out66: pointer to a 66-byte array to store the serialized nonce
 *  In:    nonce: pointer to the nonce
 */
SECP256K1_API int secp256k1_frost_pubnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_frost_pubnonce *nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

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

/** Obtain the aggregate public key from a FROST x-only aggregate public key.
 *
 *  This is only useful if you need the non-xonly public key, in particular for
 *  ordinary (non-xonly) tweaking or batch-verifying multiple key aggregations
 *  (not implemented).
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out:   ec_agg_pk: the FROST-aggregated public key.
 *  In: xonly_agg_pk: the aggregated x-only public key that is the output of
 *                    `secp256k1_frost_share_agg`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *ec_agg_pk,
    const secp256k1_xonly_pubkey *xonly_agg_pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Initializes a tweak cache used for applying tweaks to a FROST key
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out: tweak_cache: pointer to a frost_tweak_cache struct that is required
 *                    for key tweaking
 *  In:       agg_pk: the aggregated x-only public key that is the output of
 *                    `secp256k1_frost_share_agg`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_pubkey_tweak(
    const secp256k1_context *ctx,
    secp256k1_frost_tweak_cache *tweak_cache,
    const secp256k1_xonly_pubkey *agg_pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Apply ordinary "EC" tweaking to a public key in a given tweak_cache by
 *  adding the generator multiplied with `tweak32` to it. This is useful for
 *  deriving child keys from an aggregate public key via BIP32.
 *
 *  The tweaking method is the same as `secp256k1_ec_pubkey_tweak_add`. So after
 *  the following pseudocode buf and buf2 have identical contents (absent
 *  earlier failures).
 *
 *  secp256k1_frost_share_agg(..., xonly_agg_pk, ...)
 *  secp256k1_frost_pubkey_tweak(..., tweak_cache, xonly_agg_pk)
 *  secp256k1_frost_pubkey_ec_tweak_add(..., output_pk, tweak_cache, tweak32)
 *  secp256k1_ec_pubkey_serialize(..., buf, output_pk)
 *  secp256k1_frost_pubkey_get(..., ec_agg_pk, xonly_agg_pk)
 *  secp256k1_ec_pubkey_tweak_add(..., ec_agg_pk, tweak32)
 *  secp256k1_ec_pubkey_serialize(..., buf2, ec_agg_pk)
 *
 *  This function is required if you want to _sign_ for a tweaked aggregate key.
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
 *  In/Out:  tweak_cache: pointer to a `frost_tweak_cache` struct initialized by
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
    secp256k1_frost_tweak_cache *tweak_cache,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Apply x-only tweaking to a public key in a given tweak_cache by adding the
 *  generator multiplied with `tweak32` to it. This is useful for creating
 *  Taproot outputs.
 *
 *  The tweaking method is the same as `secp256k1_xonly_pubkey_tweak_add`. So in
 *  the following pseudocode xonly_pubkey_tweak_add_check (absent earlier
 *  failures) returns 1.
 *
 *  secp256k1_frost_share_agg(..., agg_pk, ...)
 *  secp256k1_frost_pubkey_tweak(..., tweak_cache, agg_pk)
 *  secp256k1_frost_pubkey_xonly_tweak_add(..., output_pk, tweak_cache, tweak32)
 *  secp256k1_xonly_pubkey_serialize(..., buf, output_pk)
 *  secp256k1_xonly_pubkey_tweak_add_check(..., buf, ..., agg_pk, tweak32)
 *
 *  This function is required if you want to _sign_ for a tweaked aggregate key.
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
 *  In/Out:  tweak_cache: pointer to a `frost_tweak_cache` struct initialized by
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
    secp256k1_frost_tweak_cache *tweak_cache,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Starts a signing session by generating a nonce
 *
 *  This function outputs a secret nonce that will be required for signing and a
 *  corresponding public nonce that is intended to be sent to other signers.
 *
 *  FROST, like MuSig, differs from regular Schnorr signing in that
 *  implementers _must_ take special care to not reuse a nonce. This can be
 *  ensured by following these rules:
 *
 *  1. Each call to this function must have a UNIQUE session_id32 that must NOT BE
 *     REUSED in subsequent calls to this function.
 *     If you do not provide a seckey, session_id32 _must_ be UNIFORMLY RANDOM
 *     AND KEPT SECRET (even from other signers). If you do provide a seckey,
 *     session_id32 can instead be a counter (that must never repeat!). However,
 *     it is recommended to always choose session_id32 uniformly at random.
 *  2. If you already know the seckey, message or aggregate public key, they
 *     can be optionally provided to derive the nonce and increase
 *     misuse-resistance. The extra_input32 argument can be used to provide
 *     additional data that does not repeat in normal scenarios, such as the
 *     current time.
 *  3. Avoid copying (or serializing) the secnonce. This reduces the possibility
 *     that it is used more than once for signing.
 *
 *  Remember that nonce reuse will leak the secret key!
 *  Note that using the same agg_share for multiple FROST sessions is fine.
 *
 *  Returns: 0 if the arguments are invalid and 1 otherwise
 *  Args:         ctx: pointer to a context object (not secp256k1_context_static)
 *  Out:     secnonce: pointer to a structure to store the secret nonce
 *           pubnonce: pointer to a structure to store the public nonce
 *  In:  session_id32: a 32-byte session_id32 as explained above. Must be
 *                     unique to this call to secp256k1_frost_nonce_gen and
 *                     must be uniformly random unless you really know what you
 *                     are doing.
 *          agg_share: the aggregated share that will later be used for
 *                     signing, if already known (can be NULL)
 *              msg32: the 32-byte message that will later be signed, if
 *                     already known (can be NULL)
 *             agg_pk: the FROST-aggregated public key (can be NULL)
 *      extra_input32: an optional 32-byte array that is input to the nonce
 *                     derivation function (can be NULL)
 */
SECP256K1_API int secp256k1_frost_nonce_gen(
    const secp256k1_context *ctx,
    secp256k1_frost_secnonce *secnonce,
    secp256k1_frost_pubnonce *pubnonce,
    const unsigned char *session_id32,
    const secp256k1_frost_share *agg_share,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
