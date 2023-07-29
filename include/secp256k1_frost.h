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
 * (https://crysp.uwaterloo.ca/software/frost/). Signatures are compatible with
 * BIP-340 ("Schnorr"). There's an example C source file in the module's
 * directory (examples/frost.c) that demonstrates how it can be used.
 *
 * The module also supports BIP-341 ("Taproot") and BIP-32 ("ordinary") public
 * key tweaking, and adaptor signatures.
 *
 * It is recommended to read the documentation in this include file carefully.
 * Further notes on API usage can be found in src/modules/frost/frost.md
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

/** Opaque data structure that holds a FROST session.
 *
 *  This structure is not required to be kept secret for the signing protocol
 *  to be secure. Guaranteed to be 133 bytes in size. It can be safely
 *  copied/moved. No serialization and parsing functions.
 */
typedef struct {
    unsigned char data[133];
} secp256k1_frost_session;

/** Opaque data structure that holds a partial FROST signature.
 *
 *  Guaranteed to be 36 bytes in size. Serialized and parsed with
 *  `frost_partial_sig_serialize` and `frost_partial_sig_parse`.
 */
typedef struct {
    unsigned char data[36];
} secp256k1_frost_partial_sig;

/** Parse a signer's public nonce.
 *
 *  Returns: 1 when the nonce could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   nonce: pointer to a nonce object
 *  In:     in66: pointer to the 66-byte nonce to be parsed
 */
SECP256K1_API int secp256k1_frost_pubnonce_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_pubnonce* nonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a signer's public nonce
 *
 *  Returns: 1 when the nonce could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out66: pointer to a 66-byte array to store the serialized nonce
 *  In:    nonce: pointer to the nonce
 */
SECP256K1_API int secp256k1_frost_pubnonce_serialize(
    const secp256k1_context* ctx,
    unsigned char *out66,
    const secp256k1_frost_pubnonce* nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a FROST partial signature
 *
 *  Returns: 1 when the signature could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_frost_partial_sig_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_frost_partial_sig* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature verification with it is
 *  guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_frost_partial_sig_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_partial_sig* sig,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a FROST share
 *
 *  Returns: 1 when the share could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized share
 *  In:    share: pointer to the share
 */
SECP256K1_API int secp256k1_frost_share_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_frost_share* share
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST share.
 *
 *  Returns: 1 when the share could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   share: pointer to a share object
 *  In:     in32: pointer to the 32-byte share to be parsed
 */
SECP256K1_API int secp256k1_frost_share_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_share* share,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/**
 * Generates VSS commitments and a proof of knowledge of the first coefficient.
 *
 * This function generates the VSS commitments based on the given seed and
 * threshold, and creates a proof of knowledge of the first coefficient.
 *
 * Returns: 0 if the arguments are invalid, 1 otherwise
 * Args:            ctx:  pointer to a context object initialized for
 *                        verification
 *  Out:  vss_commitment: the coefficient commitments. The length of this array
 *                        must be equal to the threshold (can be NULL).
                   pok64: pointer to the proof of knowledge of the first
 *                        coefficient
 *   In:          seed32: a 32-byte seed used to generate the VSS commitments
 *             threshold: the minimum number of signers required to produce a
 *                        signature
 */
SECP256K1_API int secp256k1_frost_vss_gen(
    const secp256k1_context *ctx,
    secp256k1_pubkey *vss_commitment,
    unsigned char *pok64,
    const unsigned char *seed32,
    size_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);


/** Creates a key generation share
 *
 *  To generate a key, each participant generates a share for each other
 *  participant. For example, in the case of 2 particpants, Alice and Bob, they
 *  each generate 2 shares, distribute 1 share to each other using a secure
 *  channel, and keep 1 for themselves.
 *
 *  Each participant _must_ have a secure channel with each other participant
 *  with which they can transmit shares to each other.
 *
 *  A new session_id32 _must_ be used for each key generation session. For
 *  example, in the case of 2 participants, Alice and Bob, Alice will generate
 *  a session_id32 and use it for each of the 2 calls to
 *  secp256k1_frost_share_gen and Bob will generate a session_id32 and use it
 *  for each of the 2 calls to secp256k1_frost_share_gen. Both Alice and Bob
 *  must NOT REUSE there respective session_id32 again for subsequent key
 *  generation sessions. If Alice and Bob fail to complete this session or
 *  start a new session to generate a new key, they must NOT REUSE their
 *  respective session_id32 again, but instead generate a new one. It is
 *  recommended to always choose session_id32 uniformly at random to avoid
 *  their reuse.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object initialized for
 *                        verification
 *  Out:           share: pointer to the key generation share
 *   In:    session_id32: a 32-byte session_id32 as explained above
 *          recipient_pk: pointer to the public key of the share recipient
 *             threshold: the minimum number of signers required to produce a
 *                        signature
 */
SECP256K1_API int secp256k1_frost_share_gen(
    const secp256k1_context *ctx,
    secp256k1_frost_share *share,
    const unsigned char *session_id32,
    const secp256k1_xonly_pubkey *recipient_pk,
    size_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Aggregates shares
 *
 *  As part of the key generation protocol, each participant receives a share
 *  from each participant, including a share they "receive" from themselves.
 *  This function verifies those shares against their VSS commitments,
 *  aggregates the shares, and then aggregates the commitments to each
 *  participant's first polynomial coefficient to derive the aggregate public
 *  key.
 *
 *  This function outputs a vss_hash, which is a sha256 image of the VSS of all
 *  participants. The vss_hash _must_ be signed and distributed to each other
 *  participant, and upon receiving a signed vss_hash from each other
 *  participant, the signature must be verified against the vss_hash generated
 *  by the receiving participant, otherwise the key generation session must be
 *  aborted. This vss_commitments _must_ be sorted by the x-only pubkeys of the
 *  participants, otherwise the vss_hash generated will be invalid.
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
 *           vss_hash: sha256 image of the coefficient commitments
 *  In:        shares: all key generation shares for the partcipant's index
 *    vss_commitments: coefficient commitments of all participants ordered by
 *                     the x-only pubkeys of the participants
 *           n_shares: the total number of shares
 *          threshold: the minimum number of shares required to produce a
 *                     signature
 *                 pk: the public key of the participant whose shares are being
 *                     aggregated
 */
SECP256K1_API int secp256k1_frost_share_agg(
    const secp256k1_context* ctx,
    secp256k1_frost_share *agg_share,
    secp256k1_xonly_pubkey *agg_pk,
    unsigned char *vss_hash,
    const secp256k1_frost_share * const* shares,
    const secp256k1_pubkey * const* vss_commitments,
    size_t n_shares,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(9);

/** Verifies a share received during a key generation session
 *
 *  The signature is verified against the VSS commitment received with the
 *  share.
 *
 *  Returns: 0 if the arguments are invalid or the share does not verify, 1
 *           otherwise
 *  Args         ctx: pointer to a context object, initialized for verification
 *  In:    threshold: the minimum number of signers required to produce a
 *                    signature
 *                pk: pointer to the public key of the share recipient
 *             share: pointer to a key generation share
 *    vss_commitment: the commitments to the coeffcieints used to generate the
 *                    share
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_share_verify(
    const secp256k1_context* ctx,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_frost_share *share,
    const secp256k1_pubkey * const* vss_commitment
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

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
    const secp256k1_context* ctx,
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
    const secp256k1_context* ctx,
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
 *  Args:            ctx: pointer to a context object initialized for verification
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
    const secp256k1_context* ctx,
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
 *  Args:            ctx: pointer to a context object initialized for verification
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
    const secp256k1_context* ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_cache *tweak_cache,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Computes a public verification share used for verifying partial signatures
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  In:     pubshare: pointer to a struct to store the public verification
 *                    share
 *         threshold: the minimum number of signers required to produce a
 *                    signature
 *                pk: pointer to the public key of the participant whose
 *                    partial signature will be verified with the pubshare
 *   vss_commitments: coefficient commitments of all participants
 */
SECP256K1_API int secp256k1_frost_compute_pubshare(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubshare,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_pubkey * const* vss_commitments,
    size_t n_participants
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

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
 *  Args:         ctx: pointer to a context object, initialized for signing
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
    const secp256k1_context* ctx,
    secp256k1_frost_secnonce *secnonce,
    secp256k1_frost_pubnonce *pubnonce,
    const unsigned char *session_id32,
    const secp256k1_frost_share *agg_share,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Takes the public nonces of all signers and computes a session that is
 * required for signing and verification of partial signatures. The pubkeys can
 * be sorted before combining with `secp256k1_xonly_sort`, but the
 * corresponding pubnonces must be resorted as well. All signers must use the
 * same sorting of pubnonces, otherwise signing will fail.
 *
 *  Returns: 0 if the arguments are invalid or if some signer sent invalid
 *           pubnonces, 1 otherwise
 *  Args:          ctx: pointer to a context object, initialized for
 *                      verification
 *  Out:       session: pointer to a struct to store the session
 *  In:      pubnonces: array of pointers to public nonces sent by the signers
 *         n_pubnonces: number of elements in the pubnonces array. Must be
 *                      greater than 0.
 *               msg32: the 32-byte message to sign
 *              agg_pk: the FROST-aggregated public key
 *                  pk: the public key of the participant who will use the
 *                      session for signing
 *             pubkeys: array of pointers to public keys of the signers
 *         tweak_cache: pointer to frost_tweak_cache struct (can be NULL)
 *             adaptor: optional pointer to an adaptor point encoded as a
 *                      public key if this signing session is part of an
 *                      adaptor signature protocol (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_nonce_process(
    const secp256k1_context* ctx,
    secp256k1_frost_session *session,
    const secp256k1_frost_pubnonce * const* pubnonces,
    size_t n_pubnonces,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_xonly_pubkey * const* pubkeys,
    const secp256k1_frost_tweak_cache *tweak_cache,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Produces a partial signature
 *
 *  This function overwrites the given secnonce with zeros and will abort if given a
 *  secnonce that is all zeros. This is a best effort attempt to protect against nonce
 *  reuse. However, this is of course easily defeated if the secnonce has been
 *  copied (or serialized). Remember that nonce reuse will leak the secret key!
 *
 *  Returns: 0 if the arguments are invalid or the provided secnonce has already
 *           been used for signing, 1 otherwise
 *  Args:         ctx: pointer to a context object
 *  Out:  partial_sig: pointer to struct to store the partial signature
 *  In/Out:  secnonce: pointer to the secnonce struct created in
 *                     frost_nonce_gen that has been never used in a
 *                     partial_sign call before
 *  In:     agg_share: the aggregated share
 *            session: pointer to the session that was created with
 *                     frost_nonce_process
 *        tweak_cache: pointer to frost_tweak_cache struct (can be NULL)
 */
SECP256K1_API int secp256k1_frost_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_frost_partial_sig *partial_sig,
    secp256k1_frost_secnonce *secnonce,
    const secp256k1_frost_share *agg_share,
    const secp256k1_frost_session *session,
    const secp256k1_frost_tweak_cache *tweak_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verifies an individual signer's partial signature
 *
 *  The signature is verified for a specific signing session. In order to avoid
 *  accidentally verifying a signature from a different or non-existing signing
 *  session, you must ensure the following:
 *    1. The `tweak_cache` argument is identical to the one used to create the
 *       `session` with `frost_nonce_process`.
 *    2. The `pubshare` argument must be the output of
 *       `secp256k1_frost_compute_pubshare` for the signer's 'pk'.
 *    3. The `pubnonce` argument must be identical to the one sent by the
 *       signer and used to create the `session` with `frost_nonce_process`.
 *
 *  This function can be used to assign blame for a failed signature.
 *
 *  Returns: 0 if the arguments are invalid or the partial signature does not
 *           verify, 1 otherwise
 *  Args         ctx: pointer to a context object, initialized for verification
 *  In:  partial_sig: pointer to partial signature to verify, sent by
 *                    the signer associated with `pubnonce` and `pubkey`
 *          pubnonce: public nonce of the signer in the signing session
 *          pubshare: public verification share of the signer in the signing
 *                    session that is the output of
 *                    `secp256k1_frost_compute_pubshare`
 *           session: pointer to the session that was created with
 *                    `frost_nonce_process`
 *       tweak_cache: pointer to frost_tweak_cache struct (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_frost_partial_sig *partial_sig,
    const secp256k1_frost_pubnonce *pubnonce,
    const secp256k1_pubkey *pubshare,
    const secp256k1_frost_session *session,
    const secp256k1_frost_tweak_cache *tweak_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Aggregates partial signatures
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
 *           the resulting signature verifies).
 *  Args:         ctx: pointer to a context object
 *  Out:        sig64: complete (but possibly invalid) Schnorr signature
 *  In:       session: pointer to the session that was created with
 *                     frost_nonce_process
 *       partial_sigs: array of pointers to partial signatures to aggregate
 *             n_sigs: number of elements in the partial_sigs array. Must be
 *                     greater than 0.
 */
SECP256K1_API int secp256k1_frost_partial_sig_agg(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const secp256k1_frost_session *session,
    const secp256k1_frost_partial_sig * const* partial_sigs,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts the nonce_parity bit from a session
 *
 *  This is used for adaptor signatures.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:         ctx: pointer to a context object
 *  Out: nonce_parity: pointer to an integer that indicates the parity
 *                     of the aggregate public nonce. Used for adaptor
 *                     signatures.
 *  In:       session: pointer to the session that was created with
 *                     frost_nonce_process
 */
SECP256K1_API int secp256k1_frost_nonce_parity(
    const secp256k1_context* ctx,
    int *nonce_parity,
    const secp256k1_frost_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Verifies that the adaptor can be extracted by combining the adaptor
 *  pre-signature and the completed signature.
 *
 *  Returns: 0 if the arguments are invalid or the adaptor signature does not
 *           verify, 1 otherwise
 *  Args:         ctx: pointer to a context object
 *  In:     pre_sig64: 64-byte pre-signature
 *              msg32: the 32-byte message being verified
 *             pubkey: pointer to an x-only public key to verify with
 *            adaptor: pointer to the adaptor point being verified
 *       nonce_parity: the output of `frost_nonce_parity` called with the
 *                     session used for producing the pre-signature
 */
SECP256K1_API int secp256k1_frost_verify_adaptor(
    const secp256k1_context* ctx,
    const unsigned char *pre_sig64,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_pubkey *adaptor,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Creates a signature from a pre-signature and an adaptor.
 *
 *  If the sec_adaptor32 argument is incorrect, the output signature will be
 *  invalid. This function does not verify the signature.
 *
 *  Returns: 0 if the arguments are invalid, or pre_sig64 or sec_adaptor32 contain
 *           invalid (overflowing) values. 1 otherwise (which does NOT mean the
 *           signature or the adaptor are valid!)
 *  Args:         ctx: pointer to a context object
 *  Out:        sig64: 64-byte signature. This pointer may point to the same
 *                     memory area as `pre_sig`.
 *  In:     pre_sig64: 64-byte pre-signature
 *      sec_adaptor32: 32-byte secret adaptor to add to the pre-signature
 *       nonce_parity: the output of `frost_nonce_parity` called with the
 *                     session used for producing the pre-signature
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_adapt(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *pre_sig64,
    const unsigned char *sec_adaptor32,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a FROST pre-signature and corresponding
 *  signature
 *
 *  This function will not fail unless given grossly invalid data; if it is
 *  merely given signatures that do not verify, the returned value will be
 *  nonsense. It is therefore important that all data be verified at earlier
 *  steps of any protocol that uses this function. In particular, this includes
 *  verifying all partial signatures that were aggregated into pre_sig64.
 *
 *  Returns: 0 if the arguments are NULL, or sig64 or pre_sig64 contain
 *           grossly invalid (overflowing) values. 1 otherwise (which does NOT
 *           mean the signatures or the adaptor are valid!)
 *  Args:         ctx: pointer to a context object
 *  Out:sec_adaptor32: 32-byte secret adaptor
 *  In:         sig64: complete, valid 64-byte signature
 *          pre_sig64: the pre-signature corresponding to sig64, i.e., the
 *                     aggregate of partial signatures without the secret
 *                     adaptor
 *       nonce_parity: the output of `frost_nonce_parity` called with the
 *                     session used for producing sig64
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_extract_adaptor(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *sig64,
    const unsigned char *pre_sig64,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif