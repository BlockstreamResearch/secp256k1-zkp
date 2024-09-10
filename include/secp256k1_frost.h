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
} secp256k1_frost_keygen_cache;

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

/** Serialize a FROST partial signature
 *
 *  Returns: 1 when the signature could be serialized, 0 otherwise
 *  Args:    ctx: pointer to a context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_frost_partial_sig_serialize(
    const secp256k1_context *ctx,
    unsigned char *out32,
    const secp256k1_frost_partial_sig *sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: pointer to a context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature verification with it is
 *  guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_frost_partial_sig_parse(
    const secp256k1_context *ctx,
    secp256k1_frost_partial_sig *sig,
    const unsigned char *in32
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
 *  2. If you already know the seckey, message or group public key, they
 *     can be optionally provided to derive the nonce and increase
 *     misuse-resistance. The extra_input32 argument can be used to provide
 *     additional data that does not repeat in normal scenarios, such as the
 *     current time.
 *  3. Avoid copying (or serializing) the secnonce. This reduces the possibility
 *     that it is used more than once for signing.
 *
 *  Remember that nonce reuse will leak the secret share!
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
 *       keygen_cache: pointer to the keygen_cache that was used to create the group
 *                     (and potentially tweaked) public key if already known
 *                     (can be NULL)
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
    const secp256k1_frost_keygen_cache *keygen_cache,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Takes the public nonces of all signers and computes a session that is
 *  required for signing and verification of partial signatures. The participant
 *  IDs can be sorted before combining, but the corresponding pubnonces must be
 *  resorted as well. All signers must use the same sorting of pubnonces,
 *  otherwise signing will fail.
 *
 *  Returns: 0 if the arguments are invalid or if some signer sent invalid
 *           pubnonces, 1 otherwise
 *  Args:          ctx: pointer to a context object
 *  Out:       session: pointer to a struct to store the session
 *  In:      pubnonces: array of pointers to public nonces sent by the signers
 *         n_pubnonces: number of elements in the pubnonces array. Must be
 *                      greater than 0.
 *               msg32: the 32-byte message to sign
 *            myd_id33: the 33-byte ID of the participant who will use the
 *                      session for signing
 *               ids33: array of the 33-byte participant IDs of the signers
 *         keygen_cache: pointer to frost_keygen_cache struct
 *             adaptor: optional pointer to an adaptor point encoded as a
 *                      public key if this signing session is part of an
 *                      adaptor signature protocol (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_nonce_process(
    const secp256k1_context *ctx,
    secp256k1_frost_session *session,
    const secp256k1_frost_pubnonce * const *pubnonces,
    size_t n_pubnonces,
    const unsigned char *msg32,
    const unsigned char *my_id33,
    const unsigned char * const *ids33,
    const secp256k1_frost_keygen_cache *keygen_cache,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Produces a partial signature
 *
 *  This function overwrites the given secnonce with zeros and will abort if given a
 *  secnonce that is all zeros. This is a best effort attempt to protect against nonce
 *  reuse. However, this is of course easily defeated if the secnonce has been
 *  copied (or serialized). Remember that nonce reuse will leak the secret share!
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
 *        keygen_cache: pointer to frost_keygen_cache struct
 */
SECP256K1_API int secp256k1_frost_partial_sign(
    const secp256k1_context *ctx,
    secp256k1_frost_partial_sig *partial_sig,
    secp256k1_frost_secnonce *secnonce,
    const secp256k1_frost_share *agg_share,
    const secp256k1_frost_session *session,
    const secp256k1_frost_keygen_cache *keygen_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verifies an individual signer's partial signature
 *
 *  The signature is verified for a specific signing session. In order to avoid
 *  accidentally verifying a signature from a different or non-existing signing
 *  session, you must ensure the following:
 *    1. The `keygen_cache` argument is identical to the one used to create the
 *       `session` with `frost_nonce_process`.
 *    2. The `pubshare` argument must be the output of
 *       `secp256k1_frost_compute_pubshare` for the signer's ID.
 *    3. The `pubnonce` argument must be identical to the one sent by the
 *       signer and used to create the `session` with `frost_nonce_process`.
 *
 *  This function can be used to assign blame for a failed signature.
 *
 *  Returns: 0 if the arguments are invalid or the partial signature does not
 *           verify, 1 otherwise
 *  Args         ctx: pointer to a context object
 *  In:  partial_sig: pointer to partial signature to verify, sent by
 *                    the signer associated with `pubnonce` and `pubkey`
 *          pubnonce: public nonce of the signer in the signing session
 *          pubshare: public verification share of the signer in the signing
 *                    session that is the output of
 *                    `secp256k1_frost_compute_pubshare`
 *           session: pointer to the session that was created with
 *                    `frost_nonce_process`
 *       keygen_cache: pointer to frost_keygen_cache struct
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_partial_sig_verify(
    const secp256k1_context *ctx,
    const secp256k1_frost_partial_sig *partial_sig,
    const secp256k1_frost_pubnonce *pubnonce,
    const secp256k1_pubkey *pubshare,
    const secp256k1_frost_session *session,
    const secp256k1_frost_keygen_cache *keygen_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

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
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const secp256k1_frost_session *session,
    const secp256k1_frost_partial_sig * const *partial_sigs,
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
    const secp256k1_context *ctx,
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
    const secp256k1_context *ctx,
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
    const secp256k1_context *ctx,
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
    const secp256k1_context *ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *sig64,
    const unsigned char *pre_sig64,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
