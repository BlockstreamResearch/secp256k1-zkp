#ifndef SECP256K1_SCHNORRSIG_H
#define SECP256K1_SCHNORRSIG_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a variant of Schnorr signatures compliant with
 * BIP-schnorr
 * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).
 */

/** Opaque data structure that holds a parsed Schnorr signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_schnorrsig_serialize` and
 *  `secp256k1_schnorrsig_parse` functions.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig;

/** Serialize a Schnorr signature.
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out64: pointer to a 64-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 *
 *  See secp256k1_schnorrsig_parse for details about the encoding.
 */
SECP256K1_API int secp256k1_schnorrsig_serialize(
    const secp256k1_context* ctx,
    unsigned char *out64,
    const secp256k1_schnorrsig* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a Schnorr signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in64: pointer to the 64-byte signature to be parsed
 *
 * The signature is serialized in the form R||s, where R is a 32-byte public
 * key (x-coordinate only; the y-coordinate is considered to be the unique
 * y-coordinate satisfying the curve equation that is a quadratic residue)
 * and s is a 32-byte big-endian scalar.
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_schnorrsig_parse(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig* sig,
    const unsigned char *in64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *       nonce_is_negated: a pointer to an integer indicates if signing algorithm negated the
 *                nonce (can be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bipschnorr is used
 *         ndata: pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_sign(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig *sig,
    int *nonce_is_negated,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature being verified (cannot be NULL)
 *         msg32: the 32-byte message hash being verified (cannot be NULL)
 *        pubkey: pointer to a public key to verify with (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const secp256k1_schnorrsig *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verifies a set of Schnorr signatures.
 *
 * Returns 1 if all succeeded, 0 otherwise. In particular, returns 1 if n_sigs is 0.
 *
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays. Must be smaller than
 *                2^31 and smaller than half the maximum size_t value. Must be 0
 *                if above arrays are NULL.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify_batch(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_schnorrsig *const *sig,
    const unsigned char *const *msg32,
    const secp256k1_pubkey *const *pk,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRSIG_H */
