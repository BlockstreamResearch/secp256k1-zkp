#ifndef SECP256K1_MUSIG_ADAPTOR_H
#define SECP256K1_MUSIG_ADAPTOR_H

#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements adaptor signature support for the MuSig2 module.
 *
 *  It provides functions to create adaptor (pre-)signatures using the MuSig2
 *  protocol, adapt pre-signatures into valid signatures, and extract secret
 *  adaptors from signature/pre-signature pairs.
 *
 *  This module depends on the musig module.
 */

/** Takes the aggregate nonce and creates a session that is required for signing
 *  and verification of partial signatures, with adaptor signature support.
 *
 *  The output of musig_partial_sig_agg will be a pre-signature which is not a
 *  valid Schnorr signature. In order to create a valid signature, the
 *  pre-signature and the secret adaptor must be provided to `musig_adapt`.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:          ctx: pointer to a context object
 *  Out:       session: pointer to a struct to store the session
 *  In:       aggnonce: pointer to an aggregate public nonce object that is the
 *                      output of musig_nonce_agg
 *              msg32:  the 32-byte message to sign
 *       keyagg_cache:  pointer to the keyagg_cache that was used to create the
 *                      aggregate (and potentially tweaked) pubkey
 *            adaptor:  pointer to an adaptor point encoded as a public key.
 *                      This signing session is part of an adaptor signature
 *                      protocol.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_nonce_process_adaptor(
    const secp256k1_context *ctx,
    secp256k1_musig_session *session,
    const secp256k1_musig_aggnonce *aggnonce,
    const unsigned char *msg32,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

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
 *                     musig_nonce_process
 */
SECP256K1_API int secp256k1_musig_nonce_parity(
    const secp256k1_context *ctx,
    int *nonce_parity,
    const secp256k1_musig_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

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
 *       nonce_parity: the output of `musig_nonce_parity` called with the
 *                     session used for producing the pre-signature
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *pre_sig64,
    const unsigned char *sec_adaptor32,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a MuSig pre-signature and corresponding
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
 *       nonce_parity: the output of `musig_nonce_parity` called with the
 *                     session used for producing sig64
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_extract_adaptor(
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
