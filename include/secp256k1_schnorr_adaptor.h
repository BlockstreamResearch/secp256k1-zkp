#ifndef SECP256K1_SCHNORR_ADAPTOR_H
#define SECP256K1_SCHNORR_ADAPTOR_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as secp256k1_schnorrsig_nonce function with the exception of accepting an
 *  additional adaptor point argument.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:  nonce32: pointer to a 32-byte array to be filled by the function
 *  In:     msg32: the 32-byte message being verified (will not be NULL)
 *          key32: pointer to a 32-byte secret key (will not be NULL)
 *      adaptor33: the 33-byte serialized adaptor point (will not be NULL)
 *     xonly_pk32: the 32-byte serialized xonly pubkey corresponding to key32
 *                 (will not be NULL)
 *           algo: pointer to an array describing the signature
 *                 algorithm (will not be NULL)
 *        algolen: the length of the algo array
 *           data: arbitrary data pointer that is passed through
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the adaptor point, the pubkey, the algorithm description, and data.
 */
typedef int (*secp256k1_adaptor_nonce_function_hardened)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *adaptor33,
    const unsigned char *xonly_pk32,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** A Schnorr Adaptor nonce generation function. */
SECP256K1_API const secp256k1_adaptor_nonce_function_hardened secp256k1_nonce_function_schnorr_adaptor;

/** Create a Schnorr adaptor signature.
 *
 *  This function only signs 32-byte messages. If you have messages of a
 *  different size (or the same size but without a context-specific tag
 *  prefix), it is recommended to create a 32-byte message hash with
 *  secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
 *  providing an context-specific tag for domain separation. This prevents
 *  signatures from being valid in multiple contexts by accident.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:       ctx: pointer to a context object (not secp256k1_context_static).
 *  Out:   presig65: pointer to a 65-byte array to store the adaptor signature.
 *  In:       msg32: the 32-byte message being signed.
 *          keypair: pointer to an initialized keypair.
 *        adaptor33: pointer to a 33-byte compressed adaptor point.
 *       aux_rand32: 32 bytes of fresh randomness. While recommended to provide
 *                   this, it is only supplemental to security and can be NULL. A
 *                   NULL argument is treated the same as an all-zero one. See
 *                   BIP-340 "Default Signing" for a full explanation of this
 *                   argument and for guidance if randomness is expensive.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_presign(
    const secp256k1_context *ctx,
    unsigned char *presig65,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *adaptor33,
    const unsigned char *aux_rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Extract an adaptor point from the signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object.
 *  Out:    adaptor33: pointer to a 33-byte array to store the compressed adaptor point.
 *  In:      presig65: pointer to a 65-byte adaptor signature.
 *              msg32: the 32-byte message being signed.
 *             pubkey: pointer to an x-only public key to verify with
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract(
    const secp256k1_context *ctx,
    unsigned char *adaptor33,
    const unsigned char *presig65,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Adapt an adaptor signature to result in a Schnorr signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object.
 *  Out:        sig64: pointer to a 64-byte array to store the adapted Schnorr signature.
 *  In:      presig65: pointer to a 65-byte adaptor signature.
 *         secadaptor: pointer to a 32-byte secadaptor.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *presig65,
    const unsigned char *secadaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extract the secadaptor from a valid adaptor signature and a Schnorr signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object.
 *  Out:   secadaptor: pointer to a 32-byte array to store the secadaptor.
 *  In:      presig65: pointer to a 65-byte adaptor signature.
 *              sig64: pointer to a 64-byte adapted Schnorr signature.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract_sec(
    const secp256k1_context *ctx,
    unsigned char *secadaptor,
    const unsigned char *presig65,
    const unsigned char *sig64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORR_ADAPTOR_H */
