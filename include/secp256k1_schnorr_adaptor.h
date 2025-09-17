#ifndef SECP256K1_SCHNORR_ADAPTOR_H
#define SECP256K1_SCHNORR_ADAPTOR_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module provides an experimental implementation of a Schnorr adaptor
 *  signature protocol variant.
 *
 *  The test vectors have been generated and cross-verified using a Python
 *  implementation of this adaptor signature variant available at [0].
 *
 *  The protocol involves two parties, Alice and Bob. The general sequence of
 *  their interaction is as follows:
 *  1. Alice calls the `schnorr_adaptor_presign` function for an adaptor point T
 *  and sends the pre-signature to Bob.
 *  2. Bob extracts the adaptor point T from the pre-signature using
 *  `schnorr_adaptor_extract`.
 *  3. Bob provides the pre-signature and the discrete logarithm of T to
 *  `schnorr_adaptor_adapt` which outputs a valid BIP 340 Schnorr signature.
 *  4. Alice extracts the discrete logarithm of T from the pre-signature and the
 *  BIP 340 signature using `schnorr_adaptor_extract_sec`.
 *
 *  In contrast to common descriptions of adaptor signature protocols, this
 *  module does not provide a verification algorithm for pre-signatures.
 *  Instead, `schnorr_adaptor_extract` returns the adaptor point encoded by a
 *  pre-signature, reducing communication cost. If a verification function for
 *  pre-signatures is needed, it can be easily simulated with
 *  `schnorr_adaptor_extract`.
 *
 *  Assuming that BIP 340 Schnorr signatures satisfy strong unforgeability under
 *  chosen message attack, the Schnorr adaptor signature scheme fulfills the
 *  following properties as formalized by [1].
 *
 *  - Witness extractability:
 *    If Alice
 *      1. creates a pre-signature with `schnorr_adaptor_presign` for message m
 *         and adaptor point T and
 *      2. receives a Schnorr signature for message m that she hasn't created
 *         herself,
 *    then Alice is able to obtain the discrete logarithm of T with
 *    `schnorr_adaptor_extract_sec`.
 *
 *  - Pre-signature adaptability:
 *    If Bob
 *      1. receives a pre-signature and extracts an adaptor point T using
 *         `schnorr_adaptor_extract`, and
 *      2. obtains the discrete logarithm of the adaptor point T
 *    Then then Bob is able to adapt the received pre-signature to a valid BIP
 *    340 Schnorr signature using `schnorr_adaptor_adapt`.
 *
 *  - Existential Unforgeability:
 *    Bob is not able to create a BIP 340 signature from a pre-signature for
 *    adaptor T without knowing the discrete logarithm of T.
 *
 *  - Pre-signature existiential unforgeability:
 *    Only Alice can create a pre-signature for her public key.
 *
 *  [0] https://github.com/ZhePang/Python_Specification_for_Schnorr_Adaptor
 *  [1] https://eprint.iacr.org/2020/476.pdf
 */

/** A pointer to a function to deterministically generate a nonce.
 *
 *  In addition to the features of secp256k1_nonce_function_hardened,
 *  this function introduces an extra argument for a compressed 33-byte
 *  adaptor point.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:  nonce32: pointer to a 32-byte array to be filled by the function
 *  In:     msg32: the 32-byte message being verified (will not be NULL)
 *          key32: pointer to a 32-byte secret key (will not be NULL)
*       adaptor33: the 33-byte serialized adaptor point (will not be NULL)
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
typedef int (*secp256k1_nonce_function_hardened_schnorr_adaptor)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *adaptor33,
    const unsigned char *xonly_pk32,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** A modified BIP-340 nonce generation function. If a data pointer is passed, it is
 *  assumed to be a pointer to 32 bytes of auxiliary random data as defined in BIP-340.
 *  If the data pointer is NULL, the nonce derivation procedure uses a zeroed 32-byte
 *  auxiliary random data. The hash will be tagged with algo after removing all
 *  terminating null bytes.
 */
SECP256K1_API const secp256k1_nonce_function_hardened_schnorr_adaptor secp256k1_nonce_function_schnorr_adaptor;

/** Creates a pre-signature for a given message and adaptor point.
 *
 *  The pre-signature can be converted into a valid BIP-340 Schnorr signature
 *  (using `schnorr_adaptor_adapt`) by combining it with the discrete logarithm
 *  of the adaptor point.
 *
 *  This function only signs 32-byte messages. If you have messages of a
 *  different size (or the same size but without a context-specific tag
 *  prefix), it is recommended to create a 32-byte message hash with
 *  secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
 *  providing an context-specific tag for domain separation. This prevents
 *  signatures from being valid in multiple contexts by accident.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:        ctx: pointer to a context object (not secp256k1_context_static).
 *  Out:   pre_sig65: pointer to a 65-byte array to store the pre-signature.
 *  In:        msg32: the 32-byte message being signed.
 *           keypair: pointer to an initialized keypair.
 *           adaptor: pointer to an adaptor point encoded as a public key.
 *        aux_rand32: pointer to arbitrary data used by the nonce generation
 *                    function (can be NULL). If it is non-NULL and
 *                    secp256k1_nonce_function_schnorr_adaptor is used, then
 *                    aux_rand32 must be a pointer to 32-byte auxiliary randomness
 *                    as per BIP-340.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_presign(
    const secp256k1_context *ctx,
    unsigned char *pre_sig65,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const secp256k1_pubkey *adaptor,
    const unsigned char *aux_rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Extracts the adaptor point from a pre-signature.
 *
 *  This function assumes that pre_sig65 was created using the corresponding
 *  msg32, pubkey, and a valid adaptor point, which it will extract. If these
 *  inputs are not related (e.g., if pre_sig65 was generated with a different
 *  key or message), the extracted adaptor point will be incorrect. However,
 *  the function will still return 1 to indicate a successful extraction.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object.
 *  Out:      adaptor: pointer to store the adaptor point.
 *  In:     pre_sig65: pointer to a 65-byte pre-signature.
 *              msg32: the 32-byte message associated with presig_65
 *             pubkey: pointer to the x-only public key associated with pre_sig65
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract(
    const secp256k1_context *ctx,
    secp256k1_pubkey *adaptor,
    const unsigned char *pre_sig65,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Adapts the pre-signature to produce a BIP-340 Schnorr signature.
 *
 *  The output BIP-340 signature is not verified by this function.
 *  To verify it, use `secp256k1_schnorrsig_verify`.
 *
 *  If the pre_sig65 and sec_adaptor32 values are not related, the
 *  output signature will be invalid. In this case, the function will
 *  still return 1 to indicate successful execution.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object.
 *  Out:          sig64: pointer to a 64-byte array to store the adapted
 *                       pre-signature. This pointer may point to the same
 *                       memory area as `pre_sig65`.
 *  In:       pre_sig65: pointer to a 65-byte pre-signature.
 *        sec_adaptor32: pointer to a 32-byte secret adaptor associated with pre_sig65
 */
SECP256K1_API int secp256k1_schnorr_adaptor_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *pre_sig65,
    const unsigned char *sec_adaptor32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts the secret adaptor (discrete logarithm of the adaptor point)
 *  from a pre-signature and the corresponding BIP-340 signature.
 *
 *  This function assumes that the sig64 was created by adapting pre_sig65.
 *  If these inputs are not related, the extracted secret adaptor will be
 *  incorrect. However, the function will still return 1 to indicate successful
 *  extraction.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object.
 *  Out:  sec_adaptor32: pointer to a 32-byte array to store the secret adaptor.
 *  In:       pre_sig65: pointer to a 65-byte pre-signature.
 *                sig64: pointer to a valid 64-byte BIP-340 Schnorr signature
 *                       associated with pre_sig65.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract_sec(
    const secp256k1_context *ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *pre_sig65,
    const unsigned char *sig64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORR_ADAPTOR_H */
