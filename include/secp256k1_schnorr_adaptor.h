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

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORR_ADAPTOR_H */
