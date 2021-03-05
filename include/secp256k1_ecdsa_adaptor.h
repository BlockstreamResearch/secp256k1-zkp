#ifndef SECP256K1_ECDSA_ADAPTOR_H
#define SECP256K1_ECDSA_ADAPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements single signer ECDSA adaptor signatures following
 *  "One-Time Verifiably Encrypted Signatures A.K.A. Adaptor Signatures" by
 *  Lloyd Fournier
 *  (https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-November/002316.html
 *  and https://github.com/LLFourn/one-time-VES/blob/master/main.pdf).
*/

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as secp256k1_nonce_function_hardened with the exception of using the
 *  compressed 33-byte encoding for the pubkey argument.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:     nonce32:   pointer to a 32-byte array to be filled by the function
 *  In:        msg32:   the 32-byte message hash being verified
 *             key32:   pointer to a 32-byte secret key
 *              pk33:   the 33-byte serialized pubkey corresponding to key32
 *              algo:   pointer to an array describing the signature algorithm
 *           algolen:   the length of the algo array
 *              data:   arbitrary data pointer that is passed through
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the pubkey, the algorithm description, and data.
 */
typedef int (*secp256k1_nonce_function_hardened_ecdsa_adaptor)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *pk33,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** A modified BIP-340 nonce generation function. If a data pointer is passed, it is
 *  assumed to be a pointer to 32 bytes of auxiliary random data as defined in BIP-340.
 *  The hash will be tagged with algo after removing all terminating null bytes.
 */
SECP256K1_API extern const secp256k1_nonce_function_hardened_ecdsa_adaptor secp256k1_nonce_function_ecdsa_adaptor;

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_ADAPTOR_H */
