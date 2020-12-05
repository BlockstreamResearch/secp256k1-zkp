#ifndef SECP256K1_ECDSA_S2C_H
#define SECP256K1_ECDSA_S2C_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Data structure that holds a sign-to-contract ("s2c") opening information.
 *  Sign-to-contract allows a signer to commit to some data as part of a signature. It
 *  can be used as an Out-argument in certain signing functions.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_ecdsa_s2c_opening_serialize and secp256k1_ecdsa_s2c_opening_parse.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_s2c_opening;

/** Parse a sign-to-contract opening.
 *
 *  Returns: 1 if the opening could be parsed
 *           0 if the opening could not be parsed
 *  Args:    ctx: a secp256k1 context object.
 *  Out: opening: pointer to an opening object. If 1 is returned, it is set to a
 *                parsed version of input. If not, its value is unspecified.
 *  In:  input33: pointer to 33-byte array with a serialized opening
 *
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_opening_parse(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_s2c_opening* opening,
    const unsigned char* input33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a sign-to-contract opening into a byte sequence.
 *
 *  Returns: 1 if the opening was successfully serialized.
 *           0 if the opening could not be serialized
 *  Args:     ctx: a secp256k1 context object
 *  Out: output33: pointer to a 33-byte array to place the serialized opening in
 *  In:   opening: a pointer to an initialized `secp256k1_ecdsa_s2c_opening`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_opening_serialize(
    const secp256k1_context* ctx,
    unsigned char* output33,
    const secp256k1_ecdsa_s2c_opening* opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Same as secp256k1_ecdsa_sign, but s2c_data32 is committed to inside the nonce
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:  pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:  pointer to an array where the signature will be placed (cannot be NULL)
 *   s2c_opening:  if non-NULL, pointer to an secp256k1_ecdsa_s2c_opening structure to populate
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *    s2c_data32: pointer to a 32-byte data to commit to in the nonce (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_s2c_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    secp256k1_ecdsa_s2c_opening* s2c_opening,
    const unsigned char* msg32,
    const unsigned char* seckey,
    const unsigned char* s2c_data32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verify a sign-to-contract commitment.
 *
 *  Returns: 1: the signature contains a commitment to data32 (though it does
 *              not necessarily need to be a valid siganture!)
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature containing the sign-to-contract commitment (cannot be NULL)
 *        data32: the 32-byte data that was committed to (cannot be NULL)
 *       opening: pointer to the opening created during signing (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_verify_commit(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *data32,
    const secp256k1_ecdsa_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_S2C_H */
