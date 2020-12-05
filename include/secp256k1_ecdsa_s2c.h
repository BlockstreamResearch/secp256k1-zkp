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

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_S2C_H */
