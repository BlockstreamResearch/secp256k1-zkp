#ifndef _SECP256K1_POINTS_
# define _SECP256K1_POINTS_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** Opaque data structure that holds a parsed and valid curve point.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_point_serialize and secp256k1_point_parse.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_point;


/** Parse point into the point object.
 *
 *  Returns: 1 if point was fully valid.
 *           0 if point could not be parsed or is invalid.
 *
 *  Out:  point:    pointer to a point object. If 1 is returned, it is set to a
 *                  parsed version of input. If not, its value is undefined.
 *  In:   input:    pointer to a serialized 33 bytes point
 *
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_point_parse(
    secp256k1_point* point,
    const unsigned char *input
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serialize a point object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *
 *  Out:    output:     a pointer to a 33-byte byte array to place the serialized
 *                      point in.
 *                      
 *  In:     point :     a pointer to a secp256k1_point containing an
 *                      initialized point.
 */
SECP256K1_API int secp256k1_point_serialize(
    unsigned char *output,
    const secp256k1_point* point
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Sum a number of points together.
 *  Returns: 1: the sum of the points is valid.
 *           0: the sum of the points is not valid.
 *
 *  Out:    out:        pointer to a point object for placing the resulting point
 *                      (cannot be NULL)
 *  In:     addends:    pointer to array of pointers to points (cannot be NULL)
 *          n:          the number of points to add together (must be at least 1)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_points_combine(
    secp256k1_point *out,
    const secp256k1_point * const * addends,
    size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Multiply point on curve by scalar
 * Returns: 0 if the scalar was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
 * Args:    ctx:         pointer to a context object initialized for 
 *                       validation (cannot be NULL).
 * In/Out:  point:       pointer to a point object.
 * In:      multiplier:  pointer to a 32-byte scalar.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_point_mul(
    const secp256k1_context* ctx,
    secp256k1_point *point,
    const unsigned char *multiplier
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Cast curve point object to pubkey object
 *
 * In:      point:       pointer to a point object (cannot be NULL).
 * Out:     pubkey:      pointer to a pubkey (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_point_to_pubkey(
    secp256k1_point* point, 
    secp256k1_pubkey* pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Cast pubkey object to curve point object
 * Args:    ctx:         pointer to a context object initialized for 
 *                       validation (cannot be NULL).
 * In:     pubkey:       pointer to a pubkey (cannot be NULL).
 * Out:    point:        pointer to a point object (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_pubkey_to_point(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    secp256k1_point* point
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

#ifdef ENABLE_MODULE_GENERATOR

/** Cast curve point object to generator object
 *
 * In:      point:       pointer to a point object (cannot be NULL).
 * Out:     generator:   pointer to a generator (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_point_to_generator(
    secp256k1_point* point, 
    secp256k1_generator* generator
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Cast generator object to curve point object
 *
 * In:     generator:    pointer to a generator (cannot be NULL).
 * Out:    point:        pointer to a point object (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_generator_to_point(
    secp256k1_generator* generator,
    secp256k1_point* point
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#endif /* ENABLE_MODULE_GENERATOR */

#ifdef ENABLE_MODULE_RANGEPROOF

/** Cast curve point object to pedersen commitment object
 *
 * In:      point:       pointer to a point object (cannot be NULL).
 * Out:     generator:   pointer to a generator (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_point_to_pedersen_commitment(
    secp256k1_point* point, 
    secp256k1_pedersen_commitment* pedersen_commitment
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Cast generator object to curve point object
 *
 * In:     pedersen_commitment: pointer to a generator (cannot be NULL).
 * Out:    point:               pointer to a point object (cannot be NULL).
 */
SECP256K1_API void secp256k1_points_cast_pedersen_commitment_to_point(
    secp256k1_pedersen_commitment* pedersen_commitment,
    secp256k1_point* point
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#endif /* ENABLE_MODULE_RANGEPROOF */


# ifdef __cplusplus
}
# endif

#endif
