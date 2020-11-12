#ifndef _SECP256K1_BULLETPROOFS_
# define _SECP256K1_BULLETPROOFS_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bulletproofs_generators secp256k1_bulletproofs_generators;

/** Allocates and initializes a list of NUMS generators, along with precomputation data
 *  Returns a list of generators, or NULL if allocation failed.
 *  Args:          ctx: pointer to a context object (cannot be NULL)
 *                   n: number of NUMS generators to produce. Should be 128 to allow for
 *                      64-bit rangeproofs
 */
SECP256K1_API secp256k1_bulletproofs_generators *secp256k1_bulletproofs_generators_create(
    const secp256k1_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Allocates a list of generators from a static array
 *  Returns a list of generators, or NULL if allocation or parsing failed.
 *  Args:      ctx: pointer to a context object (cannot be NULL)
 *  In:       data: data that came from `secp256k1_bulletproofs_generators_serialize`
 *        data_len: the length of the `data` buffer
 */
SECP256K1_API secp256k1_bulletproofs_generators* secp256k1_bulletproofs_generators_parse(
    const secp256k1_context* ctx,
    const unsigned char* data,
    size_t data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serializes a list of generators to an array
 *  Returns 1 on success, 0 if the provided array was not large enough
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *               gen: pointer to the generator set to be serialized (cannot be NULL)
 *  In:         data: data that came from `secp256k1_bulletproofs_generators_serialize`
 *  In/Out: data_len: the length of the `data` buffer. Should be initially set to at
 *                    least 33 times the number of generators; will be set to 33 times
 *                    the number of generators on successful return (cannot be NULL)
 */
SECP256K1_API int secp256k1_bulletproofs_generators_serialize(
    const secp256k1_context* ctx,
    secp256k1_bulletproofs_generators* gen,
    unsigned char* data,
    size_t *data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 *          gen: pointer to the generator set to be destroyed
 */
SECP256K1_API void secp256k1_bulletproofs_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproofs_generators* gen
) SECP256K1_ARG_NONNULL(1);

# ifdef __cplusplus
}
# endif

#endif
