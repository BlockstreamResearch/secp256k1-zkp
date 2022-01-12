#ifndef _SECP256K1_BULLETPROOFS_
# define _SECP256K1_BULLETPROOFS_

# include "secp256k1.h"
# include "secp256k1_generator.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** A function-like macro returning the size, in bytes, of an uncompressed
 *  Bulletproof proving that a value lies in the range [0, 2^(n_bits) - 1]
 *
 *  A proof contains: 65 bytes for (A, S); 65 for (T1, T2); 64 for (tau_x, mu)
 *  followed by n_bits-many scalar pairs (l(i), r(i)).
 */
#define SECP256K1_BULLETPROOFS_UNCOMPRESSED_SIZE(n_bits) (65UL + 65 + 64 + (n_bits) * 64)

/** Maximum size, in bytes, of an uncompressed rangeproof */
extern const size_t SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH;

/** The same value, as a C macro so it can be used as C89 array size */
#define SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_ \
    SECP256K1_BULLETPROOFS_UNCOMPRESSED_SIZE(64)

/** Opaque data structure that holds the current state of an uncompressed
 * Bulletproof proof generation. This data is not secret and does not need
 * to be handled carefully, but neither does it have any meaning outside
 * of the API functions that use it.
 *
 * Obviously you should not modify it or else you will get invalid proofs.
 *
 * Typical users do not need this structure. If you have more than a few
 * hundred bytes of memory to spare create a proof in one shot with the
 * TODO function instead.
 */
typedef struct {
    unsigned char data[160];
} secp256k1_bulletproofs_prover_context;

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bulletproofs_generators secp256k1_bulletproofs_generators;

/** Allocates and initializes a list of NUMS generators
 *  Returns a list of generators, or NULL if allocation failed.
 *  Args:          ctx: pointer to a context object
 *                   n: number of NUMS generators to produce. Should be 128 to allow for
 *                      64-bit rangeproofs
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT secp256k1_bulletproofs_generators *secp256k1_bulletproofs_generators_create(
    const secp256k1_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Allocates a list of generators from a static array
 *  Returns a list of generators, or NULL if allocation or parsing failed.
 *  Args:      ctx: pointer to a context object
 *  In:       data: data that came from `secp256k1_bulletproofs_generators_serialize`
 *        data_len: the length of the `data` buffer
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT secp256k1_bulletproofs_generators* secp256k1_bulletproofs_generators_parse(
    const secp256k1_context* ctx,
    const unsigned char* data,
    size_t data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serializes a list of generators to an array
 *  Returns 1 on success, 0 if the provided array was not large enough
 *  Args:        ctx: pointer to a context object
 *               gen: pointer to the generator set to be serialized
 *  Out:        data: pointer to buffer into which the generators will be serialized
 *  In/Out: data_len: the length of the `data` buffer. Should be initially set to at
 *                    least 33 times the number of generators; will be set to 33 times
 *                    the number of generators on successful return
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproofs_generators_serialize(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gen,
    unsigned char* data,
    size_t *data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object
 *          gen: pointer to the generator set to be destroyed
 *               (can be NULL, in which case this function is a no-op)
 */
SECP256K1_API void secp256k1_bulletproofs_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproofs_generators* gen
) SECP256K1_ARG_NONNULL(1);

/** Returns the serialized size of an uncompressed proof of a given number of bits
 *  Args:   ctx: pointer to a context object
 *  In:  n_bits: number of bits to prove (max 64, should usually be 64)
 */
SECP256K1_API size_t secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(
    const secp256k1_context* ctx,
    size_t n_bits
) SECP256K1_ARG_NONNULL(1);

/** Produces an uncompressed rangeproof. Returns 1 on success, 0 on failure.
 *  Args:      ctx: pointer to a context object
 *            gens: pointer to the generator set to use, which must have at least 2*n_bits generators
 *       asset_gen: pointer to the asset generator for the Pedersen/CT commitment
 *  Out:     proof: pointer to a byte array to output the proof into
 *  In/Out:   plen: pointer to the size of the above array; will be set to the actual size of
 *                  the serialized proof. To learn this value in advance, to allocate a sufficient
 *                  buffer, call `secp256k1_bulletproofs_rangeproof_uncompressed_proof_length` or
 *                  use `SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH`
 *  In:     n_bits: size of range being proven, in bits
 *           value: value committed in the Pedersen commitment
 *       min_value: minimum value of the range being proven
 *          commit: the Pedersen commitment being proven
 *           blind: blinding factor for the Pedersen commitment
 *           nonce: seed for the RNG used to generate random data during proving
 *        enc_data: 32-byte array of extra data which may be decrypted by a verifier who knows `nonce`
 *                  (may be NULL if no data is to be encrypted)
 *    extra_commit: arbitrary extra data that the proof commits to (may be NULL if extra_commit_len is 0)
 *    extra_commit_len: length of the arbitrary extra data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproofs_rangeproof_uncompressed_prove(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* asset_gen,
    unsigned char* proof,
    size_t* plen,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* blind,
    const unsigned char* nonce,
    const unsigned char* enc_data,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11);

/** Verifies an uncompressed rangeproof. Returns 1 on success, 0 on failure.
 *  Args:      ctx: pointer to a context object
 *         scratch: pointer to a scratch space
 *            gens: pointer to the generator set to use, which must have at least 2*n_bits generators
 *       asset_gen: pointer to the asset generator for the CT commitment
 *  In:      proof: pointer to a byte array containing the serialized proof
 *            plen: length of the serialized proof
 *       min_value: minimum value of the range being proven
 *          commit: the Pedersen commitment being proven
 *    extra_commit: arbitrary extra data that the proof commits to (may be NULL if extra_commit_len is 0)
 *    extra_commit_len: length of the arbitrary extra data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bulletproofs_rangeproof_uncompressed_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* asset_gen,
    const unsigned char* proof,
    const size_t plen,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(8);

# ifdef __cplusplus
}
# endif

#endif
