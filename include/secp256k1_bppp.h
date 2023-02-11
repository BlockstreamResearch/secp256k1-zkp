#ifndef _SECP256K1_BPPP_
# define _SECP256K1_BPPP_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

#include "include/secp256k1_generator.h"

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bppp_generators secp256k1_bppp_generators;

/** Opaque structure representing a prover context used in bulletproofs++ prover */
typedef struct secp256k1_bppp_rangeproof_prover_context secp256k1_bppp_rangeproof_prover_context;

/** Allocates and initializes a list of NUMS generators.
 *  Returns a list of generators, or calls the error callback if the allocation fails.
 *  Args:          ctx: pointer to a context object
 *                   n: number of NUMS generators to produce.
 */
SECP256K1_API secp256k1_bppp_generators *secp256k1_bppp_generators_create(
    const secp256k1_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Allocates a list of generators from a static array
 *  Returns a list of generators or NULL in case of failure.
 *  Args:      ctx: pointer to a context object
 *  In:       data: data that came from `secp256k1_bppp_generators_serialize`
 *        data_len: the length of the `data` buffer
 */
SECP256K1_API secp256k1_bppp_generators* secp256k1_bppp_generators_parse(
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
 *                    least 33 times the number of generators plus one(33 * (num_gens - 1)).
 *                    Upon success, data_len will be set to the (33 * (num_gens - 1)).
 */
SECP256K1_API int secp256k1_bppp_generators_serialize(
    const secp256k1_context* ctx,
    const secp256k1_bppp_generators* gen,
    unsigned char* data,
    size_t *data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object
 *          gen: pointer to the generator set to be destroyed
 *               (can be NULL, in which case this function is a no-op)
 */
SECP256K1_API void secp256k1_bppp_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bppp_generators* gen
) SECP256K1_ARG_NONNULL(1);

/** Returns the serialized size of an bulletproofs++ proof of a given number
 *  of bits and the base. Both base and n_bits must be a power of two. The number
 *  of digits required to represent number of bits in the given base must also be
 *  a power of two. Specifically, all of n_bits, base and num_digits = (n_bits / log2(base))
 *  must all be a power of two.
 *  Args:   ctx: pointer to a context object
 *  Out:    len: 0 if the parameters and num_digits (n_bits/log2(base)) are not a power of two
 *               length of the serialized proof otherwise
 *  In:  n_bits: number of bits to prove (max 64, should usually be 64)
 *         base: base representation to be used in proof construction (max 256, recommended 16)
 */
SECP256K1_API size_t secp256k1_bppp_rangeproof_proof_length(
    const secp256k1_context* ctx,
    size_t n_bits,
    size_t base
) SECP256K1_ARG_NONNULL(1);

/** Produces a Bulletproofs++ rangeproof. Returns 1 on success, 0 on failure.
 * Proof creation can only fail if the arguments are invalid. The documentation
 * below specifies the constraints on inputs and arguments under which this API
 * can fail.
 *  Args:      ctx: pointer to a context object
 *         scratch: pointer to a scratch space
 *            gens: pointer to the generator set to use, which must have exactly
 *                 `n = max(num_digits, base) + 7` generators, where num_digits is the number.
 *       asset_gen: pointer to the asset generator for the Pedersen/CT commitment
 *  Out:     proof: pointer to a byte array to output the proof into
 *  In/Out:   plen: pointer to the size of the above array; will be set to the actual size of
 *                  the serialized proof. To learn this value in advance, to allocate a sufficient
 *                  buffer, call `secp256k1_bppp_rangeproof_proof_length`
 *  In:     n_bits: size of range being proven, in bits. Must be a power of two,
 *                  and at most 64.
 *            base: base representation to be used in proof construction. Must be a power of two,
 *           value: value committed in the Pedersen commitment. Must be less
 *                  than 2^n_bits.
 *       min_value: minimum value of the range being proven. Must be less than value
 *          commit: the Pedersen commitment being proven
 *           blind: blinding factor for the Pedersen commitment. Must be a 32 byte
 *                  valid scalar within secp curve order.
 *           nonce: seed for the RNG used to generate random data during proving
 *    extra_commit: arbitrary extra data that the proof commits to (may be NULL if extra_commit_len is 0)
 *    extra_commit_len: length of the arbitrary extra data.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bppp_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bppp_generators* gens,
    const secp256k1_generator* asset_gen,
    unsigned char* proof,
    size_t* plen,
    const size_t n_bits,
    const size_t base,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* blind,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(11) SECP256K1_ARG_NONNULL(12) SECP256K1_ARG_NONNULL(13);

/** Verifies an Bulletproofs++ rangeproof. Returns 1 on success, 0 on failure.
 *  Args:      ctx: pointer to a context object
 *         scratch: pointer to a scratch space
 *            gens: pointer to the generator set to use, which must have at least 2*n_bits generators
 *       asset_gen: pointer to the asset generator for the CT commitment
 *  In:      proof: pointer to a byte array containing the serialized proof
 *            plen: length of the serialized proof
 *          n_bits: size of range being proven, in bits. Must be a power of two,
 *                  and at most 64.
 *            base: base representation to be used in proof construction. Must be a power of two,
 *       min_value: minimum value of the range being proven
 *          commit: the Pedersen commitment being proven
 *    extra_commit: arbitrary extra data that the proof commits to (may be NULL if extra_commit_len is 0)
 *    extra_commit_len: length of the arbitrary extra data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bppp_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bppp_generators* gens,
    const secp256k1_generator* asset_gen,
    const unsigned char* proof,
    const size_t plen,
    const uint64_t n_bits,
    const uint64_t base,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(10);

# ifdef __cplusplus
}
# endif

#endif
