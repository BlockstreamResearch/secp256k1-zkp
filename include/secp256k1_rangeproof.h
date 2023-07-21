#ifndef SECP256K1_RANGEPROOF_H
# define SECP256K1_RANGEPROOF_H

# include "secp256k1.h"
# include "secp256k1_generator.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** Length of a message that can be embedded into a maximally-sized rangeproof
 *
 * It is not be possible to fit a message of this size into a non-maximally-sized
 * rangeproof, but it is guaranteed that any embeddable message can fit into an
 * array of this size. This constant is intended to be used for memory allocations
 * and sanity checks.
 */
#define SECP256K1_RANGEPROOF_MAX_MESSAGE_LEN 3968

/** Verify a proof that a committed value is within a range.
 * Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs.
 *         0: Proof failed or other error.
 * In:   ctx: pointer to a context object (not secp256k1_context_static)
 *       commit: the commitment being proved. (cannot be NULL)
 *       proof: pointer to character array with the proof. (cannot be NULL)
 *       plen: length of proof in bytes.
 *       extra_commit: additional data covered in rangeproof signature
 *       extra_commit_len: length of extra_commit byte array (0 if NULL)
 *       gen: additional generator 'h'
 * Out:  min_value: pointer to a unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 *       max_value: pointer to a unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_verify(
  const secp256k1_context *ctx,
  uint64_t *min_value,
  uint64_t *max_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *proof,
  size_t plen,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(9);

/** Verify a range proof proof and rewind the proof to recover information sent by its author.
 *  Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs, and the value and blinding were recovered.
 *          0: Proof failed, rewind failed, or other error.
 *  In:   ctx: pointer to a context object (not secp256k1_context_static)
 *        commit: the commitment being proved. (cannot be NULL)
 *        proof: pointer to character array with the proof. (cannot be NULL)
 *        plen: length of proof in bytes.
 *        nonce: 32-byte secret nonce used by the prover (cannot be NULL)
 *        extra_commit: additional data covered in rangeproof signature
 *        extra_commit_len: length of extra_commit byte array (0 if NULL)
 *        gen: additional generator 'h'
 *  In/Out: blind_out: storage for the 32-byte blinding factor used for the commitment
 *        value_out: pointer to an unsigned int64 which has the exact value of the commitment.
 *        message_out: pointer to a 4096 byte character array to receive message data from the proof author.
 *        outlen: length of message data written to message_out. This is generally not equal to the
 *                msg_len used by the signer. However, for all i with msg_len <= i < outlen, it is
 *                guaranteed that message_out[i] == 0.
 *        min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 *        max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_rewind(
  const secp256k1_context *ctx,
  unsigned char *blind_out,
  uint64_t *value_out,
  unsigned char *message_out,
  size_t *outlen,
  const unsigned char *nonce,
  uint64_t *min_value,
  uint64_t *max_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *proof,
  size_t plen,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(14);

/** Author a proof that a committed value is within a range.
 *  Returns 1: Proof successfully created.
 *          0: Error
 *  In:     ctx:    pointer to a context object (not secp256k1_context_static)
 *          proof:  pointer to array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
 *          min_value: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 *          commit: the commitment being proved.
 *          blind:  32-byte blinding factor used by commit. The blinding factor may be all-zeros as long as min_bits is set to 3 or greater.
 *                  This is a side-effect of the underlying crypto, not a deliberate API choice, but it may be useful when balancing CT transactions.
 *          nonce:  32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
 *          exp:    Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *                  (-1 is a special case that makes the value public. 0 is the most private.)
 *          min_bits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 *          value:  Actual value of the commitment.
 *          message: pointer to a byte array of data to be embedded in the rangeproof that can be recovered by rewinding the proof
 *          msg_len: size of the message to be embedded in the rangeproof
 *          extra_commit: additional data to be covered in rangeproof signature
 *          extra_commit_len: length of extra_commit byte array (0 if NULL)
 *          gen: additional generator 'h'
 *  In/out: plen:   point to an integer with the size of the proof buffer and the size of the constructed proof.
 *
 *  If min_value or exp is non-zero then the value must be on the range [0, 2^63) to prevent the proof range from spanning past 2^64.
 *
 *  If exp is -1 the value is revealed by the proof (e.g. it proves that the proof is a blinding of a specific value, without revealing the blinding key.)
 *
 *  This can randomly fail with probability around one in 2^100. If this happens, buy a lottery ticket and retry with a different nonce or blinding.
 *
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_sign(
  const secp256k1_context *ctx,
  unsigned char *proof,
  size_t *plen,
  uint64_t min_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *blind,
  const unsigned char *nonce,
  int exp,
  int min_bits,
  uint64_t value,
  const unsigned char *message,
  size_t msg_len,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(15);

/** Extract some basic information from a range-proof.
 *  Returns 1: Information successfully extracted.
 *          0: Decode failed.
 *  In:   ctx: pointer to a context object
 *        proof: pointer to character array with the proof.
 *        plen: length of proof in bytes.
 *  Out:  exp: Exponent used in the proof (-1 means the value isn't private).
 *        mantissa: Number of bits covered by the proof.
 *        min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 *        max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_info(
  const secp256k1_context *ctx,
  int *exp,
  int *mantissa,
  uint64_t *min_value,
  uint64_t *max_value,
  const unsigned char *proof,
  size_t plen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Returns an upper bound on the size of a rangeproof with the given parameters
 *
 * An actual rangeproof may be smaller, for example if the actual value
 * is less than both the provided `max_value` and 2^`min_bits`, or if
 * the `exp` parameter to `secp256k1_rangeproof_sign` is set such that
 * the proven range is compressed. In particular this function will always
 * overestimate the size of single-value proofs. Also, if `min_value`
 * is set to 0 in the proof, the result will usually, but not always,
 * be 8 bytes smaller than if a nonzero value had been passed.
 *
 * The goal of this function is to provide a useful upper bound for
 * memory allocation or fee estimation purposes, without requiring
 * too many parameters be fixed in advance.
 *
 * To obtain the size of largest possible proof, set `max_value` to
 * `UINT64_MAX` (and `min_bits` to any valid value such as 0).
 *
 *  In:       ctx: pointer to a context object
 *      max_value: the maximum value that might be passed for `value` for the proof.
 *       min_bits: the value that will be passed as `min_bits` for the proof.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT size_t secp256k1_rangeproof_max_size(
  const secp256k1_context *ctx,
  uint64_t max_value,
  int min_bits
) SECP256K1_ARG_NONNULL(1);

# ifdef __cplusplus
}
# endif

#endif
