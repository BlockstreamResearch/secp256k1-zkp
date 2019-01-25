#ifndef SECP256K1_THRESHOLDSIG_H
#define SECP256K1_THRESHOLDSIG_H

/** Shard of a threshold signature secret key. Created with `secp256k1_thresholdsig_keysplit`
 *  for a specific set of signers. Secret keys or shards should *never* be reused across
 *  multiple signer sets.
 *
 * This data structure is guaranteed to be a 32-byte byte array; it is a separate
 * type from ordinary secret keys to help prevent API users confusing shards with
 * complete keys or using the non-threshold API in place of the threshold API,
 * which would result in mysteriously invalid signatures being produced.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_thresholdsig_keyshard;

/** Multiplies a secret key by its MuSig coefficient and produces keyshards
 *  for distribution to other signers.
 *
 * Returns 1 on success, 0 if any input was invalid.
 *
 *  Args:    ctx: pointer to a context object initialized for signing (cannot be NULL)
 *  Out:  shards: array of keyshards, one for each signer (cannot be NULL)
 *      pubcoeff: array of k EC points used by signers to verify their shards (cannot be NULL)
 *  In:   seckey: unmodified secret key (cannot be NULL)
 *             k: signing threshold; size of `pubcoeff` array
 *             n: number of signers; size of `shards` array
 */
SECP256K1_API int secp256k1_thresholdsig_keysplit(
    const secp256k1_context *ctx,
    secp256k1_thresholdsig_keyshard *shards,
    secp256k1_pubkey *pubcoeff,
    const unsigned char *seckey,
    const size_t k,
    const size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verifies a keyshard against a set of public coefficients and updates the set of signing keys
 *
 *  This function serves two very different purposes. First, if `privshard` is non-NULL, it
 *  verifies that this shard is consistent with a set of public coefficients which were output
 *  from `secp256k1_thresholdsig_keysplit`. If `seckey` is non-NULL, it updates this value to
 *  become a sum of all other signers' private shards.
 *
 *  Secondly, it computes the public version of every other signer's shard, and updates the
 *  array `signer_pubkeys` to become an array of all other signers' public keys.
 *
 *  The resulting keys, when weighted by appropriate Lagrange coefficients, will sum to the MuSig
 *  signing key corresponding to the threshold policy.
 *
 *  Returns 1 on success, 0 if any input was invalid.
 *
 *  Args:         ctx: pointer to a context object initialized for signing and verification (cannot be NULL)
 *            scratch: if non-NULL, pointer to a scratch space used to speed up computations
 *  In/Out:    seckey: secret key belonging to the caller
 *     signer_pubkeys: array of public keys corresponding to every signer (cannot be NULL)
 *  In:        n_keys: number of keys in the above array
 *         continuing: whether to initialize (zero) or update (nonzero) `seckey` and `signer_pubkeys`
 *          privshard: if non-NULL, a private shard to verify against the computed public shards
 *             my_idx: index of the caller in the MuSig policy
 *          other_idx: index of the signer who provided the shards
 *           pubcoeff: array of public coefficients (cannot be NULL)
 *           n_coeffs: number of coefficients in the above array; or number of signers needed for quorum
 */
SECP256K1_API int secp256k1_thresholdsig_verify_shard(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    unsigned char *seckey,
    secp256k1_pubkey *signer_pubkeys,
    size_t n_keys,
    const unsigned char *pk_hash,
    int continuing,
    const secp256k1_thresholdsig_keyshard *privshard,
    size_t my_idx,
    size_t other_idx,
    const secp256k1_pubkey *pubcoeff,
    size_t n_coeffs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(11);

/** Initializes a threshold signing session
 *
 *  Returns 1 on success, 0 if any input was invalid.
 *
 *  Args:         ctx: pointer to a context object initialized for signing (cannot be NULL)
 *  Out:      session: the session structure to initialize (cannot be NULL)
 *            signers: an array of signers' data to be initialized. Array length must
 *                     equal to `n_signers` (cannot be NULL)
 * nonce_commitment32: filled with a 32-byte commitment to the generated nonce
 *                     (cannot be NULL)
 *  In:  session_id32: a *unique* 32-byte ID to assign to this session (cannot be
 *                     NULL). If a non-unique session_id32 was given then a partial
 *                     signature will LEAK THE SECRET KEY.
 *              msg32: the 32-byte message to be signed. Shouldn't be NULL unless you
 *                     require sharing public nonces before the message is known
 *                     because it reduces nonce misuse resistance. If NULL, must be
 *                     set with `musig_session_set_msg` before signing and verifying.
 *        combined_pk: the combined public key of all signers (cannot be NULL)
 *            indices: array of signers' indices in the MuSig key combination (cannot be NULL)
 *          n_signers: length of signers array. Number of signers participating in
 *                     the signature. This is not necessarily the same as the number
 *                     of contributors to the MuSig key. Must be greater than 0 and at most 2^32 - 1.
 *           my_index: index of this signer in the MuSig key combination
 *             seckey: the signer's 32-byte secret key (cannot be NULL)
 */
int secp256k1_thresholdsig_session_initialize(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    secp256k1_musig_session_signer_data *signers,
    unsigned char *nonce_commitment32,
    const unsigned char *session_id32,
    const unsigned char *msg32,
    const secp256k1_pubkey *combined_pk,
    const size_t *indices,
    size_t n_signers,
    size_t my_index,
    const unsigned char *seckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(10);

/** Checks that an individual partial signature verifies
 *
 *  This function is essential when using protocols with adaptor signatures.
 *  However, it is not essential for regular MuSig's, in the sense that if any
 *  partial signatures does not verify, the full signature will also not verify, so the
 *  problem will be caught. But this function allows determining the specific party
 *  who produced an invalid signature, so that signing can be restarted without them.
 *
 *  Returns: 1: partial signature verifies
 *           0: invalid signature or bad data
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *            session: active session for which the combined nonce has been computed
 *                     (cannot be NULL)
 *  In:       signers: array of signers involved in this threshold signature (cannot be NULL)
 *          n_signers: number of signers in the above array
 *        partial_sig: signature to verify (cannot be NULL)
 *             pubkey: public key of the signer who produced the signature (cannot be NULL)
 */
int secp256k1_thresholdsig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_session *session,
    const secp256k1_musig_session_signer_data *signers,
    size_t n_signers,
    size_t signer_idx,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

#endif
