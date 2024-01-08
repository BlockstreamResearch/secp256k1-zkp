Notes on the frost module API
===========================

The following sections contain additional notes on the API of the frost module
(`include/secp256k1_frost.h`). A usage example can be found in
`examples/frost.c`.

# API misuse

Users of the frost module must take great care to make sure of the following:

1. The dealer establishes a secure communications channel with each participant
   and uses that channel to transmit shares during key generation.
2. A unique set of coefficients per key generation session is generated in
   `secp256k1_frost_share_gen`. See the corresponding comment in
   `include/secp256k1_frost.h` for how to ensure that.
3. The `pubnonces` provided to `secp256k1_frost_nonce_process` are sorted by
   the corresponding lexicographic ordering of the x-only pubkey of each
   participant, and the `pubkeys` provided to `secp256k1_frost_nonce_process`
   are sorted lexicographically.
4. A unique nonce per signing session is generated in
   `secp256k1_frost_nonce_gen`. See the corresponding comment in
   `include/secp256k1_frost.h` for how to ensure that.
5. The `secp256k1_frost_secnonce` structure is never copied or serialized. See
   also the comment on `secp256k1_frost_secnonce` in
   `include/secp256k1_frost.h`.
6. Opaque data structures are never written to or read from directly. Instead,
   only the provided accessor functions are used.
7. If adaptor signatures are used, all partial signatures are verified.

# Key Generation

1. A trusted dealer generates shares with `secp256k1_frost_shares_trusted_gen`
   and distributes a share and the public key to each participant using a
   secure channel.

# Tweaking

A (Taproot) tweak can be added to the resulting public key with
`secp256k1_xonly_pubkey_tweak_add`, after converting it to an xonly pubkey if
necessary with `secp256k1_xonly_pubkey_from_pubkey`.

An ordinary tweak can be added to the resulting public key with
`secp256k1_ec_pubkey_tweak_add`, after converting it to an ordinary pubkey if
necessary with `secp256k1_frost_pubkey_get`.

Tweaks can also be chained together by tweaking an already tweaked key.

# Signing

1. Optionally add a tweak by calling `secp256k1_frost_pubkey_tweak` and then
   `secp256k1_frost_pubkey_xonly_tweak_add` for a Taproot tweak and
   `secp256k1_frost_pubkey_ec_tweak_add` for an ordinary tweak.
2. Generate a pair of secret and public nonce with `secp256k1_frost_nonce_gen`
   and send the public nonce to the other signers.
3. Process the aggregate nonce with `secp256k1_frost_nonce_process`.
4. Create a partial signature with `secp256k1_frost_partial_sign`.
5. Verify the partial signatures (optional in some scenarios) with
   `secp256k1_frost_partial_sig_verify`.
6. Someone (not necessarily the signer) obtains all partial signatures and
   aggregates them into the final Schnorr signature using
   `secp256k1_frost_partial_sig_agg`.

The aggregate signature can be verified with `secp256k1_schnorrsig_verify`.

Note that steps 1 to 3 can happen before the message to be signed is known to
the signers. Therefore, the communication round to exchange nonces can be
viewed as a pre-processing step that is run whenever convenient to the signers.
This disables some of the defense-in-depth measures that may protect against
API misuse in some cases. Similarly, the API supports an alternative protocol
flow where generating the key (see Key Generation above) is allowed to happen
after exchanging nonces (step 2).

# Verification

A participant who wants to verify the partial signatures, but does not sign
itself may do so using the above instructions except that the verifier skips
steps 2 and 4.
