# Status

This PR has been open for a while and is blocked on progress on some
supporting infrastructure; in particular the key setup protocol requires
both a broadcast channel and private communication channels between
each pair of peers.

There are also API issues that need to be ironed out, including:

* All the same issues that affect MuSig, especially with regards to
stateless or low-memory signing hardware
* How to identify participants and assign blame on misbehavior
* How to recover from misbehavior; is it possible to do better than
entirely restarting the protocol?

# High-Level/Intuitive Design

This document assumes familiarity with MuSig[1] or a similar n-of-n
multiparty Schnorr signature scheme. The intuition there is that all
parties may exchange public nonces, sum these, compute a jointly-known
challenge hash, exchange individual signatures on said challenge, and
sum these to produce a multisignature. To avoid related-key attacks
it is required that the summation be randomized; to avoid Wagner-style
attacks[2,3] another round is needed in which participants exchange
precommitments to their public nonces prior to exchanging the nonces
themselves.

The extension from n-of-n compact multisignatures to k-of-n *threshold*
signatures is conceptually simple: at key generation time, every participant
uses a linear secret sharing scheme to split their secret amongst the *n*
participants (including him/herself) such that any *k* may reconstruct
the secret using Lagrange interpolation. Then any *k* participants may
use the MuSig signing protocol to produce a signature, with the small
modification that each signer's private key is multiplied by an appropriate
Lagrange coefficient before signing starts.

Much as the folklore "add the keys, add the signatures" Schnorr multisignature
scheme turns out to be insecure in practice, so does this folklore Schnorr
threshold signature scheme. What follows is an unstructured list of
difficulties we've encountered.

## Key Exchange

1. First, while rogue-key attacks appear to be prevented by the need to
exchange keyshares consistent with individuals' public keys, this does
not protect against Taproot rogue-key attacks (where one participant adds
a Taproot commitment, unbeknownst to the others). So MuSig-style key
aggregation is required.
2. Having said that, the security properties of threshold-MuSig have not
been studied.
3. Also, if the "Lagrange-interpolate the keys then MuSig-sign" scheme
described above is used, a nonce-precommitment round is required for
the usual reasons. Though as we will see, this is not the scheme typically
described in the literature.
4. To validate the shares being exchange it is required to use a *verifiable
secret sharing scheme*; otherwise a user may provide inconsistent shares
to other participants resulting in an inability to sign. In fact, to
assign blame and reliably detect misbehavior it is required to use a *publicly
verifable secret sharing scheme* such as [4]. Though it is not explicitly
stated, this scheme requires use of a **broadcast channel**.
5. Also, the applicability of [4] to signature schemes has been disputed
by Gennaro et al [5] because it allows a rogue participant to bias the public
key; the same authors suggest that in [6] that this doesn't actually matter.
6. After key exchange, users must store all the keyshards they've received.
These cannot be reduced to a BIP32 seed and **cannot be reproduced** without
help from the other signers. What is the backup story here?

## Signing (Stinson & Strobl)

Assuming the key exchange has gone well (this likely involves using a trusted
intermediary as a broadcast channel, and requires all users maintain backups
of their (summed) key shares, meaning that this is not something that can be
redone frequently or automatically), signing presents new difficulties.

1. Unlike in n-of-n schemes, where a single misbehaving party may stymie a
signature by design, in k-of-n we expect robustness against rogue parties,
as long as we have at least *k* honest parties.
2. The naive "Lagrange-multiply your keys then use MuSig signing" scheme
above does not have this property because somebody can produce a nonce,
making the signature unproduceable without their input, then drop out
before the second round.
3. Instead, such a scheme which is robust against such attackers is
described in Stinson & Strobl [7]. It does so by secret-sharing the nonce,
which means bringing all the complexities of key-generation time into
signing-time (except this time we at least don't need to store the result
for a long time).
4. It further assumes that the additional countermeasures from [5] to avoid
key-biasing attacks are needed; perhaps there is a simpler scheme in light
of [6]? In any case this involves multiple rounds of challenges and responses
in the case of misbehavior; It also assumes a broadcast channel. More research
needs to be done into this.
5. In general, what happens when messages are lost? What happens when they
are delayed?

## Signing (ad hoc MuSig-like scheme)

In light of the above discussion, it might make more sense to use the following
simpler protocol which resembles MuSig:

1. At signing time, all participants from a set of size at least *k* exchange
nonce commitments.
2. Then they reveal their nonces.
3. Based on the set of participants available, everybody multiplies their key
by an appropriate Lagrange multiplier (and multiplies the other's public keys
by an appropriate multiplier, for the purpose of checking partial signatures).
4. Then everyone partially signs with their multiplied-by key. The final
signature is the sum of partial signatures.

This eliminates all exchange of secret data from signing-time, makes
identification of misbehavior easy (since there is only one valid step
for every signing after nonce-precommitment), and is generally easy to
reason about.

But this is plagued by the following problems:

1. Nobody has produced an academic proof of security.
2. If a party simply fails to communicate, rather than misbehaving, this is
impossible to prove. Worse, if a party fails to communicate *only to some
participants*, he can jam a signing protocol without any transferrable proof
that this happened. So it seems we still need a broadcast channel.
3. It requires a full restart of the protocol on misbehavior, with fresh
nonces and everything. (On the other hand, it appears that the restarted
protocol can be done in parallel to the old one, so each retry is only
one additional round ... provided that everyone can agree on who to kick out.)
	
# Citations

[1] MuSig https://eprint.iacr.org/2018/068
[2] Wagner's Algorithm https://people.eecs.berkeley.edu/~daw/papers/genbday.html
[3] Wagner attack on "2-round MuSig" https://eprint.iacr.org/2018/417
[4] Pedersen '98 https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
[5] GKJR '99 https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf
[6] GKJR '03 https://pdfs.semanticscholar.org/642b/d1bbc86c7750cef9fa770e9e4ba86bd49eb9.pdf
[7] Stinson & Strobl https://cacr.uwaterloo.ca/techreports/2001/corr2001-13.ps
