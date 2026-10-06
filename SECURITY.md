# Security Policy

## Reporting a Vulnerability

If the vulnerability also affects the upstream libsecp256k1 (shared code, not a module or feature added by this fork), please report it to its maintainers first at secp256k1-security@bitcoincore.org; their keys are listed in the [upstream SECURITY.md](https://github.com/bitcoin-core/secp256k1/blob/master/SECURITY.md).

To report a vulnerability specific to libsecp256k1-zkp, send an email to security@blockstream.com (not for support).

The following key may be used to communicate sensitive information to developers:

| Name                     | Fingerprint                                        |
|--------------------------|----------------------------------------------------|
| security@blockstream.com | 1176 542D A98E 71E1 3372  2EF7 4AC8 CC88 6844 A2D6 |

You can import this key from a keyserver by its fingerprint: `gpg --keyserver hkps://keys.openpgp.org --recv-keys "<fingerprint>"` (also published at https://blockstream.com/pgp.txt). Ensure that you put quotes around fingerprints containing spaces.
