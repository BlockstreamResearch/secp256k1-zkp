/**********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_RANGEPROOF_IMPL_H_
#define _SECP256K1_RANGEPROOF_IMPL_H_

#include "eckey.h"
#include "scalar.h"
#include "group.h"
#include "rangeproof.h"
#include "hash_impl.h"
#include "pedersen_impl.h"
#include "util.h"

#include "modules/rangeproof/pedersen.h"
#include "modules/rangeproof/borromean.h"
#include "modules/rangeproof/rangeproof.h"

/** Takes a header with `exp`, `mantissa` and `min_value` set and fills in all other fields
 *
 * Returns 1 on success, 0 if the `max_value` field would exceed UINT64_MAX */
static int secp256k1_rangeproof_header_expand(secp256k1_rangeproof_header* header) {
    if (header->exp == -1) {
        header->n_rings = 1;
        header->n_pubs = 1;
        header->max_value = 0;
        header->rsizes[0] = 1;
    } else {
        size_t i;

        header->n_rings = header->mantissa / 2;
        header->n_pubs = 4 * header->n_rings;
        header->max_value = UINT64_MAX >> (64 - header->mantissa);
        for (i = 0; i < header->n_rings; i++) {
            header->rsizes[i] = 4;
        }

        if (header->mantissa & 1) {
            header->rsizes[header->n_rings] = 2;
            header->n_pubs += 2;
            header->n_rings++;
        }
    }
    VERIFY_CHECK(header->n_rings > 0);
    VERIFY_CHECK(header->n_rings <= 32);
    VERIFY_CHECK(header->n_pubs <= 128);
    VERIFY_CHECK(header->n_pubs >= 1);

    header->scale = 1;
    if (header->exp > 0) {
        int i;
        for (i = 0; i < header->exp; i++) {
            if (header->max_value > UINT64_MAX / 10) {
                return 0;
            }
            header->max_value *= 10;
            header->scale *= 10;
        }
    }

    if (header->max_value > UINT64_MAX - header->min_value) {
        return 0;
    }
    header->max_value += header->min_value;

    return 1;
}

static int secp256k1_rangeproof_header_parse(
    secp256k1_rangeproof_header* header,
    size_t* offset,
    const unsigned char* proof,
    size_t plen
) {
    memset(header, 0, sizeof(*header));
    *offset = 0;

    if (plen < 65 || ((proof[0] & 128) != 0)) {
        return 0;
    }
    /* Read `exp` and `mantissa` */
    if (proof[0] & 64) {
        *offset += 1;
        header->exp = proof[0] & 31;
        if (header->exp > 18) {
           return 0;
        }
        header->mantissa = proof[1] + 1;
        if (header->mantissa > 64) {
            return 0;
        }
    } else {
        /* single-value proof */
        header->mantissa = 0;
        header->exp = -1;
    }
    *offset += 1;
    /* Read `min_value` */
    if (proof[0] & 32) {
        size_t i;
        for (i = 0; i < 8; i++) {
            header->min_value = (header->min_value << 8) | proof[*offset + i];
        }
        *offset += 8;
    } else {
        header->min_value = 0;
    }

    return secp256k1_rangeproof_header_expand(header);
}

static int secp256k1_rangeproof_header_set_for_value(
    secp256k1_rangeproof_header* header,
    uint64_t* proven_value,
    const uint64_t min_value,
    uint64_t min_bits,
    const int exp,
    const uint64_t value
) {
    memset(header, 0, sizeof(*header));
    *proven_value = 0;

    /* Sanity checks */
    if (min_value > value || min_bits > 64 || exp < -1 || exp > 18) {
        return 0;
    }

    /* Start by just using the user's requested values, then adjust them in
     * various ways to make them compatible. This is probably not advisable
     * from a privacy point-of-view but it's important to be compatible with
     * the 2015-era API, and all of these issues will go away when we merge
     * Bulletproofs. */
    header->exp = exp;
    header->min_value = min_value;
    header->mantissa = min_bits ? min_bits : 1; /* force mantissa to be nonzero */

    /* Special-case single-value proofs */
    if (header->exp == -1) {
        header->mantissa = 0; /* ignore user's min_bits */
        return secp256k1_rangeproof_header_expand(header);
    }

    /* Deal with extreme values (copied directly from 2015 code) */
    if (header->mantissa > 61 || value > INT64_MAX) {
        /* Ten is not a power of two, so dividing by ten and then representing in base-2 times ten
         * expands the representable range. The verifier requires the proven range is within 0..2**64.
         * For very large numbers (all over 2**63) we must change our exponent to compensate.
         * Rather than handling it precisely, this just disables use of the exponent for big values.
         */
        header->exp = 0;
    }
    /* Reduce mantissa to keep within a uint64_t's range (essentially copied from 2015 code) */
    {
        const unsigned int max_bits = min_value ? secp256k1_clz64_var(min_value) : 64;
        if (header->mantissa > max_bits) {
            header->mantissa = max_bits;
        }
    }
    {
        /* If the user has asked for more bits of proof then there is room for in the exponent, reduce the exponent. */
        uint64_t max = header->mantissa ? (UINT64_MAX >> (64 - header->mantissa)) : 0;
        int i;
        for (i = 0; i < header->exp && max <= UINT64_MAX / 10; i++) {
            max *= 10;
        }
        header->exp = i;
    }


    /* Increase the mantissa from min_bits until it actually covers the proven value */
    if (!secp256k1_rangeproof_header_expand(header)) {
        return 0;
    }
    *proven_value = (value - header->min_value) / header->scale;
    while (header->mantissa < 64 && (*proven_value >> header->mantissa) > 0) {
        header->mantissa++;
    }
    /* Fudge min_value so we don't lose the low-order digits of `value` */
    header->min_value = value - (*proven_value * header->scale);

    /* Did we get all the bits? */
    VERIFY_CHECK(header->mantissa > 0);
    VERIFY_CHECK((*proven_value & ~(UINT64_MAX >> (64 - header->mantissa))) == 0);

    /* We may have changed `mantissa`, `exp` and `min_value`, all of which would
     * affect the derived values, so re-expand the header. */
    return secp256k1_rangeproof_header_expand(header);
}

static int secp256k1_rangeproof_header_serialize(
    unsigned char* proof,
    size_t plen,
    size_t* offset,
    const secp256k1_rangeproof_header* header
) {
    *offset = 0;
    if (plen < 65) {
        return 0;
    }

    /* Write control byte */
    proof[0] = (header->exp >= 0 ? (64 | header->exp) : 0) | (header->min_value ? 32 : 0);
    *offset += 1;
    /* Write mantissa, for non-exact-value proofs */
    if (header->exp >= 0) {
        VERIFY_CHECK(header->mantissa > 0 && header->mantissa <= 64);
        proof[1] = header->mantissa - 1;
        *offset += 1;
    }
    /* Write min_value, if present */
    if (header->min_value > 0) {
        size_t i;
        for (i = 0; i < 8; i++) {
            proof[*offset + i] = (header->min_value >> ((7-i) * 8)) & 255;
        }
        *offset += 8;
    }

    return 1;
}

SECP256K1_INLINE static void secp256k1_rangeproof_pub_expand(secp256k1_gej *pubs,
 int exp, size_t *rsizes, size_t rings, const secp256k1_ge* genp) {
    secp256k1_gej base;
    size_t i;
    size_t j;
    size_t npub;
    VERIFY_CHECK(exp < 19);
    if (exp < 0) {
        exp = 0;
    }
    secp256k1_gej_set_ge(&base, genp);
    secp256k1_gej_neg(&base, &base);
    while (exp--) {
        /* Multiplication by 10 */
        secp256k1_gej tmp;
        secp256k1_gej_double_var(&tmp, &base, NULL);
        secp256k1_gej_double_var(&base, &tmp, NULL);
        secp256k1_gej_double_var(&base, &base, NULL);
        secp256k1_gej_add_var(&base, &base, &tmp, NULL);
    }
    npub = 0;
    for (i = 0; i < rings; i++) {
        for (j = 1; j < rsizes[i]; j++) {
            secp256k1_gej_add_var(&pubs[npub + j], &pubs[npub + j - 1], &base, NULL);
        }
        if (i < rings - 1) {
            secp256k1_gej_double_var(&base, &base, NULL);
            secp256k1_gej_double_var(&base, &base, NULL);
        }
        npub += rsizes[i];
    }
}

SECP256K1_INLINE static void secp256k1_rangeproof_serialize_point(unsigned char* data, const secp256k1_ge *point) {
    secp256k1_fe pointx;
    pointx = point->x;
    secp256k1_fe_normalize(&pointx);
    data[0] = !secp256k1_fe_is_quad_var(&point->y);
    secp256k1_fe_get_b32(data + 1, &pointx);
}

SECP256K1_INLINE static void secp256k1_rangeproof_init_rng(
    secp256k1_rfc6979_hmac_sha256* rng,
    const unsigned char* nonce,
    const secp256k1_ge* commit,
    const unsigned char *proof,
    const size_t len,
    const secp256k1_ge* genp
) {
    unsigned char rngseed[32 + 33 + 33 + 10];
    VERIFY_CHECK(len <= 10);

    memcpy(rngseed, nonce, 32);
    secp256k1_rangeproof_serialize_point(rngseed + 32, commit);
    secp256k1_rangeproof_serialize_point(rngseed + 32 + 33, genp);
    memcpy(rngseed + 33 + 33 + 32, proof, len);
    secp256k1_rfc6979_hmac_sha256_initialize(rng, rngseed, 32 + 33 + 33 + len);
}

SECP256K1_INLINE static int secp256k1_rangeproof_genrand(
    secp256k1_scalar *sec,
    secp256k1_scalar *s,
    unsigned char *message,
    const secp256k1_rangeproof_header* header,
    secp256k1_rfc6979_hmac_sha256* rng
) {
    unsigned char tmp[32];
    secp256k1_scalar acc;
    int overflow;
    int ret;
    size_t i;
    size_t j;
    int b;
    size_t npub;
    secp256k1_scalar_clear(&acc);
    npub = 0;
    ret = 1;
    for (i = 0; i < header->n_rings; i++) {
        if (i < header->n_rings - 1) {
            secp256k1_rfc6979_hmac_sha256_generate(rng, tmp, 32);
            do {
                secp256k1_rfc6979_hmac_sha256_generate(rng, tmp, 32);
                secp256k1_scalar_set_b32(&sec[i], tmp, &overflow);
            } while (overflow || secp256k1_scalar_is_zero(&sec[i]));
            secp256k1_scalar_add(&acc, &acc, &sec[i]);
        } else {
            secp256k1_scalar_negate(&acc, &acc);
            sec[i] = acc;
        }
        for (j = 0; j < header->rsizes[i]; j++) {
            secp256k1_rfc6979_hmac_sha256_generate(rng, tmp, 32);
            if (message) {
                for (b = 0; b < 32; b++) {
                    tmp[b] ^= message[(i * 4 + j) * 32 + b];
                    message[(i * 4 + j) * 32 + b] = tmp[b];
                }
            }
            secp256k1_scalar_set_b32(&s[npub], tmp, &overflow);
            ret &= !(overflow || secp256k1_scalar_is_zero(&s[npub]));
            npub++;
        }
    }
    secp256k1_rfc6979_hmac_sha256_finalize(rng);
    secp256k1_scalar_clear(&acc);
    memset(tmp, 0, 32);
    return ret;
}

/* strawman interface, writes proof in proof, a buffer of plen, proves with respect to min_value the range for commit which has the provided blinding factor and value. */
SECP256K1_INLINE static int secp256k1_rangeproof_sign_impl(const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_ge *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_ge* genp){
    secp256k1_rangeproof_header header;
    secp256k1_gej pubs[128];     /* Candidate digits for our proof, most inferred. */
    secp256k1_scalar s[128];     /* Signatures in our proof, most forged. */
    secp256k1_scalar sec[32];    /* Blinding factors for the correct digits. */
    secp256k1_scalar k[32];      /* Nonces for our non-forged signatures. */
    secp256k1_scalar stmp;
    secp256k1_sha256 sha256_m;
    unsigned char prep[4096];
    unsigned char tmp[33];
    unsigned char *signs;          /* Location of sign flags in the proof. */
    uint64_t v;
    size_t secidx[32];                /* Which digit is the correct one. */
    secp256k1_rfc6979_hmac_sha256 genrand_rng;
    size_t len;                       /* Number of bytes used so far. */
    size_t i;
    size_t pub_idx;
    int overflow;
    len = 0;
    if (*plen < 65) {
        return 0;
    }

    if (!secp256k1_rangeproof_header_set_for_value(&header, &v, min_value, min_bits, exp, value)) {
        return 0;
    }
    if (header.exp >= 0) {
        for (i = 0; i < header.n_rings; i++) {
            secidx[i] = (v >> (i * 2)) & 3;
        }
    } else {
        secidx[0] = 0;
    }

    VERIFY_CHECK(v * header.scale + header.min_value == value);

    secp256k1_rangeproof_header_serialize (proof, *plen, &len, &header);

    /* Do we have enough room in the proof for the message? Each ring gives us 128 bytes, but the
     * final ring is used to encode the blinding factor and the value, so we can't use that. (Well,
     * technically there are 64 bytes available if we avoided the other data, but this is difficult
     * because it's not always in the same place. */
    if (msg_len > 0 && msg_len > 128 * (header.n_rings - 1)) {
        return 0;
    }
    /* Do we have enough room for the proof? */
    if (*plen - len < 32 * (header.n_pubs + header.n_rings - 1) + 32 + ((header.n_rings + 6) >> 3)) {
        return 0;
    }
    secp256k1_sha256_initialize(&sha256_m);
    secp256k1_rangeproof_serialize_point(tmp, commit);
    secp256k1_sha256_write(&sha256_m, tmp, 33);
    secp256k1_rangeproof_serialize_point(tmp, genp);
    secp256k1_sha256_write(&sha256_m, tmp, 33);
    secp256k1_sha256_write(&sha256_m, proof, len);

    memset(prep, 0, 4096);
    if (message != NULL) {
        memcpy(prep, message, msg_len);
    }
    /* Note, the data corresponding to the blinding factors must be zero. */
    if (header.rsizes[header.n_rings - 1] > 1) {
        size_t idx;
        /* Value encoding sidechannel. */
        idx = header.rsizes[header.n_rings - 1] - 1;
        idx -= secidx[header.n_rings - 1] == idx;
        idx = ((header.n_rings - 1) * 4 + idx) * 32;
        for (i = 0; i < 8; i++) {
            prep[8 + i + idx] = prep[16 + i + idx] = prep[24 + i + idx] = (v >> (56 - i * 8)) & 255;
            prep[i + idx] = 0;
        }
        prep[idx] = 128;
    }
    secp256k1_rangeproof_init_rng(&genrand_rng, nonce, commit, proof, len, genp);
    if (!secp256k1_rangeproof_genrand(sec, s, prep, &header, &genrand_rng)) {
        return 0;
    }
    memset(prep, 0, 4096);
    for (i = 0; i < header.n_rings; i++) {
        /* Sign will overwrite the non-forged signature, move that random value into the nonce. */
        k[i] = s[i * 4 + secidx[i]];
        secp256k1_scalar_clear(&s[i * 4 + secidx[i]]);
    }
    /** Genrand returns the last blinding factor as -sum(rest),
     *   adding in the blinding factor for our commitment, results in the blinding factor for
     *   the commitment to the last digit that the verifier can compute for itself by subtracting
     *   all the digits in the proof from the commitment. This lets the prover skip sending the
     *   blinded value for one digit.
     */
    secp256k1_scalar_set_b32(&stmp, blind, &overflow);
    secp256k1_scalar_add(&sec[header.n_rings - 1], &sec[header.n_rings - 1], &stmp);
    if (overflow || secp256k1_scalar_is_zero(&sec[header.n_rings - 1])) {
        return 0;
    }
    signs = &proof[len];
    /* We need one sign bit for each blinded value we send. */
    for (i = 0; i < (header.n_rings + 6) >> 3; i++) {
        signs[i] = 0;
        len++;
    }
    pub_idx = 0;
    for (i = 0; i < header.n_rings; i++) {
        /*OPT: Use the precomputed gen2 basis?*/
        secp256k1_pedersen_ecmult(ecmult_gen_ctx, &pubs[pub_idx], &sec[i], ((uint64_t)secidx[i] * header.scale) << (i*2), genp);
        if (secp256k1_gej_is_infinity(&pubs[pub_idx])) {
            return 0;
        }
        if (i < header.n_rings - 1) {
            unsigned char tmpc[33];
            secp256k1_ge c;
            unsigned char quadness;
            /*OPT: split loop and batch invert.*/
            /*OPT: do not compute full pubs[pub_idx] in ge form; we only need x */
            secp256k1_ge_set_gej_var(&c, &pubs[pub_idx]);
            secp256k1_rangeproof_serialize_point(tmpc, &c);
            quadness = tmpc[0];
            secp256k1_sha256_write(&sha256_m, tmpc, 33);
            signs[i>>3] |= quadness << (i&7);
            memcpy(&proof[len], tmpc + 1, 32);
            len += 32;
        }
        pub_idx += header.rsizes[i];
    }
    VERIFY_CHECK(pub_idx == header.n_pubs);
    secp256k1_rangeproof_pub_expand(pubs, header.exp, header.rsizes, header.n_rings, genp);
    if (extra_commit != NULL) {
        secp256k1_sha256_write(&sha256_m, extra_commit, extra_commit_len);
    }
    secp256k1_sha256_finalize(&sha256_m, tmp);
    if (!secp256k1_borromean_sign(ecmult_gen_ctx, &proof[len], s, pubs, k, sec, header.rsizes, secidx, header.n_rings, tmp, 32)) {
        return 0;
    }
    len += 32;
    for (i = 0; i < pub_idx; i++) {
        secp256k1_scalar_get_b32(&proof[len], &s[i]);
        len += 32;
    }
    VERIFY_CHECK(len <= *plen);
    *plen = len;
    memset(prep, 0, 4096);
    return 1;
}

/* Computes blinding factor x given k, s, and the challenge e. */
SECP256K1_INLINE static void secp256k1_rangeproof_recover_x(secp256k1_scalar *x, const secp256k1_scalar *k, const secp256k1_scalar *e,
 const secp256k1_scalar *s) {
    secp256k1_scalar stmp;
    secp256k1_scalar_negate(x, s);
    secp256k1_scalar_add(x, x, k);
    secp256k1_scalar_inverse(&stmp, e);
    secp256k1_scalar_mul(x, x, &stmp);
}

/* Computes ring's nonce given the blinding factor x, the challenge e, and the signature s. */
SECP256K1_INLINE static void secp256k1_rangeproof_recover_k(secp256k1_scalar *k, const secp256k1_scalar *x, const secp256k1_scalar *e,
 const secp256k1_scalar *s) {
    secp256k1_scalar stmp;
    secp256k1_scalar_mul(&stmp, x, e);
    secp256k1_scalar_add(k, s, &stmp);
}

SECP256K1_INLINE static void secp256k1_rangeproof_ch32xor(unsigned char *x, const unsigned char *y) {
    int i;
    for (i = 0; i < 32; i++) {
        x[i] ^= y[i];
    }
}

SECP256K1_INLINE static int secp256k1_rangeproof_rewind_inner(secp256k1_scalar *blind, uint64_t *v,
 unsigned char *m, size_t *mlen, secp256k1_scalar *ev, secp256k1_scalar *s,
 secp256k1_rangeproof_header* header, const unsigned char *nonce, const secp256k1_ge *commit, const unsigned char *proof, size_t len, const secp256k1_ge *genp) {
    secp256k1_rfc6979_hmac_sha256 genrand_rng;
    secp256k1_scalar s_orig[128];
    secp256k1_scalar sec[32];
    secp256k1_scalar stmp;
    unsigned char prep[4096];
    unsigned char tmp[32];
    uint64_t value = 0;
    size_t final_x_pos;
    size_t offset;
    size_t i;
    size_t j;
    int b;
    size_t npub;
    memset(prep, 0, 4096);
    /* Reconstruct the provers random values. */
    secp256k1_rangeproof_init_rng(&genrand_rng, nonce, commit, proof, len, genp);
    if (!secp256k1_rangeproof_genrand(sec, s_orig, prep, header, &genrand_rng)) {
        return 0;
    }
    *v = UINT64_MAX;
    secp256k1_scalar_clear(blind);
    if (header->n_rings == 1 && header->rsizes[0] == 1) {
        /* With only a single proof, we can only recover the blinding factor. */
        secp256k1_rangeproof_recover_x(blind, &s_orig[0], &ev[0], &s[0]);
        if (v) {
            *v = 0;
        }
        if (mlen) {
            *mlen = 0;
        }
        return 1;
    }
    for (j = 0; j < 2; j++) {
        size_t idx;
        /* Look for a value encoding in the last ring. */
        idx = header->n_pubs - 1 - j;
        secp256k1_scalar_get_b32(tmp, &s[idx]);
        secp256k1_rangeproof_ch32xor(tmp, &prep[idx * 32]);
        if ((tmp[0] & 128) && (memcmp(&tmp[16], &tmp[24], 8) == 0) && (memcmp(&tmp[8], &tmp[16], 8) == 0)) {
            value = 0;
            for (i = 0; i < 8; i++) {
                value = (value << 8) + tmp[24 + i];
            }
            if (v) {
                *v = value;
            }
            memcpy(&prep[idx * 32], tmp, 32);
            break;
        }
    }
    if (j > 1) {
        /* Couldn't extract a value. */
        if (mlen) {
            *mlen = 0;
        }
        return 0;
    }
    /* Like in the rsize[] == 1 case, Having figured out which s is the one which was not forged, we can recover the blinding factor. */
    final_x_pos = 4 * (header->n_rings - 1) + ((*v >> (2 * (header->n_rings - 1))) & 3);
    secp256k1_rangeproof_recover_x(&stmp, &s_orig[final_x_pos], &ev[final_x_pos], &s[final_x_pos]);
    secp256k1_scalar_negate(&sec[header->n_rings - 1], &sec[header->n_rings - 1]);
    secp256k1_scalar_add(blind, &stmp, &sec[header->n_rings - 1]);
    if (!m || !mlen || *mlen == 0) {
        if (mlen) {
            *mlen = 0;
        }
        /* FIXME: cleanup in early out/failure cases. */
        return 1;
    }
    offset = 0;
    npub = 0;
    for (i = 0; i < header->n_rings - 1; i++) {
        size_t idx;
        idx = (value >> (i << 1)) & 3;
        for (j = 0; j < header->rsizes[i]; j++) {
            if (idx == j) {
                /** For the non-forged signatures the signature is calculated instead of random, instead we recover the prover's nonces.
                 *  this could just as well recover the blinding factors and messages could be put there as is done for recovering the
                 *  blinding factor in the last ring, but it takes an inversion to recover x so it's faster to put the message data in k.
                 */
                secp256k1_rangeproof_recover_k(&stmp, &sec[i], &ev[npub], &s[npub]);
            } else {
                stmp = s[npub];
            }
            secp256k1_scalar_get_b32(tmp, &stmp);
            secp256k1_rangeproof_ch32xor(tmp, &prep[npub * 32]);
            for (b = 0; b < 32 && offset < *mlen; b++) {
                m[offset] = tmp[b];
                offset++;
            }
            npub++;
        }
    }
    *mlen = offset;
    memset(prep, 0, 4096);
    for (i = 0; i < 128; i++) {
        secp256k1_scalar_clear(&s_orig[i]);
    }
    for (i = 0; i < 32; i++) {
        secp256k1_scalar_clear(&sec[i]);
    }
    secp256k1_scalar_clear(&stmp);
    return 1;
}

/* Verifies range proof (len plen) for commit, the min/max values proven are put in the min/max arguments; returns 0 on failure 1 on success.*/
SECP256K1_INLINE static int secp256k1_rangeproof_verify_impl(const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *blindout, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value, const secp256k1_ge *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_ge* genp) {
    secp256k1_gej accj;
    secp256k1_gej pubs[128];
    secp256k1_scalar s[128];
    secp256k1_scalar evalues[128]; /* Challenges, only used during proof rewind. */
    secp256k1_sha256 sha256_m;
    secp256k1_rangeproof_header header;
    int ret;
    size_t i;
    size_t pub_idx;
    size_t offset;
    size_t offset_post_header;
    unsigned char signs[31];
    unsigned char m[33];
    const unsigned char *e0;
    if (!secp256k1_rangeproof_header_parse(&header, &offset, proof, plen)) {
        return 0;
    }
    *min_value = header.min_value;
    *max_value = header.max_value;
    offset_post_header = offset;
    if (plen - offset < 32 * (header.n_pubs + header.n_rings - 1) + 32 + ((header.n_rings + 6) >> 3)) {
        return 0;
    }
    secp256k1_sha256_initialize(&sha256_m);
    secp256k1_rangeproof_serialize_point(m, commit);
    secp256k1_sha256_write(&sha256_m, m, 33);
    secp256k1_rangeproof_serialize_point(m, genp);
    secp256k1_sha256_write(&sha256_m, m, 33);
    secp256k1_sha256_write(&sha256_m, proof, offset);
    for(i = 0; i < header.n_rings - 1; i++) {
        signs[i] = (proof[offset + ( i>> 3)] & (1 << (i & 7))) != 0;
    }
    offset += (header.n_rings + 6) >> 3;
    if ((header.n_rings - 1) & 7) {
        /* Number of coded blinded points is not a multiple of 8, force extra sign bits to 0 to reject mutation. */
        if ((proof[offset - 1] >> ((header.n_rings - 1) & 7)) != 0) {
            return 0;
        }
    }
    pub_idx = 0;
    secp256k1_gej_set_infinity(&accj);
    if (*min_value) {
        secp256k1_pedersen_ecmult_small(&accj, *min_value, genp);
    }
    for(i = 0; i < header.n_rings - 1; i++) {
        secp256k1_fe fe;
        secp256k1_ge c;
        if (!secp256k1_fe_set_b32(&fe, &proof[offset]) ||
            !secp256k1_ge_set_xquad(&c, &fe)) {
            return 0;
        }
        if (signs[i]) {
            secp256k1_ge_neg(&c, &c);
        }
        /* Not using secp256k1_rangeproof_serialize_point as we almost have it
         * serialized form already. */
        secp256k1_sha256_write(&sha256_m, &signs[i], 1);
        secp256k1_sha256_write(&sha256_m, &proof[offset], 32);
        secp256k1_gej_set_ge(&pubs[pub_idx], &c);
        secp256k1_gej_add_ge_var(&accj, &accj, &c, NULL);
        offset += 32;
        pub_idx += header.rsizes[i];
    }
    secp256k1_gej_neg(&accj, &accj);
    secp256k1_gej_add_ge_var(&pubs[pub_idx], &accj, commit, NULL);
    if (secp256k1_gej_is_infinity(&pubs[pub_idx])) {
        return 0;
    }
    secp256k1_rangeproof_pub_expand(pubs, header.exp, header.rsizes, header.n_rings, genp);
    e0 = &proof[offset];
    offset += 32;
    for (i = 0; i < header.n_pubs; i++) {
        int overflow;
        secp256k1_scalar_set_b32(&s[i], &proof[offset], &overflow);
        if (overflow) {
            return 0;
        }
        offset += 32;
    }
    if (offset != plen) {
        /*Extra data found, reject.*/
        return 0;
    }
    if (extra_commit != NULL) {
        secp256k1_sha256_write(&sha256_m, extra_commit, extra_commit_len);
    }
    secp256k1_sha256_finalize(&sha256_m, m);
    ret = secp256k1_borromean_verify(nonce ? evalues : NULL, e0, s, pubs, header.rsizes, header.n_rings, m, 32);
    if (ret && nonce) {
        /* Given the nonce, try rewinding the witness to recover its initial state. */
        secp256k1_scalar blind;
        uint64_t vv;
        if (!ecmult_gen_ctx) {
            return 0;
        }
        if (!secp256k1_rangeproof_rewind_inner(&blind, &vv, message_out, outlen, evalues, s, &header, nonce, commit, proof, offset_post_header, genp)) {
            return 0;
        }
        /* Unwind apparently successful, see if the commitment can be reconstructed. */
        /* FIXME: should check vv is in the mantissa's range. */
        vv = (vv * header.scale) + header.min_value;
        secp256k1_pedersen_ecmult(ecmult_gen_ctx, &accj, &blind, vv, genp);
        if (secp256k1_gej_is_infinity(&accj)) {
            return 0;
        }
        secp256k1_gej_neg(&accj, &accj);
        secp256k1_gej_add_ge_var(&accj, &accj, commit, NULL);
        if (!secp256k1_gej_is_infinity(&accj)) {
            return 0;
        }
        if (blindout) {
            secp256k1_scalar_get_b32(blindout, &blind);
        }
        if (value_out) {
            *value_out = vv;
        }
    }
    return ret;
}

#endif
