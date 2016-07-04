/***********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_PEDERSEN_IMPL_H_
#define _SECP256K1_PEDERSEN_IMPL_H_

#include <string.h>

#include "eckey.h"
#include "ecmult_const.h"
#include "ecmult_gen.h"
#include "group.h"
#include "field.h"
#include "scalar.h"
#include "util.h"

/** Alternative generator for secp256k1.
 *  This is the sha256 of 'g' after DER encoding (without compression),
 *  which happens to be a point on the curve.
 *  sage: G2 = EllipticCurve ([F (0), F (7)]).lift_x(int(hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex')).hexdigest(),16))
 *  sage: '%x %x'%G2.xy()
 */
static const secp256k1_ge secp256k1_ge_const_g2 = SECP256K1_GE_CONST(
    0x50929b74UL, 0xc1a04954UL, 0xb78b4b60UL, 0x35e97a5eUL,
    0x078a5a0fUL, 0x28ec96d5UL, 0x47bfee9aUL, 0xce803ac0UL,
    0x31d3c686UL, 0x3973926eUL, 0x049e637cUL, 0xb1b5f40aUL,
    0x36dac28aUL, 0xf1766968UL, 0xc30c2313UL, 0xf3a38904UL
);

static void secp256k1_pedersen_scalar_set_u64(secp256k1_scalar *sec, uint64_t value) {
    unsigned char data[32];
    int i;
    for (i = 0; i < 24; i++) {
        data[i] = 0;
    }
    for (; i < 32; i++) {
        data[i] = value >> 56;
        value <<= 8;
    }
    secp256k1_scalar_set_b32(sec, data, NULL);
    memset(data, 0, 32);
}

static void secp256k1_pedersen_ecmult_small(secp256k1_gej *r, uint64_t gn) {
    secp256k1_scalar s;
    secp256k1_pedersen_scalar_set_u64(&s, gn);
    secp256k1_ecmult_const(r, &secp256k1_ge_const_g2, &s, 64);
    secp256k1_scalar_clear(&s);
}

/* sec * G + value * G2. */
SECP256K1_INLINE static void secp256k1_pedersen_ecmult(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_gej *rj, const secp256k1_scalar *sec, uint64_t value) {
    secp256k1_gej vj;
    secp256k1_ecmult_gen(ecmult_gen_ctx, rj, sec);
    secp256k1_pedersen_ecmult_small(&vj, value);
    /* FIXME: constant time. */
    secp256k1_gej_add_var(rj, rj, &vj, NULL);
    secp256k1_gej_clear(&vj);
}

#endif
