/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_INTERNALS_SCALAR_IMPL
#define SECP256K1_MODULE_INTERNALS_SCALAR_IMPL

#include "scalar.h"

struct secp256k1_internals_scalar_struct {
    secp256k1_scalar s;
};

size_t secp256k1_internals_scalar_size() {
    return sizeof(struct secp256k1_internals_scalar_struct);
}

void secp256k1_internals_scalar_set_b32(secp256k1_internals_scalar *r, const unsigned char *bin, int *overflow) {
    secp256k1_scalar_set_b32(&r->s, bin, overflow);
}

void secp256k1_internals_scalar_get_b32(unsigned char *bin, const secp256k1_internals_scalar* a) {
    secp256k1_scalar_get_b32(bin, &a->s);
}

int secp256k1_internals_scalar_add(secp256k1_internals_scalar *r, const secp256k1_internals_scalar *a, const secp256k1_internals_scalar *b) {
    return secp256k1_scalar_add(&r->s, &a->s, &b->s);
}

#endif
