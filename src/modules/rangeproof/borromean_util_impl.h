/**********************************************************************
 * Copyright (c) 2021 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BORROMEAN_UTIL_IMPL_H_
#define _SECP256K1_BORROMEAN_UTIL_IMPL_H_

#include "modules/rangeproof/borromean_util.h"
#include "util.h"

static size_t secp256k1_borromean_sz_closure_const_call(const secp256k1_borromean_sz_closure* self, size_t index) {
    (void) index;
    return self->input;
}

secp256k1_borromean_sz_closure secp256k1_borromean_sz_closure_const(uint64_t c) {
    secp256k1_borromean_sz_closure ret;
    VERIFY_CHECK(c < SIZE_MAX);
    ret.input = c;
    ret.call = secp256k1_borromean_sz_closure_const_call;
    return ret;
}

#endif
