/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef _SECP256K1_BORROMEAN_H_
#define _SECP256K1_BORROMEAN_H_

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

typedef int (secp256k1_borromean_sign_ring_callback)(const secp256k1_gej **pubs, const secp256k1_scalar **k, size_t *rsize, size_t *secidx, size_t ridx, void* cbdata);

int secp256k1_borromean_verify(const secp256k1_ecmult_context* ecmult_ctx, secp256k1_scalar *evalues, const unsigned char *e0, const secp256k1_scalar *ss,
 const secp256k1_gej *pubs, const size_t *rsizes, size_t nrings, const unsigned char *m, size_t mlen);

int secp256k1_borromean_sign(const secp256k1_ecmult_context* ecmult_ctx, const secp256k1_ecmult_gen_context *ecmult_gen_ctx,
 unsigned char *e0, secp256k1_scalar *ss, const secp256k1_gej *pubs, const secp256k1_scalar *ks, const secp256k1_scalar *sec,
 const size_t *rsizes, const size_t *secidxs, size_t nrings, const unsigned char *m, size_t mlen);

int secp256k1_borromean_sign_with_callback(const secp256k1_ecmult_context* ecmult_ctx, const secp256k1_ecmult_gen_context *ecmult_gen_ctx,
 unsigned char *e0, secp256k1_scalar *ss, const secp256k1_scalar *sec, size_t nrings, const unsigned char *m, size_t mlen, secp256k1_borromean_sign_ring_callback *cb, void *cbdata);

#endif
