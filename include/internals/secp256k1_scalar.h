#ifndef SECP256K1_INTERNALS_H
#define SECP256K1_INTERNALS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Caller is responsible for allocating a maximally-aligned space of size
   secp256k1_internals_scalar_size */
typedef struct secp256k1_internals_scalar_struct secp256k1_internals_scalar;

SECP256K1_API size_t secp256k1_internals_scalar_size(void);

SECP256K1_API void secp256k1_internals_scalar_set_b32(secp256k1_internals_scalar *r, const unsigned char *bin, int *overflow);

SECP256K1_API void secp256k1_internals_scalar_get_b32(unsigned char *bin, const secp256k1_internals_scalar* a);

SECP256K1_API int secp256k1_internals_scalar_add(secp256k1_internals_scalar *r, const secp256k1_internals_scalar *a, const secp256k1_internals_scalar *b);

#ifdef __cplusplus
}
#endif
#endif
