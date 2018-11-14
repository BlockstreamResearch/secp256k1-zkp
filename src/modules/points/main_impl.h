#ifndef SECP256K1_MODULE_POINTS
#define SECP256K1_MODULE_POINTS

#include <assert.h>
#include <string.h>
#include "include/secp256k1_points.h"


static void secp256k1_point_load(secp256k1_ge* ge, const secp256k1_point* point) {
    int succeed;
    succeed = secp256k1_fe_set_b32(&ge->x, &point->data[0]);
    VERIFY_CHECK(succeed != 0);
    succeed = secp256k1_fe_set_b32(&ge->y, &point->data[32]);
    VERIFY_CHECK(succeed != 0);
    ge->infinity = 0;
    (void) succeed;
}

static void secp256k1_point_save(secp256k1_point *point, secp256k1_ge* ge) {
    VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(&point->data[0], &ge->x);
    secp256k1_fe_get_b32(&point->data[32], &ge->y);
}

int secp256k1_point_serialize(unsigned char *output, const secp256k1_point* point) {
    secp256k1_ge ge;

    VERIFY_CHECK(output != NULL);
    VERIFY_CHECK(point != NULL);

    secp256k1_point_load(&ge, point);

    output[0] = 129 ^ secp256k1_fe_is_quad_var(&ge.y);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_get_b32(&output[1], &ge.x);
    return 1;
}

int secp256k1_point_parse(secp256k1_point* point, const unsigned char *input) {
    secp256k1_fe x;
    secp256k1_ge ge;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(input != NULL);

    if ((input[0] & 0xFE) != 128 ||
        !secp256k1_fe_set_b32(&x, &input[1]) ||
        !secp256k1_ge_set_xquad(&ge, &x)) {
        return 0;
    }
    if (input[0] & 1) {
        secp256k1_ge_neg(&ge, &ge);
    }
    secp256k1_point_save(point, &ge);
    return 1;
}

int secp256k1_points_combine(secp256k1_point *out, const secp256k1_point * const *addends, size_t n) {
    size_t i;
    secp256k1_gej Qj;
    secp256k1_ge Q;

    VERIFY_CHECK(out != NULL);
    memset(out, 0, sizeof(*out));
    VERIFY_CHECK(n >= 1);
    VERIFY_CHECK(addends != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        secp256k1_point_load(&Q, addends[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_point_save(out, &Q);
    return 1;
}

int secp256k1_point_mul(const secp256k1_context* ctx, secp256k1_point *point, const unsigned char *multiplier) {
    secp256k1_ge p;
    secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;


    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(point != NULL);
    ARG_CHECK(multiplier != NULL);

    secp256k1_scalar_set_b32(&factor, multiplier, &overflow);
    if (secp256k1_scalar_is_zero(&factor)) {
        return 0;
    }
    ret = !overflow;
    secp256k1_point_load(&p, point);
    memset(point, 0, sizeof(*point));
    if (ret) {
        secp256k1_scalar zero;
        secp256k1_gej pt;
        secp256k1_scalar_set_int(&zero, 0);
        secp256k1_gej_set_ge(&pt, &p); 
        secp256k1_ecmult(&ctx->ecmult_ctx, &pt, &pt, &factor, &zero);
        secp256k1_ge_set_gej(&p, &pt);
        secp256k1_point_save(point, &p);
    }

    return ret;
}

void secp256k1_points_cast_point_to_pubkey(secp256k1_point* point, secp256k1_pubkey* pubkey) {
    secp256k1_ge p;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(pubkey != NULL);

    secp256k1_point_load(&p, point);
    secp256k1_pubkey_save(pubkey, &p);
}

void secp256k1_points_cast_pubkey_to_point(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, secp256k1_point* point) {
    secp256k1_ge p;

    VERIFY_CHECK(ctx != NULL);
    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(pubkey != NULL);

    secp256k1_pubkey_load(ctx, &p, pubkey);
    secp256k1_point_save(point, &p);
}

#ifdef ENABLE_MODULE_GENERATOR
#include "include/secp256k1_generator.h"
void secp256k1_points_cast_point_to_generator(secp256k1_point* point, secp256k1_generator* generator) {
    secp256k1_ge p;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(generator != NULL);

    secp256k1_point_load(&p, point);
    secp256k1_generator_save(generator, &p);
}

void secp256k1_points_cast_generator_to_point(secp256k1_generator* generator, secp256k1_point* point) {
    secp256k1_ge p;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(generator != NULL);

    secp256k1_generator_load(&p, generator);
    secp256k1_point_save(point, &p);
}
#endif /* ENABLE_MODULE_GENERATOR */


#ifdef ENABLE_MODULE_RANGEPROOF
#include "include/secp256k1_rangeproof.h"
void secp256k1_points_cast_point_to_pedersen_commitment(secp256k1_point* point, secp256k1_pedersen_commitment* pedersen_commitment) {
    secp256k1_ge p;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(pedersen_commitment != NULL);

    secp256k1_point_load(&p, point);
    secp256k1_pedersen_commitment_save(pedersen_commitment, &p);
}

void secp256k1_points_cast_pedersen_commitment_to_point(secp256k1_pedersen_commitment* pedersen_commitment, secp256k1_point* point) {
    secp256k1_ge p;

    VERIFY_CHECK(point != NULL);
    VERIFY_CHECK(pedersen_commitment != NULL);

    secp256k1_pedersen_commitment_load(&p, pedersen_commitment);
    secp256k1_point_save(point, &p);
}
#endif /* ENABLE_MODULE_RANGEPROOF */

#endif
