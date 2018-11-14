#ifndef SECP256K1_MODULE_POINTS_TESTS
#define SECP256K1_MODULE_POINTS_TESTS

#include <string.h>

#include "group.h"
#include "scalar.h"
#include "testrand.h"
#include "util.h"

#include "include/secp256k1_points.h"

static void test_casts(void) {
  secp256k1_point point, casted_from_key, deserialized_point;
  secp256k1_pubkey key, key_casted_from_point;
  unsigned char point_pad[33], key_pad[33];
  size_t len = 33;
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_generator gen, gen_casted_from_point;
  secp256k1_point casted_from_gen;
  unsigned char gen_pad[33];
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_pedersen_commitment com, com_casted_from_point;
  secp256k1_point casted_from_com;
  unsigned char com_pad[33];
  #endif
  secp256k1_gej j;
  secp256k1_ge ge;
  secp256k1_context *sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
       
  secp256k1_scalar s;
  random_scalar_order_test(&s);
  secp256k1_ecmult_gen(&sign_ctx->ecmult_gen_ctx, &j, &s);
  
  secp256k1_ge_set_gej(&ge, &j);
  secp256k1_pubkey_save(&key, &ge);
  secp256k1_point_save(&point, &ge);
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_generator_save(&gen, &ge);
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_pedersen_commitment_save(&com, &ge);
  #endif
  
  secp256k1_points_cast_pubkey_to_point(sign_ctx, &key, &casted_from_key);
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_points_cast_generator_to_point(&gen, &casted_from_gen);
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_points_cast_pedersen_commitment_to_point(&com, &casted_from_com);
  #endif

  secp256k1_point_serialize(point_pad, &point);
  secp256k1_point_serialize(key_pad, &casted_from_key);

  CHECK(!memcmp(point_pad, key_pad, 33));
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_point_serialize(gen_pad, &casted_from_gen);
  CHECK(!memcmp(point_pad, gen_pad, 33));
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_point_serialize(com_pad, &casted_from_com);
  CHECK(!memcmp(point_pad, com_pad, 33));
  #endif

  CHECK(secp256k1_point_parse(&deserialized_point, point_pad));
  secp256k1_points_cast_point_to_pubkey(&deserialized_point, &key_casted_from_point);
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_points_cast_point_to_generator(&deserialized_point, &gen_casted_from_point);
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_points_cast_point_to_pedersen_commitment(&deserialized_point, &com_casted_from_point);
  #endif

  secp256k1_ec_pubkey_serialize(sign_ctx, key_pad, &len, &key, SECP256K1_EC_COMPRESSED);
  secp256k1_ec_pubkey_serialize(sign_ctx, point_pad, &len, &key_casted_from_point, SECP256K1_EC_COMPRESSED);
  CHECK(!memcmp(point_pad, key_pad, 33));
  #ifdef ENABLE_MODULE_GENERATOR
  secp256k1_generator_serialize(sign_ctx, point_pad, &gen_casted_from_point);
  secp256k1_generator_serialize(sign_ctx, gen_pad, &gen);
  CHECK(!memcmp(point_pad, gen_pad, 33));
  #endif
  #ifdef ENABLE_MODULE_RANGEPROOF
  secp256k1_pedersen_commitment_serialize(sign_ctx, point_pad, &com_casted_from_point);
  secp256k1_pedersen_commitment_serialize(sign_ctx, com_pad, &com);
  CHECK(!memcmp(point_pad, com_pad, 33));
  #endif
  
  
  
}

static void test_curve_operations(void) {
  /* Since operations with public keys are well tested we
     just compare results with pubkey tweaks and combine */
  secp256k1_pubkey keys[10], combine_key;
  secp256k1_point points[10], combine_point, multipication_result, casted_from_key;
  const secp256k1_pubkey *pubkeys[10];
  const secp256k1_point *_points[10],  *tripple_point[3];
  unsigned char three[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
  unsigned char combine_point_pad[33], multipication_result_pad[33], key_pad[33];
  secp256k1_context *both_ctx;
  secp256k1_gej j;
  secp256k1_ge ge;
  secp256k1_scalar s;
  int counter;
  
  both_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |SECP256K1_CONTEXT_VERIFY);

  for(counter=0; counter<10; counter++)  {
      random_scalar_order_test(&s);
      secp256k1_ecmult_gen(&both_ctx->ecmult_gen_ctx, &j, &s);  
      secp256k1_ge_set_gej(&ge, &j);
      secp256k1_pubkey_save(&keys[counter], &ge);
      secp256k1_point_save(&points[counter], &ge);
      _points[counter] = &points[counter];
      pubkeys[counter] = &keys[counter];
  }
  
  tripple_point[0] = &points[0]; tripple_point[1] = &points[0]; tripple_point[2] = &points[0];
  secp256k1_point_load(&ge, &points[0]);
  secp256k1_point_save(&multipication_result, &ge);

  CHECK(secp256k1_points_combine(&combine_point, tripple_point, 3));
  
  CHECK(secp256k1_point_mul(both_ctx, &multipication_result, three));
  
  secp256k1_point_serialize(combine_point_pad, &combine_point);
  secp256k1_point_serialize(multipication_result_pad, &multipication_result);
  CHECK(!memcmp(combine_point_pad, multipication_result_pad, 33));
  
  CHECK(secp256k1_points_combine(&combine_point, _points, 10));
  CHECK(secp256k1_ec_pubkey_combine(both_ctx, &combine_key, pubkeys, 10));
  secp256k1_points_cast_pubkey_to_point(both_ctx, &combine_key, &casted_from_key);
  secp256k1_point_serialize(combine_point_pad, &combine_point);
  secp256k1_point_serialize(key_pad, &casted_from_key);
  CHECK(!memcmp(combine_point_pad, key_pad, 33));

  for(counter=0; counter<10; counter++)  {
      CHECK(secp256k1_ec_pubkey_tweak_mul(both_ctx, &keys[counter], combine_point_pad));
      CHECK(secp256k1_point_mul(both_ctx, &points[counter], combine_point_pad));
      secp256k1_points_cast_pubkey_to_point(both_ctx, &keys[counter], &casted_from_key);
      secp256k1_point_serialize(multipication_result_pad, &points[counter]);
      secp256k1_point_serialize(key_pad, &casted_from_key);
      CHECK(!memcmp(multipication_result_pad, key_pad, 33));      
    }
  
}

void run_points_tests(void) {
    test_casts();
    test_curve_operations();
}

#endif
