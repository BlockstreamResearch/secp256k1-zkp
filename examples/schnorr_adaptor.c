/*************************************************************************
 * Written in 2024 by Sivaram Dhakshinamoorthy                           *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_schnorr_adaptor.h>

#include "examples_util.h"

/** This example implements the Multi-hop Locks protocol described in
 *  https://github.com/BlockstreamResearch/scriptless-scripts/blob/master/md/multi-hop-locks.md,
 *  using the Schnorr adaptor module.
 *
 *  In this example, Alice (sender) sends a payment to Carol (recipient)
 *  via Bob (intermediate hop). The protocol ensures that Alice exchanges
 *  her coins for a proof of payment from Carol, and Bob securely forwards
 *  the payment without being able to access its details.
 *
 *  Carol provides Alice with a point (z*G), which acts as the proof of
 *  payment. Alice sets up cryptographic locks with Bob, and Bob forwards
 *  the payment to Carol. When Carol reveals the secret z to claim the
 *  payment, Alice learns the proof of payment.
 */

static int create_keypair(const secp256k1_context *ctx, secp256k1_keypair *keypair, secp256k1_xonly_pubkey *pubkey) {
	unsigned char seckey[32];
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 0;
        }
        if (secp256k1_keypair_create(ctx, keypair, seckey)) {
            break;
        }
    }
    if(!secp256k1_keypair_xonly_pub(ctx, pubkey, NULL, keypair)){
		return 0;
	}
	return 1;
}

/* Creates the locks required for multi-hop payments */
static int create_hop_locks(const secp256k1_context *ctx, secp256k1_pubkey *left_lock, secp256k1_pubkey *right_lock, secp256k1_pubkey *adaptor_pop, unsigned char *tweak_sum, unsigned char *tweak1, unsigned char *tweak2) {
    while (1) {
		if (!fill_random(tweak1, 32)) {
			printf("Failed to generate randomness\n");
			return 0;
		}
		if (!fill_random(tweak2, 32)) {
			printf("Failed to generate randomness\n");
			return 0;
		}
        if (secp256k1_ec_seckey_verify(ctx, tweak1) && secp256k1_ec_seckey_verify(ctx, tweak2)) {
            break;
        }
    }
	/* Create left lock = (z + tweak1)*G */
	memcpy(left_lock, adaptor_pop, sizeof(secp256k1_pubkey));
	if(!secp256k1_ec_pubkey_tweak_add(ctx, left_lock, tweak1)) {
		return 0;
	}

	/* Create right lock = (z + tweak1 + tweak2)*G */
	memcpy(tweak_sum, tweak1, 32);
	if(!secp256k1_ec_seckey_tweak_add(ctx, tweak_sum, tweak2)) {
		return 0;
	}
	memcpy(right_lock, adaptor_pop, sizeof(secp256k1_pubkey));
	if(!secp256k1_ec_pubkey_tweak_add(ctx, right_lock, tweak_sum)) {
		return 0;
	}

	return 1;
}

int main(void) {
    unsigned char tx_ab[32] = "alice sends a payment to bob....";
    unsigned char tx_bc[32] = "bob sends a payment to carol....";
    unsigned char presig_ab[65];
    unsigned char presig_bc[65];
	unsigned char sig_ab[64];
	unsigned char sig_bc[64];
	unsigned char tmp[32];
	unsigned char tweak1[32];
	unsigned char tweak2[32];
	unsigned char tweak_sum[32];
	unsigned char secret_pop[32]; /* Carol's secret proof of payment */
    secp256k1_pubkey adaptor_pop;
	secp256k1_pubkey left_lock;
	secp256k1_pubkey right_lock;
	secp256k1_pubkey tmp_pubkey;
    secp256k1_xonly_pubkey pubkey_a, pubkey_b;
	secp256k1_keypair keypair_a, keypair_b;
	int ret;

	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

	/* Generate keypairs for Alice and Bob */
	ret = create_keypair(ctx, &keypair_a, &pubkey_a);
	assert(ret);
	ret = create_keypair(ctx, &keypair_b, &pubkey_b);
	assert(ret);

	/* Carol setup: creates a proof of payment (z*G) */
	if (!fill_random(secret_pop, sizeof(secret_pop))) {
		printf("Failed to generate randomness\n");
		return 1;
	}
	ret = secp256k1_ec_pubkey_create(ctx, &adaptor_pop, secret_pop);
	assert(ret);

	/* Alice's setup: Generates tweak1, tweak2, left lock, and right lock
	* for the payment. She shares the following:
	*
	* 1. With Bob: tweak2, left lock, right lock
	* 2. With Carol: tweak1 + tweak2, right lock
	*/
	if (!create_hop_locks(ctx, &left_lock, &right_lock, &adaptor_pop, tweak_sum, tweak1, tweak2)) {
		return 1;
	}
	/* Alice sends a pre-signature to Bob */
	ret = secp256k1_schnorr_adaptor_presign(ctx, presig_ab, tx_ab, &keypair_a, &left_lock, NULL);
	assert(ret);

	/* Bob setup: extracts the left lock from Alice's pre-signature and verifies it */
	ret = secp256k1_schnorr_adaptor_extract(ctx, &tmp_pubkey, presig_ab, tx_ab, &pubkey_a);
	assert(ret);
	assert(memcmp(&tmp_pubkey, &left_lock, sizeof(left_lock)) == 0);
	/* Bob creates a pre-signature that forwards the payment to Carol */
	ret = secp256k1_schnorr_adaptor_presign(ctx, presig_bc, tx_bc, &keypair_b, &right_lock, NULL);
	assert(ret);

	/* Carol extracts the right lock from Bob's pre-signature and verifies it */
	ret = secp256k1_schnorr_adaptor_extract(ctx, &tmp_pubkey, presig_bc, tx_bc, &pubkey_b);
	assert(ret);
	assert(memcmp(&tmp_pubkey, &right_lock, sizeof(right_lock)) == 0);
	/* Carol claims her payment by adapting Bob's pre-signature with the
	* secret = z + tweak1 + tweak2, to produce a valid BIP340 Schnorr
	* signature. */
	memcpy(tmp, secret_pop, sizeof(secret_pop));
	ret = secp256k1_ec_seckey_tweak_add(ctx, tmp, tweak_sum);
	assert(ret);
	ret = secp256k1_schnorr_adaptor_adapt(ctx, sig_bc, presig_bc, tmp);
	assert(ret);
	assert(secp256k1_schnorrsig_verify(ctx, sig_bc, tx_bc, sizeof(tx_bc), &pubkey_b));

	/* Bob extracts the secret = z + tweak1 + tweak2 from his pre-signature
	* and the BIP340 signature created by Carol. */
	ret = secp256k1_schnorr_adaptor_extract_sec(ctx, tmp, presig_bc, sig_bc);
	assert(ret);
	/* Bob claims his payment by adapting Alice's pre-signature with the
	* secret = z + tweak1, to produce a valid BIP340 Schnorr signature. */
	ret = secp256k1_ec_seckey_negate(ctx, tweak2);
	assert(ret);
	ret = secp256k1_ec_seckey_tweak_add(ctx, tmp, tweak2);
	assert(ret);
	ret = secp256k1_schnorr_adaptor_adapt(ctx, sig_ab, presig_ab, tmp);
	assert(ret);
	assert(secp256k1_schnorrsig_verify(ctx, sig_ab, tx_ab, sizeof(tx_ab), &pubkey_a));

	/* Alice extracts the proof of payment = z from her pre-signature
	 * and the BIP340 signature created by Bob. */
	ret = secp256k1_schnorr_adaptor_extract_sec(ctx, tmp, presig_ab, sig_ab);
	assert(ret);
	ret = secp256k1_ec_seckey_negate(ctx, tweak1);
	assert(ret);
	ret = secp256k1_ec_seckey_tweak_add(ctx, tmp, tweak1);
	assert(ret);
	assert(memcmp(tmp, secret_pop, sizeof(secret_pop)) == 0);

	printf("Multi-hop locks protocol successfully executed!!!\n");
	secp256k1_context_destroy(ctx);
	return 0;
}
