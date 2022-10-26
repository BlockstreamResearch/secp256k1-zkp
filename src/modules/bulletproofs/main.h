#ifndef SECP256K1_MODULE_BULLETPROOFS_MAIN_H
#define SECP256K1_MODULE_BULLETPROOFS_MAIN_H

/* this type must be completed before any of the modules/bulletproofs includes */
struct secp256k1_bulletproofs_generators {
    size_t n;
    /* n total generators; includes both G_i and H_i */
    /* For BP++, the generators are G_i from [0..(n - 8)] and the last 8 values
    are generators are for H_i */
    secp256k1_ge* gens;
};

#endif
