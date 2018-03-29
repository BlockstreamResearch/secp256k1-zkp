/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_PARSER_IMPL
#define SECP256K1_MODULE_BULLETPROOF_PARSER_IMPL

#include <ctype.h>
#include <stdio.h>

#include "modules/bulletproofs/circuit_compress_impl.h"

static size_t secp256k1_bulletproof_encoding_width(size_t n) {
    if (n < 0x100) return 1;
    if (n < 0x10000) return 2;
    if (n < 0x100000000) return 4;
    return 8;
}

static void secp256k1_encode(unsigned char *buf, size_t width, size_t n) {
     size_t i;
     for (i = 0; i < width; i++) {
         buf[i] = n;
         n >>= 8;
     }
}

static size_t secp256k1_decode(const unsigned char *buf, size_t width) {
    size_t ret = 0;
    while (width--) {
        ret = ret * 0x100 + buf[width];
    }
    return ret;
}

static size_t secp256k1_scalar_encode(unsigned char *buf, const secp256k1_fast_scalar *s) {
     secp256k1_scalar tmp = s->scal;
     size_t i = 0;
     size_t high = secp256k1_scalar_is_high(&tmp);

     if (high) {
         secp256k1_scalar_negate(&tmp, &tmp);
     }

     while (!secp256k1_scalar_is_zero(&tmp)) {
         buf[1 + i] = secp256k1_scalar_shr_int(&tmp, 8);
         i++;
     }

     buf[0] = i ^ (high << 7);
     return i + 1;
}

static int secp256k1_scalar_decode(secp256k1_fast_scalar *r, const unsigned char *buf) {
    secp256k1_scalar two;
    unsigned char rbuf[32] = {0};
    const size_t neg = buf[0] & 0x80;
    const size_t len = buf[0] & 0x3f;
    size_t i;
    int overflow;

    for (i = 0; i < len; i++) {
        rbuf[31 - i] = buf[i + 1];
    }
    secp256k1_scalar_set_b32(&r->scal, rbuf, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_int(&two, 2);
    if (secp256k1_scalar_is_one(&r->scal)) {
        r->special = neg ? -1 : 1;
    } else if (secp256k1_scalar_eq(&r->scal, &two)) {
        r->special = neg ? -2 : 2;
    } else if (secp256k1_scalar_is_zero(&r->scal)) {
        r->special = 0;
    } else {
        r->special = 5;
    }
    if (neg) {
        secp256k1_scalar_negate(&r->scal, &r->scal);
    }
    return 1;
}

static int secp256k1_bulletproof_matrix_encode(FILE *fh, const secp256k1_bulletproof_wmatrix_row *w, size_t n_rows) {
    size_t i;
    unsigned char buf[41];
    const size_t row_width = secp256k1_bulletproof_encoding_width(n_rows);
    for (i = 0; i < n_rows; i++) {
        size_t j;
        size_t scalar_width;
        secp256k1_encode(buf, row_width, w[i].size);
        if (fwrite(buf, row_width, 1, fh) != 1) {
            return 0;
        }
        for (j = 0; j < w[i].size; j++) {
            secp256k1_encode(buf, row_width, w[i].entry[j].idx);
            scalar_width = secp256k1_scalar_encode(buf + row_width, &w[i].entry[j].scal);
            if (fwrite(buf, row_width + scalar_width, 1, fh) != 1) {
                return 0;
            }
        }
    }
    return 1;
}

static int secp256k1_bulletproof_matrix_decode(FILE *fh, secp256k1_bulletproof_wmatrix_row *w, secp256k1_bulletproof_wmatrix_entry *entries, size_t *n_entries, size_t n_rows, size_t row_width) {
    size_t i;
    unsigned char buf[0x3f];

    for (i = 0; i < n_rows; i++) {
        size_t j;
        if (fread(buf, row_width, 1, fh) != 1) {
            return 0;
        }
        w[i].size = secp256k1_decode(buf, row_width);
        w[i].entry = &entries[*n_entries];
        for (j = 0; j < w[i].size; j++) {
            if (fread(buf, row_width, 1, fh) != 1) {
                return 0;
            }
            w[i].entry[j].idx = secp256k1_decode(buf, row_width);
            if (fread(buf, 1, 1, fh) != 1 ||
                fread(buf + 1, buf[0] & 0x3f, 1, fh) != 1 ||
                secp256k1_scalar_decode(&w[i].entry[j].scal, buf) != 1) {
                return 0;
            }
        }
        *n_entries += w[i].size;
    }
    return 1;
}

/* Function that just does a one-pass through a circuit to allocate memory */
static int secp256k1_bulletproof_circuit_allocate_memory(const secp256k1_context *ctx, FILE *fh, secp256k1_bulletproof_circuit **ret) {
    unsigned char buf[32];
    size_t version;
    size_t n_gates;
    size_t n_bits;
    size_t n_commits;
    size_t n_constraints;
    size_t n_entries;
    size_t total_mem;
    size_t i, w;

    if (fread(buf, 32, 1, fh) != 1) {
        return 0;
    }

    version = secp256k1_decode(&buf[0], 4);  /* read version and flags as one word */
    if (version != SECP256K1_BULLETPROOF_CIRCUIT_VERSION) {
        return 0;
    }
    n_commits = secp256k1_decode(&buf[4], 4);
    n_gates = secp256k1_decode(&buf[8], 8);
    n_bits = secp256k1_decode(&buf[16], 8);
    n_constraints = secp256k1_decode(&buf[24], 8);
    if (n_bits > n_gates) {
        return 0;
    }

    /* WL / WR / WO / WV entries */
    n_entries = 0;
    w = secp256k1_bulletproof_encoding_width(n_gates);
    for (i = 0; i < 3 * n_gates + n_commits; i++) {
        size_t n;
        if (i == 3 * n_gates) {
            w = secp256k1_bulletproof_encoding_width(n_commits);
        }
        if (fread(buf, w, 1, fh) != 1) {
            return 0;
        }
        n = secp256k1_decode(buf, w);
        n_entries += n;
        while (n--) {
            if (fseek(fh, w, SEEK_CUR)) { /* skip index */
                return 0;
            }
            if (fread(buf, 1, 1, fh) != 1) { /* read scalar width */
                return 0;
            }
            if (fseek(fh, buf[0] & 0x3f, SEEK_CUR)) { /* skip scalar */
                return 0;
            }
        }
    }
    /* Number of c entries is implied by n_constraints */
    total_mem = sizeof(**ret) + (3 * n_gates + n_commits) * sizeof(*(*ret)->wl) + n_constraints * sizeof(*(*ret)->c) + n_entries * sizeof(*(*ret)->entries);
    if (total_mem > SECP256K1_BULLETPROOF_MAX_CIRCUIT) {
        return 0;
    }
   
    /* Put the file handle back to the beginning of the file (well, right after the header) */
    if (fseek(fh, 32, SEEK_SET) != 0) {
        return 0;
    }

    /* Actually allocate all the memory */
    *ret = (secp256k1_bulletproof_circuit *)checked_malloc(&ctx->error_callback, sizeof(**ret));
    if (*ret == NULL) {
        return 0;
    }

    (*ret)->wl = (secp256k1_bulletproof_wmatrix_row *)checked_malloc(&ctx->error_callback, (3 * n_gates + n_commits) * sizeof(*(*ret)->wl));
    (*ret)->c = (secp256k1_fast_scalar *)checked_malloc(&ctx->error_callback, (3 * n_gates + n_commits) * sizeof(*(*ret)->c));
    (*ret)->entries = (secp256k1_bulletproof_wmatrix_entry *)checked_malloc(&ctx->error_callback, n_entries * sizeof(*(*ret)->entries));
    if ((*ret)->wl == NULL || (*ret)->c == NULL || (*ret)->entries == NULL) {
        free((*ret)->wl);
        free((*ret)->c);
        free((*ret)->entries);
        free(*ret);
        *ret = NULL;
        return 0;
    }

    (*ret)->n_commits = n_commits;
    (*ret)->n_gates = n_gates;
    (*ret)->n_bits = n_bits;
    (*ret)->n_constraints = n_constraints;
    (*ret)->wr = &(*ret)->wl[1 * n_gates];
    (*ret)->wo = &(*ret)->wl[2 * n_gates];
    (*ret)->wv = &(*ret)->wl[3 * n_gates];

    return 1;
}

/* text string parser */
static void secp256k1_parse_scalar(secp256k1_fast_scalar *r, const char *c, const char **end) {
    int neg = 0;
    int null = 1;
    while (isspace(*c)) {
        c++;
    }
    if (*c == '-') {
        neg = 1;
    }
    if (*c == '-' || *c == '+') {
        c++;
    }
    while (isspace(*c)) {
        c++;
    }
    secp256k1_scalar_clear(&r->scal);
    while (isdigit(*c)) {
        secp256k1_scalar digit;
        secp256k1_scalar_set_int(&digit, 10);
        secp256k1_scalar_mul(&r->scal, &r->scal, &digit);
        secp256k1_scalar_set_int(&digit, *c - '0');
        secp256k1_scalar_add(&r->scal, &r->scal, &digit);
        null = 0;
        c++;
    }
    /* interpret empty string as 1 */
    if (null == 1) {
        secp256k1_scalar_set_int(&r->scal, 1);
    }
    while (*c && *c != ',' && *c != ';' && *c != '=' && *c != 'L' && *c != 'R' && *c != 'O' && *c != 'V') {
        c++;
    }
    if (secp256k1_scalar_is_one(&r->scal)) {
        r->special = neg ? -1 : 1;
    } else if (secp256k1_scalar_is_zero(&r->scal)) {
        r->special = 0;
    } else {
        r->special = 5;
    }
    if (neg) {
        secp256k1_scalar_negate(&r->scal, &r->scal);
    }
    if (end != NULL) {
        *end = c;
    }
}

static size_t secp256k1_compressed_circuit_size(const secp256k1_bulletproof_circuit *circ) {
    /* cached C sum, cached WL/WR/WO sums for each gate, constraint-many z powers */
    return (1 + 3 * circ->n_gates + circ->n_constraints) * sizeof(secp256k1_scalar);
}

static secp256k1_bulletproof_circuit *secp256k1_parse_circuit(const secp256k1_context *ctx, const char *c) {
    size_t i;
    int chars_read;
    const char *cstart;
    int n_gates;
    int n_commits;
    int n_bits;
    int n_constraints;
    size_t entry_idx = 0;
    secp256k1_bulletproof_circuit *ret = (secp256k1_bulletproof_circuit*)checked_malloc(&ctx->error_callback, sizeof(*ret));

    if (sscanf(c, "%d,%d,%d,%d; %n", &n_gates, &n_commits, &n_bits, &n_constraints, &chars_read) != 4) {
        free (ret);
        return NULL;
    }
    c += chars_read;

    ret->n_gates = n_gates;
    ret->n_commits = n_commits;
    ret->n_bits = n_bits;
    ret->n_constraints = n_constraints;
    ret->wl = (secp256k1_bulletproof_wmatrix_row *)checked_malloc(&ctx->error_callback, (3*ret->n_gates + ret->n_commits) * sizeof(*ret->wl));
    ret->wr = &ret->wl[1 * n_gates];
    ret->wo = &ret->wl[2 * n_gates];
    ret->wv = &ret->wl[3 * n_gates];
    ret->c = (secp256k1_fast_scalar *)checked_malloc(&ctx->error_callback, ret->n_constraints * sizeof(*ret->c));
    ret->entries = NULL;

    memset(ret->wl, 0, ret->n_gates * sizeof(*ret->wl));
    memset(ret->wr, 0, ret->n_gates * sizeof(*ret->wr));
    memset(ret->wo, 0, ret->n_gates * sizeof(*ret->wo));
    memset(ret->wv, 0, ret->n_commits * sizeof(*ret->wv));
    memset(ret->c, 0, ret->n_constraints * sizeof(*ret->c));

    cstart = c;
    for (i = 0; i < ret->n_constraints; i++) {
        int index;
        size_t j;

        j = 0;
        while (*c && *c != '=') {
            secp256k1_bulletproof_wmatrix_row *w;
            secp256k1_bulletproof_wmatrix_row *row;
            secp256k1_fast_scalar mul;

            secp256k1_parse_scalar(&mul, c, &c);
            switch (*c) {
            case 'L':
                w = ret->wl;
                break;
            case 'R':
                w = ret->wr;
                break;
            case 'O':
                w = ret->wo;
                break;
            case 'V':
                w = ret->wv;
                break;
            default:
                secp256k1_bulletproof_circuit_destroy(ctx, ret);
                return NULL;
            }
            c++;
            if (sscanf(c, "%d %n", &index, &chars_read) != 1) {
                secp256k1_bulletproof_circuit_destroy(ctx, ret);
                return NULL;
            }
            if ((w != ret->wv && index >= n_gates) || (w == ret->wv && index >= n_commits)) {
                secp256k1_bulletproof_circuit_destroy(ctx, ret);
                return NULL;
            }
            row = &w[index];

            row->size++;
            entry_idx++;

            c += chars_read;
            j++;
        }
        if (*c == '=') {
            c++;
            secp256k1_parse_scalar(&ret->c[i], c, &c);
            if (*c != ';') {
                secp256k1_bulletproof_circuit_destroy(ctx, ret);
                return NULL;
            }
            c++;
        } else {
            secp256k1_bulletproof_circuit_destroy(ctx, ret);
            return NULL;
        }
    }

    c = cstart;
    ret->entries = (secp256k1_bulletproof_wmatrix_entry *)checked_malloc(&ctx->error_callback, entry_idx * sizeof(*ret->entries));
    entry_idx = 0;
    for (i = 0; i < ret->n_gates; i++) {
        ret->wl[i].entry = &ret->entries[entry_idx];
        entry_idx += ret->wl[i].size;
        ret->wl[i].size = 0;
        ret->wr[i].entry = &ret->entries[entry_idx];
        entry_idx += ret->wr[i].size;
        ret->wr[i].size = 0;
        ret->wo[i].entry = &ret->entries[entry_idx];
        entry_idx += ret->wo[i].size;
        ret->wo[i].size = 0;
    }
    for (i = 0; i < ret->n_commits; i++) {
        ret->wv[i].entry = &ret->entries[entry_idx];
        entry_idx += ret->wv[i].size;
        ret->wv[i].size = 0;
    }

    for (i = 0; i < ret->n_constraints; i++) {
        int index;
        size_t j;

        j = 0;
        while (*c && *c != '=') {
            secp256k1_bulletproof_wmatrix_row *w;
            secp256k1_bulletproof_wmatrix_row *row;
            secp256k1_bulletproof_wmatrix_entry *entry;
            secp256k1_fast_scalar mul;

            secp256k1_parse_scalar(&mul, c, &c);
            switch (*c) {
            case 'L':
                w = ret->wl;
                break;
            case 'R':
                w = ret->wr;
                break;
            case 'O':
                w = ret->wo;
                break;
            case 'V':
                /* W_V is on the opposite side of the equation from W_L/W_R/W_O */
                secp256k1_scalar_negate(&mul.scal, &mul.scal);
                mul.special *= -1;
                w = ret->wv;
                break;
            default:
                secp256k1_bulletproof_circuit_destroy(ctx, ret);
                return NULL;
            }
            c++;
            sscanf(c, "%d %n", &index, &chars_read);
            row = &w[index];

            row->size++;
            entry = &row->entry[row->size - 1];
            entry->idx = i;
            entry->scal = mul;

            c += chars_read;
            j++;
        }
        c++;
        secp256k1_parse_scalar(&ret->c[i], c, &c);
        c++;
    }

    return ret;
}

#endif
