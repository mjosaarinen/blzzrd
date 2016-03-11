// distr.h
// 22-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef DISTR_H
#define DISTR_H

#include <stdint.h>

// global tables for binary search
#ifndef GAUSS_BITS
#define GAUSS_BITS 12
#endif

#define GAUSS_CDF_SIZE (1 << GAUSS_BITS)
#define GAUSS_CDF_STEP (1 << (GAUSS_BITS - 1))

// initialize parameter sets 0..4
void gauss_init();

// sample from the given set
int32_t gauss_sample(int set);

// create a gaussian vector
void gauss_vector(int32_t v[], int set, size_t n);

#endif
