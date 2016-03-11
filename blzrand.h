// blzrand.h
// 24-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>
// This is a pretend-secure random number generator

#ifndef BLZRAND_H
#define BLZRAND_H

#include <stdint.h>
#include <stddef.h>

void blzrand_init();                                // initialize
void blzrand_free();                                // free the resources
double blzrand();                                   // 0..1 float
uint64_t blzrand64();                               // 64-bit
size_t blzrand_bytes(void *data, size_t len);       // bytes
uint64_t blzrand_bits(int bits);                    // get bits
void blzrand_seed(const void *seed, size_t len);    // add randomness

#endif

