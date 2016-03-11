// gari.h
// 10-Dec-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef GARI_H
#define GARI_H

#include <stddef.h>
#include <stdint.h>
#include "blzzrd.h"

// == gari.c ==

// encode
size_t aric_enc(uint8_t obuf[], size_t omax,    // output buffer (max size)
    const uint32_t ibuf[], size_t ilen,     // input buffer
    size_t bits, const uint64_t dist[]);    // "binary balanced" distribution

// decode
size_t aric_dec(uint32_t obuf[], size_t omax,   // output buffer (max size)
    const uint8_t ibuf[], size_t ilen,      // input buffer
    size_t bits, const uint64_t dist[]);    // "binary balanced" distribution

// build a distribution tree from frequencies
void aric_distfreq_u64(uint64_t dist[], uint64_t freq[], size_t n);
void gauss_freq(long double sig, uint64_t dist[], size_t n);

#endif

