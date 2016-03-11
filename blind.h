// blind.h
// 26-Feb-16  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef BLIND_H
#define BLIND_H

#include <stdint.h>
#include <stddef.h>

// Blinding shift by (signed) st steps, constant c. t[i] is a temp vector.
void blind_shiftc(int32_t v[], int32_t t[], size_t n, int32_t q,
    int st, int32_t c);

// Blinded negacyclic polynomial multiplication  v = n * a * b (mod 2^n + 1).
int blind_npm(int32_t v[], size_t n, int32_t q, const int32_t a[],
    const int32_t b[], const int32_t w[], const int32_t r[]);

#endif

