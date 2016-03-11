// blind.c
// 25-Feb-16  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

// Testbed for polynomial blinding

#include <stdlib.h>
#include "ntt32.h"
#include "blzrand.h"
#include "blind.h"

#include <stdio.h>

// Blinding shift by (signed) st steps, constant c. t[i] is a temp vector.

void blind_shiftc(int32_t v[], int32_t t[], size_t n, int32_t q,
    int st, int32_t c)
{
    int i;

    // shifting
    if (st >= 0) {
        st %= 2 * n;
        if (st >= n) {
            c = q - c;
            st -= n;
        }

        for (i = 0; i < n - st; i++)
            t[i] = v[i + st];
        for (; i < n; i++)
            t[i] = q - v[i + st - n];
    } else {
        st = (-st) % (2 * n);
        if (st >= n) {
            c = q - c;
            st -= n;
        }

        for (i = 0; i < st; i++)
            t[i] = q - v[i - st + n];
        for (; i < n; i++)
            t[i] = v[i - st];
    }

    // constant blinding
    for (i = 0; i < n; i++)
        v[i] = (c * t[i]) % q;
}

// Blinded negacyclic polynomial multiplication  v = n * a * b (mod 2^n + 1).

int blind_npm(int32_t v[], size_t n, int32_t q,
    const int32_t a[], const int32_t b[], const int32_t w[], const int32_t r[])
{
    size_t i;
    int32_t *t, *u, *z;
    int ra, rb;
    int32_t ca, da, cb, db;

    t = calloc(3 * n, sizeof(int32_t));
    if (t == NULL)
        return -1;
    u = &t[n];
    z = &u[n];

    // local variables
    for (i = 0; i < n; i++) {
        t[i] = a[i];
        u[i] = b[i];
    }

    // blinding
    ra = blzrand64() & 0xFFFF;
    ca = (blzrand64() % (q - 1)) + 1;
    da = ntt32_pwr(ca, q - 2, q);
    blind_shiftc(t, z, n, q, ra, ca);

    rb = blzrand64() & 0xFFFF;
    cb = (blzrand64() % (q - 1)) + 1;
    db = ntt32_pwr(cb, q - 2, q);
    blind_shiftc(u, z, n, q, rb, cb);

    // negacyclic product
    ntt32_xmu(t, n, q, t, w);
    ntt32_fft(t, n, q, w);
    ntt32_xmu(u, n, q, u, w);
    ntt32_fft(u, n, q, w);
    ntt32_xmu(v, n, q, t, u);
    ntt32_fft(v, n, q, w);
    ntt32_xmu(v, n, q, v, r);
    ntt32_flp(v, n, q);

    blind_shiftc(v, z, n, q, - ra - rb, (da * db) % q);

    free(t);

    return 0;
}

