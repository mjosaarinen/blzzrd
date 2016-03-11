// distr.c
// 22-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "distr.h"
#include "blzrand.h"
#include "blzzrd.h"
#include "sha3.h"

// global tables for binary search
uint64_t gauss_cdf[5][GAUSS_CDF_SIZE];

// Build CDF's for given sigma

void gauss_gen_cdf(uint64_t cdf[], long double sigma, int n)
{
    int i;
    long double s, d, e;

#ifdef GAUSS_BLINDING
    sigma *= 0.7071067811865475244008L; // sqrt(1/2)
#endif

    // 2/sqrt(2*Pi)  * (1 << 64) / sigma
    d = 0.7978845608028653558798L * (0x1p64) / sigma;

    e = -0.5L / (sigma * sigma);
    s = 0.5L * d;
    cdf[0] = 0;
    for (i = 1; i < n - 1; i++) {
        cdf[i] = s;
        if (cdf[i] == 0)        // overflow
            break;
        s += d * expl(e * ((long double) (i*i)));
    }
    for (; i < n; i++) {
        cdf[i] = 0xFFFFFFFFFFFFFFFF;
    }
}

void gauss_init()
{
    int i;
    for (i = 0; i <= 4; i++)
        gauss_gen_cdf(gauss_cdf[i], bliss_param[i].sig, GAUSS_CDF_SIZE);
}

// binary search on a list

static int binsearch(uint64_t x, const uint64_t l[], int n, int st)
{
    int a, b;

    a = 0;
    while (st > 0) {
        b = a + st;
        if (b < n && x >= l[b])
            a = b;
        st >>= 1;
    }
    return a;
}

// sample from the distribution with binary search

int32_t gauss_sample(int set)
{
    int a;
    uint64_t x;

    x = blzrand64();
    a = binsearch(x, gauss_cdf[set], GAUSS_CDF_SIZE, GAUSS_CDF_STEP);

    return x & 1 ? a : -a;
}

// random permutation of a vector

static void vec_permute(int32_t v[], size_t n)
{
    int32_t t;
    size_t i, j;
    uint16_t r;

    for (i = 0; i < n; i++) {
        blzrand_bytes(&r, sizeof(r));   // random position
        j = r % n;

        t = v[i];                       // swap entries
        v[i] = v[j];
        v[j] = t;
    }
}

// create a vector of samples

void gauss_vector(int32_t v[], int set, size_t n)
{
    size_t i;

#ifdef GAUSS_BLINDING

    // Sampler with Gaussian blinding
    for (i = 0; i < n; i++)
        v[i] = gauss_sample(set);
    vec_permute(v, n);
    for (i = 0; i < n; i++)
        v[i] -= gauss_sample(set);
    vec_permute(v, n);

#else

    // normal sampler
    for (i = 0; i < n; i++)
        v[i] = gauss_sample(set);

#endif

}


