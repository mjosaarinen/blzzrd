// pubpriv.c
// 04-Nov-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "blzzrd.h"
#include "distr.h"
#include "ntt32.h"
#include "sha3.h"
#include "blzrand.h"

#ifdef POLY_BLINDING
#include "blind.h"
#endif

#ifndef THETA_MAX
#define THETA_MAX   64
#endif

// == HELPER FUNCTIONS ==

// absolute maximinum of a vector

static int vecabsmax(const int32_t v[], int n)
{
    int i, max;

    max = 0;
    for (i = 0; i < n; i++) {
        if (v[i] > max)
            max = v[i];
        if (-v[i] > max)
            max = -v[i];
    }

    return max;
}

// scalar product (or norm if t=u)

static int vecscalar(const int32_t t[], const int32_t u[], int n)
{
    int i, sum;

    sum = 0;
    for (i = 0; i < n; i++)
        sum += t[i] * u[i];

    return sum;
}


// oracle step 1; create a hash from a message and the w[] vector

int bliss_cseed(void *cseed, size_t theta,
    const void *mu, size_t mu_len, const int32_t w[], int n)
{
    int i;
    uint8_t t[2];
    sha3_ctx_t sha;

    sha3_init(&sha, theta);             // SHA3 XOF

    t[0] = n >> 8;                      // encode length n
    t[1] = n & 0xFF;
    sha3_update(&sha, t, 2);

    for (i = 0; i < n; i++) {
        t[0] = w[i] >> 8;               // big endian 16-bit
        t[1] = w[i] & 0xFF;
        sha3_update(&sha, t, 2);
    }
    sha3_update(&sha, mu, mu_len);      // message

    sha3_final(cseed, &sha);

    return 0;
}

// random oracle; takes in a  hash of a message and deterministically
// creates kappa indeces

int bliss_c_oracle(int32_t c_idx[], int kappa, int n,
    const void *cseed, size_t theta)
{
    int i, j, idx;
    sha3_ctx_t sha;
    uint8_t buf[2];

    shake256_init(&sha);
    sha3_update(&sha, cseed, theta);
    shake_xof(&sha);

    for (i = 0; i < kappa;) {
        shake_out(&sha, buf, 2);
        idx = ((((uint16_t) buf[0]) << 8) + ((uint16_t) buf[1])) % n;
        for (j = 0; j < i; j++) {
            if (c_idx[j] == idx)
                break;
        }
        if (j == i)
            c_idx[i++] = idx;
    }

    return 0;
}

// == SIGNATURE ==

// GreedySC

static void greedy_sc(const int32_t f[], const int32_t g[], int n,
    const int c_idx[], int kappa, int32_t x[], int32_t y[])
{
    int i, j, k, sgn;

    for (j = 0; j < n; j++) {
        x[j] = 0;
        y[j] = 0;
    }

    for (k = 0; k < kappa; k++) {

        i = c_idx[k];
        sgn = 0;

        for (j = 0; j < n - i; j++) {
            sgn += f[j] * x[i + j] + g[j] * y[i + j];
        }
        for (j = n - i; j < n; j++) {
            sgn -= f[j] * x[i + j - n] + g[j] * y[i + j - n];
        }

        if (sgn > 0) {
            for (j = 0; j < n - i; j++) {
                x[i + j] -= f[j];
                y[i + j] -= g[j];
            }
            for (j = n - i; j < n; j++) {
                x[i + j - n] += f[j];
                y[i + j - n] += g[j];
            }
        } else {
            for (j = 0; j < n - i; j++) {
                x[i + j] += f[j];
                y[i + j] += g[j];
            }
            for (j = n - i; j < n; j++) {
                x[i + j - n] -= f[j];
                y[i + j - n] -= g[j];
            }
        }
    }
}

// Free a signature.

void bliss_sign_free(bliss_signature_t *sign)
{
    const bliss_param_t *p;

    p = &bliss_param[sign->set];
    memset(sign, 0x00, sizeof(bliss_signature_t) +
        2 * p->n  * sizeof(int32_t) + p->theta);
    free(sign);
}

// Create an empty signature with given parameters.

bliss_signature_t *bliss_sign_new(int set)
{
    bliss_signature_t *sign;
    size_t siz;
    const bliss_param_t *p;

    p = &bliss_param[set];
    siz = sizeof(bliss_signature_t) +
        2 * p->n * sizeof(int32_t) + p->theta;
    sign = malloc(siz);

    memset(sign, 0x00, siz);
    sign->set = set;
    sign->t = ((void *) sign) + sizeof(bliss_signature_t);
    sign->z = &sign->t[p->n];
    sign->cseed = (void *) &sign->z[p->n];

    return sign;
}

#include <stdio.h>

// Sign a message.

bliss_signature_t *bliss_sign(const bliss_privkey_t *priv,
    const void *mu, size_t mu_len)
{
    int i, r;
    double d;
    int32_t *t, *u, *v, *z, *x, *y, *c_idx, tmp;
    const bliss_param_t *p;
    bliss_signature_t *sign;
#ifdef POLY_BLINDING
    int32_t cf, cr;
#endif

    p = &bliss_param[priv->set];

    if ((sign = bliss_sign_new(priv->set)) == NULL ||
        (t = calloc(6 * p->n + p->kappa, sizeof(int32_t))) == NULL)
        return NULL;
    u = &t[p->n];
    v = &u[p->n];
    z = &v[p->n];
    x = &z[p->n];
    y = &x[p->n];
    c_idx = &y[p->n];

    for (r = 0; r < 99999; r++) {

        // normal distributed random
        gauss_vector(t, priv->set, p->n);
        gauss_vector(u, priv->set, p->n);

        // v = t * a

        for (i = 0; i < p->n; i++)
            v[i] = t[i];
#ifdef POLY_BLINDING
        r = blzrand64() % p->n;
        tmp = blzrand64() % (p->n - 1) + 1;
        cf = (p->n * p->w[tmp]) % p->q;
        cr = p->r[p->n - tmp];
        blind_shiftc(v, x, p->n, p->q, r, cf);
#endif

        ntt32_xmu(v, p->n, p->q, v, p->w);
        ntt32_fft(v, p->n, p->q, p->w);
        ntt32_xmu(v, p->n, p->q, v, priv->a);
        ntt32_fft(v, p->n, p->q, p->w);
        ntt32_xmu(v, p->n, p->q, v, p->r);
        ntt32_flp(v, p->n, p->q);

#ifdef POLY_BLINDING
        // backshift
        blind_shiftc(v, x, p->n, p->q, -r, cr);
#endif

        // round and drop
        for (i = 0; i < p->n; i++) {

            tmp = v[i]; // old: tmp = ((p->q + 1) * v[i] + u[i]) % (p->q * 2);
            if (tmp & 1)
                tmp += p->q;
            tmp = (tmp + u[i]) % (2 * p->q);
            if (tmp < 0)
                tmp += (2 * p->q);
            v[i] = tmp;
            z[i] = ((tmp + (1 << (p->d - 1))) >> p->d) % p->p;
        }

        // create the c index set
        bliss_cseed(sign->cseed, p->theta, mu, mu_len, z, p->n);
        bliss_c_oracle(c_idx, p->kappa, p->n, sign->cseed, p->theta);

        greedy_sc(priv->f, priv->g, p->n, c_idx, p->kappa, x, y);

        // add or subtract
        if (blzrand64() & 1) {
            for (i = 0; i < p->n; i++) {
                t[i] -= x[i];
                u[i] -= y[i];
            }
        } else {
            for (i = 0; i < p->n; i++) {
                t[i] += x[i];
                u[i] += y[i];
            }
        }

        // rejection math
        d = 1.0 / ((double) p->sig * p->sig);
        d = 1.0 / (p->m  *
            exp(-0.5 * d * (vecscalar(x, x, p->n) +
                vecscalar(y, y, p->n))) *
            cosh(d * (vecscalar(t, x, p->n) + vecscalar(u, y, p->n))));

        // must be HIGHER than the continue probability to redo generation
        if (blzrand() > d)
            continue;

        // generate signature
        for (i = 0; i < p->n; i++) {
            tmp = v[i] - u[i];

            // normalize
            if (tmp < 0)
                tmp += 2 * p->q;
            if (tmp >= 2 * p->q)
                tmp -= 2 * p->q;

            tmp = ((tmp + (1 << (p->d - 1))) >> p->d) % p->p; // uz

            // normalize in range
            tmp = z[i] - tmp;
            if (tmp < -p->p / 2)
                tmp += p->p;
            if (tmp > p->p / 2)
                tmp -= p->p;
            z[i] = tmp;
        }

        // return it
        for (i = 0; i < p->n; i++) {
            sign->t[i] = t[i];
            sign->z[i] = z[i];
        }

        free(t);
        return sign;
    }

    // too many iterations, fail
    bliss_sign_free(sign);
    free(t);

    return NULL;
}

// Verify a signature. Return 0 if signature OK.

int bliss_verify(const bliss_signature_t *sign,
    const void *mu, size_t mu_len, const bliss_pubkey_t *pub)
{
    int i;
    int32_t *v, *my_idx, tmp;
    uint8_t cseed[THETA_MAX];
    const bliss_param_t *p;

    // check that signature and public key use the same parameters set
    if (sign->set != pub->set)
        return -1;

    p = &bliss_param[pub->set];

    // compute norms
    if (vecabsmax(sign->t, p->n) > p->b_inf ||
        (vecabsmax(sign->z, p->n) << p->d) > p->b_inf)
        return -2;

    if (vecscalar(sign->t, sign->t, p->n) +
        (vecscalar(sign->z, sign->z, p->n) << (2 * p->d)) > p->b_l2)
        return -3;

    // check the signature
    v = calloc(p->n + p->kappa, sizeof(int));
    if (v == NULL)
        return -4;
    my_idx = &v[p->n];

    // v = t * a (mod x^n + 1)
    for (i = 0; i < p->n; i++)
        v[i] = sign->t[i];

    ntt32_xmu(v, p->n, p->q, v, p->w);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, pub->a);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, p->r);
    ntt32_flp(v, p->n, p->q);

    // verification magic
    for (i = 0; i < p->n; i++) {
        if (v[i] & 1)       // old: v[i] = ((p->q + 1) * v[i]) % (2 * p->q);
            v[i] += p->q;
    }

    // v = v + C * q
    bliss_c_oracle(my_idx, p->kappa, p->n, sign->cseed, p->theta);
    for (i = 0; i < p->kappa; i++)
        v[my_idx[i]] = (v[my_idx[i]] + p->q) % (2 * p->q);

    // drop bits and add z
    for (i = 0; i < p->n; i++) {
        tmp = (((v[i] + (1 << (p->d - 1))) >> p->d) + sign->z[i]) % p->p;
        if (tmp < 0)
            tmp += p->p;
        v[i] = tmp;
    }

    // run the hash on input
    bliss_cseed(cseed, p->theta, mu, mu_len, v, p->n);
    if (memcmp(cseed, sign->cseed, p->theta) != 0) {
        free(v);
        return -5;
    }

    return 0;
}

