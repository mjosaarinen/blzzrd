// gari.c
// 03-Dec-15  Markku-Juhani O. Saarinen <mjos@iki.fi>
// Arithmetic coding / decoding routines.

#include "gari.h"
#include <math.h>

// high part of x*y: these two versions probably create the same code,

#if 1
// "portable" gcc version
static uint64_t mul64hi(uint64_t x, uint64_t y)
{
    return (uint64_t) ((((__uint128_t) x) * ((__uint128_t) y)) >> 64);
}

#else

// gcc inline x86-64 alternative
static uint64_t mul64hi(uint64_t x, uint64_t y)
{
    uint64_t r;
    __asm__("mulq %2"
        : "=d" (r)
        : "a" (x), "r" (y));
    return r;
}
#endif


// encode

size_t aric_enc(uint8_t obuf[], size_t omax,    // output buffer (max size)
    const uint32_t ibuf[], size_t ilen,     // input buffer
    size_t bits, const uint64_t dist[])     // "binary balanced" distribution
{
    int i, iptr, icnt, optr, ocnt;
    uint32_t obyt;                          // output byte; can handle carry
    uint32_t iwrd;                          // input word
    uint64_t b, l, c;                       // range variables


    b = 0x0000000000000000;                 // lower bound
    l = 0xFFFFFFFFFFFFFFFF;                 // range

    obyt = 0x00;                            // (partial) output byte
    ocnt = 0;                               // bit count 0..7
    optr = 0;                               // byte pointer 0..omax-1

    for (iptr = 0; iptr < ilen; iptr++) {

        iwrd = ibuf[iptr];
        for (icnt = bits - 1; icnt >= 0; icnt--) {

            // midpoint split
            c = dist[(iwrd & (0xFFFFFFFE << icnt)) | (1 << icnt)];
            c = mul64hi(l, c);              // scale to range

            if (((iwrd >> icnt) & 1) == 0) {
                l = c;                      // 0 bit; lower part
            } else {
                b += c;                     // 1 bit; higher part
                if (b < c) {                // overflow ?
                    obyt++;                 // carry
                }
                l -= c;                     // flip range to upper half
            }

            // normalize and output bits
            while (l < 0x8000000000000000) {
                obyt <<= 1;
                obyt += (b >> 63) & 1;
                ocnt++;
                if (ocnt >= 8) {            // full byte ?
                    obuf[optr] = obyt & 0xFF;

                    // carry propagation
                    for (i = optr - 1; obyt >= 0x100 && i >= 0; i--) {
                        obyt >>= 8;
                        obyt += (uint32_t) obuf[i];
                        obuf[i] = obyt & 0xFF;
                    }
                    optr++;
                    if (optr >= omax)       // output buffer overflow
                        return omax;

                    ocnt = 0;
                    obyt = 0x00;
                }

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
        }
    }

    while (ocnt < 8) {                      // flush output byte
        obyt = (obyt << 1) ^ (b >> 63);
        b <<= 1;
        ocnt++;
    }
    obuf[optr] = obyt & 0xFF;               // final carry
    for (i = optr - 1; obyt >= 0x100 && i >= 0; i--) {
        obyt >>= 8;
        obyt += (uint32_t) obuf[i];
        obuf[i] = obyt & 0xFF;
    }
    optr++;                                 // zero b
    while (b != 0) {
        obuf[optr++] = b >> 56;
        b <<= 8;
    }

    return optr;
}

// decode

size_t aric_dec(uint32_t obuf[], size_t omax,   // output buffer (max size)
    const uint8_t ibuf[], size_t ilen,      // input buffer
    size_t bits, const uint64_t dist[])     // "binary balanced" distribution
{
    int iptr, icnt, optr, ocnt;
    uint64_t b, l, c, v;
    uint8_t ibyt;
    uint32_t owrd;

    b = 0x0000000000000000;                 // lower bound
    l = 0xFFFFFFFFFFFFFFFF;                 // range

    v = 0;                                  // read 64 bits
    for (iptr = 0; iptr < 8; iptr++) {
        v <<= 8;
        v += (uint64_t) ibuf[iptr];
    }
    ibyt = 0x00;
    icnt = 0;

    for (optr = 0; optr < omax; optr++) {

        owrd = 0;
        for (ocnt = bits - 1; ocnt >= 0; ocnt--) {

            // midpoint split
            c = dist[(owrd & (0xFFFFFFFE << ocnt)) | (1 << ocnt)];
            c = mul64hi(l, c);              // scale to range

            if (v - b < c) {                // compare
                l = c;                      // 0 bit; lower part
            } else {
                b += c;                     // 1 bit; higher part
                l -= c;                     // flip range to upper half
                owrd |= 1 << ocnt;          // set the bit
            }

            while (l < 0x8000000000000000) {

                icnt--;                     // fetch a new bit
                if (icnt < 0) {
                    if (iptr >= ilen) {     // insert zeros is over buffer
                        ibyt = 0x00;
                    } else {
                        ibyt = ibuf[iptr++];
                    }
                    icnt = 7;
                }
                v <<= 1;                    // add bit to v
                v += (ibyt >> icnt) & 1;

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
        }
        obuf[optr] = owrd;                  // have full output byte
    }

    return iptr;
}

// build a distribution tree for gaussian distribution

void gauss_freq(long double sig, uint64_t dist[], size_t n)
{
    int i, j, k, x;
    long double a, b, sig2i;
    uint64_t r;

    sig2i = -0.5 / (sig * sig);

    for (i = 0; i < n; i++)
        dist[i] = 0;

    for (i = n >> 1; i >= 1; i >>= 1) {
        for (j = 0; j < n; j += i + i) {

            a = 0.0;
            b = 0.0;

            for (k = 0; k < i; k++) {
                // x is normalized
                x = (j + k) - ((int) (n >> 1));
                a += expl(sig2i * ((long double) (x * x)));
                x = (i + j + k) - ((int) (n >> 1));
                b += expl(sig2i * ((long double) (x * x)));
            }
            a = a / (a + b);
            r = (uint64_t) (0x1p64 * a);
            if (r < 4) {
                if (a > 0.5)
                    r = -4;
                else
                    r = 4;
            }
            if (r > -4)
                r = -4;

            dist[j + i] = r;
        }
    }
}

// fractional part of x/y (with x < y), scaled to 64 bits

static uint64_t div64fr(uint64_t x, uint64_t y)
{
    return (uint64_t) (((((__uint128_t) x) << 64) - 1) / ((__uint128_t) y));
}

// build a distribution tree from frequencies

void aric_distfreq_u64(uint64_t dist[], uint64_t freq[], size_t n)
{
    size_t i, j, k;
    uint64_t a, b, r;

    for (i = 0; i < n; i++)
        dist[i] = 0;

    for (i = n >> 1; i >= 1; i >>= 1) {
        for (j = 0; j < n; j += i + i) {

            a = 1;
            b = 1;

            for (k = 0; k < i; k++) {
                a += freq[j + k];
                b += freq[i + j + k];
            }
            r = div64fr(a, a + b);
            if (r < 4)
                r = 4;
            if (r > -4)
                r = -4;
            dist[j + i] = r;
        }
    }
}

