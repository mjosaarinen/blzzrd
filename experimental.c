// experimental.c
// 10-Mar-16  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

// Various pieces of code for experiments and testing.
// This is not production code!

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "blzzrd.h"
#include "gari.h"
#include "distr.h"
#include "blind.h"
#include "blzrand.h"
#include "pack.h"

// == EXPERIMENTAL COMPRESSION TEST CODE ======================================

#define XABS(x) ((x) < 0 ? -(x) : (x))

// Number of bits with plain arithmetic code

int ari_tbits(int32_t t[], int set)
{
    uint8_t buf[0x1000];
    uint32_t v[512];
    int i, x;

    // t
    for (i = 0; i < 512; i++) {
        x = t[i] + (1 << PACK_TBITS) / 2;
        if (x < 0 || x >= (1 << PACK_TBITS)) {
            fprintf(stderr, "T overflow x=%d\n", x);
            return 0;
        }
        v[i] = x;
    }
    return 8 * aric_enc(buf, sizeof(buf), v, 512, PACK_TBITS, pack_tdist[set]);
}


int ari_zbits(int32_t z[], int set)
{
    uint8_t buf[0x1000];
    uint32_t v[512];
    int i, x;

    // z
    for (i = 0; i < 512; i++) {
        x = z[i] + (1 << PACK_ZBITS) / 2;
        if (x < 0 || x >= (1 << PACK_ZBITS)) {
            fprintf(stderr, "Z overflow x=%d\n", x);
            return 0;
        }
        v[i] = x;
    }
    return 8 * aric_enc(buf, sizeof(buf), v, 512, PACK_ZBITS, pack_zdist[set]);
}

// Number of bits required to pack a signature using [PoDuGu14] Huffman code.

int b1_huffbits(int32_t t[], int z[])
{

    // Huffman Table, directly lifted from Appendix B of [PoDuGo14]
    const char bliss1huff[4][4][2][2][32] =
        { { { { "100",                  "01000" },
              { "01001",                "0011100" } },
            { { "110",                  "01101" },
              { "01011",                "0011110" } },
            { { "00100",                "0000100" },
              { "0000110",              "000001010" } },
            { { "000000011",            "00000000101" },
              { "000001111011",         "00000111101000" } } },
          { { { "101",                  "01100" },
              { "01010",                "0011101" } },
            { { "111",                  "01110" },
              { "01111",                "0011111" } },
            { { "00101",                "0001001" },
              { "0001010",              "000001110" } },
            { { "000001100",            "00000001000" },
              { "00000001001",          "00000111101010" } } },
          { { { "00011",                "0000111" },
              { "0000101",              "000001001" } },
            { { "00110",                "0001000" },
              { "0001011",              "000001101" } },
            { { "0000001",              "0000011111" },
              { "000000000",            "000001111001" } },
            { { "000001111000",         "00000001011010" },
              { "00000001011000",       "00000111101011010" } } },
          { { { "000001000",            "00000000100" },
              { "00000000110",          "00000001011011" } },
            { { "000001011",            "00000001010" },
              { "00000000111",          "00000111101001" } },
            { { "000000010111",         "00000001011001" },
              { "000001111010111",      "00000111101011011" } },
            { { "00000111101011001",    "000001111010110000" },
              { "0000011110101100011",  "0000011110101100010" } } } };

    int i, bits, a, b, c, d;

    bits = 0;

    // Compression is performed in blocks of 4 values
    for (i = 0; i < 512; i += 2) {

        a = XABS(t[i]);
        b = XABS(t[i + 1]);
        c = XABS(z[i]);
        d = XABS(z[i + 1]);

        if (a >= 0x400 || b >= 0x400 || c >= 2 || d >= 2) {
            printf("OVERFLOW in podugu14_huffbits() %4X %4X %d %d\r",
                a, b, c, d);
            fflush(stdout);
            return 0;
        }

        // dropped low order bits (beta = 8)
        bits += 8 + 8;

        // huffman bits
        bits += strlen(bliss1huff[a >> 8][b >> 8][c][d]);

        // sign bits
        bits += (a == 0 ? 0 : 1) + (b == 0 ? 0 : 1) +
                (c == 0 ? 0 : 1) + (d == 0 ? 0 : 1);

    }

    return bits;
}

// run a long test with many signatures

int b1comp()
{
    char mu[256];
    int i, j, set;
    double cnt[4], cnz[4], tot;
    size_t mulen;

    bliss_privkey_t *priv;
    bliss_signature_t *sign;

    for (i = 0; i < 4; i++) {
        cnt[i] = 0.0;
        cnz[i] = 0.0;
    }

    for (tot = 1000.0;; tot += 1000.0) {

        for (set = 1; set <= 4; set++) {

            // create a private key
            if ((priv = bliss_privkey_gen(set)) == NULL) {
                fprintf(stderr, "i=%d  bliss_privkey_gen()" , i);
                return -1;
            }

            for (j = 0; j < 1000; j++) {

                sprintf(mu, "Iteration %d %d %d\n blah.", i, j, set);
                mulen = strlen(mu);

                if ((sign = bliss_sign(priv, mu, mulen)) == NULL) {
                    fprintf(stderr, "i=%03d j=%d  bliss_sign()" , i, j);
                    return -1;
                }

                cnt[set - 1] += ari_tbits(sign->t, set);
                cnz[set - 1] += ari_zbits(sign->z, set);
                bliss_sign_free(sign);
            }

            printf("| %7.2f %7.2f ", cnt[set - 1] / tot, cnz[set - 1] / tot);
            fflush (stdout);

            bliss_privkey_free(priv);
        }
        printf("| %.0f\n", tot);
    }

    return 0;
}

// == EXPERIMENTAL BLINDING TEST CODE =========================================

extern const int w12289n512[512];
extern const int r12289n512[512];

void blind_test()
{
    int i, j, k;
    int32_t q, a[512], b[512], v[512], w[512];
    double avg, var;

    q = 12289;

    for (i = 0; i < 512; i++) {
        a[i] = blzrand_bits(16) % q;
        b[i] = blzrand_bits(16) % q;
        v[i] = 0;
        w[i] = 0;
    }

    // blinded NTT multiplication
    blind_npm(v, 512, q, a, b, w12289n512, r12289n512);

    // old school multiplication for comparison
    for (i = 0; i < 512; i++) {
        for (j = 0; j < 512; j++) {
            k = i + j;
            if (k < 512) {
                w[k] = (w[k] + a[i] * b[j]) % q;
            } else {
                w[k - 512] = (w[k - 512] + (q - a[i]) * b[j]) % q;
            }
        }
    }

    for (i = 0; i < 512; i++) {
        if (v[i] != w[i]) {
            printf("[%03d]  a=%5d  b=%5d  v=%5d  w=%5d\n",
                i, a[i], b[i], v[i], w[i]);
            printf("ERROR!!\n");
            return;
        }
    }

#ifdef GAUSS_BLINDING
    printf("Gaussian Blinding on:");
#else
    printf("Gaussian Blinding off:");
#endif

    for (i = 1; i <= 4; i++) {
        fflush(stdout);
        var = 0.0;
        avg = 0.0;
        for (j = 0; j < 1000; j++) {
            gauss_vector(a, i, 512);
            for (k = 0; k < 512; k++) {
                avg += a[i];
                var += a[i] * a[i];
            }
        }
        printf(" %.1f/%.1f", avg / 512000.0, sqrt(var / 512000.0));
    }
    printf("\n");
}

// == EXPERIMENTAL SPEED TEST CODE ============================================

#if 0
static __inline__ uint64_t get_rdtsc(void)
{
    uint32_t a, d;
    __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));

    return ((uint64_t) a) + (((uint64_t) d) << 32);
}
#endif

void sample_speed()
{
    int set, i, l, rbyt;
    clock_t t1, t2;
    int32_t v[512];
    uint8_t rnd[10240];
    uint64_t n;

    blzrand_bytes(rnd, sizeof(rnd));

    for (set = 1; set <= 4; set++) {

        // Arithmetic Coder Sampler

        rbyt = 0;
        t1 = clock();
        n = 0;

        for (;;) {
            t2 = clock() - t1;
            if (t2 > 5 * CLOCKS_PER_SEC)
                break;

            for (i = 0; i < 100; i++) {
                l = aric_dec((uint32_t *) v, 512, rnd, sizeof(rnd),
                    PACK_TBITS, pack_tdist[set]);
                rbyt += l;
                blzrand_bytes(rnd, l);
                n += 512;
            }
        }

        printf("set=%d\t%.3f samples / sec   %.6f bits / sample\n",
            set, ((double) n) /
                (((double) t2) / ((double) CLOCKS_PER_SEC)),
            ((double) 8 * rbyt) / n);

        // The plain sampler

        t1 = clock();
        n = 0;

        for (;;) {
            t2 = clock() - t1;
            if (t2 > 5 * CLOCKS_PER_SEC)
                break;

            for (i = 0; i < 100; i++) {
                gauss_vector(v, set, 512);
                n += 512;
            }
        }
        printf("CDF\t%.3f samples / sec\n",
            ((double) n) / (((double) t2) / ((double) CLOCKS_PER_SEC)));

    }
}

