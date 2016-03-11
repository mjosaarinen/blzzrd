// blzrand.c
// 24-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include "blzrand.h"

#define BLZRAND_PRETEND

// double

double blzrand()
{
    return 0x1p-64 * ((double) blzrand64());
}

#ifdef BLZRAND_PRETEND

// This is the deterministic pretend-secure generator used for testing.

#include "sha3.h"

static sha3_ctx_t blzrand_sha;

size_t blzrand_bytes(void *data, size_t len)
{
    shake_out(&blzrand_sha, data, len);
    return len;
}

uint64_t blzrand_bits(int bits)
{
    uint64_t x;

    x = 0;
    shake_out(&blzrand_sha, &x, (bits + 7) >> 3);
    x &= (1lu << bits) - 1;

    return x;
}

uint64_t blzrand64()
{
    uint64_t x;

    shake_out(&blzrand_sha, &x, sizeof(x));
    return x;
}

void blzrand_init()
{
    shake256_init(&blzrand_sha);
    shake_xof(&blzrand_sha);
}

void blzrand_seed(const void *seed, size_t len)
{
    uint8_t mix[64];

    shake_out(&blzrand_sha, &mix, sizeof(mix));

    shake256_init(&blzrand_sha);
    sha3_update(&blzrand_sha, mix, sizeof(mix));
    sha3_update(&blzrand_sha, seed, len);
    shake_xof(&blzrand_sha);
}

void blzrand_free()
{
    blzrand_init();
}

#else

// this is an actually secure random, uses /dev/urandom directly

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int blz_devurandom = -1;

void blzrand_init()
{
    if ((blz_devurandom = open("/dev/urandom", O_RDWR)) == -1) {
        perror("opening random device file");
        exit(-1);
    }
}

void blzrand_free()
{
    if (blz_devurandom != -1) {
        close(blz_devurandom);
    }
}

void blzrand_seed(const void *seed, size_t len)
{
    if (blz_devurandom != -1) {
        if (write(blz_devurandom, seed, len) != len) {
            perror("blzrand_seed()");
        }
    }
}

size_t blzrand_bytes(void *data, size_t len)
{
    return read(blz_devurandom, data, len);
}

uint64_t blzrand64()
{
    uint64_t x;

    if (blzrand_bytes(&x, sizeof(x)) != sizeof(x)) {
        perror("blzrand64()");
    }
    return x;
}

#endif

