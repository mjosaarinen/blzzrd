// pack.c
// 14-Dec-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdio.h>
#include "blzzrd.h"
#include "distr.h"
#include "gari.h"

#define PACK_ZBITS 4
#define PACK_TBITS (GAUSS_BITS + 1)

uint64_t pack_tdist[5][1 << PACK_TBITS];
uint64_t pack_zdist[5][1 << PACK_ZBITS];

// intialize distributions
void bliss_pack_init()
{
    int i;

    // experimentally determined // 0.4792
    const long double zsig[5] = { 0.5, 0.4792, 0.4352, 0.6460, 1.136 };

    for (i = 0; i <= 4; i++) {
        gauss_freq(bliss_param[i].sig, pack_tdist[i], 1 << PACK_TBITS);
        gauss_freq(zsig[i], pack_zdist[i], 1 << PACK_ZBITS);
    }
}

// pack a signature

int bliss_pack_sign(uint8_t *dst, size_t maxl, const bliss_signature_t *sign)
{
    int i, x, len;
    const bliss_param_t *p;
    uint32_t v[0x200];

    p = &bliss_param[sign->set];

    // sets 1..4 supported
    if (sign->set < 1 || sign->set > 4 || maxl < (6 + p->theta))
        return 0;
    len = 5;                            // skip length fields
    dst[0] = sign->set;                 // store set

    // store cseed
    for (i = 0; i < p->theta; i++)
        dst[len++] = sign->cseed[i];

    // compress T values
    for (i = 0; i < p->n; i++) {
        x = sign->t[i] + (1 << PACK_TBITS) / 2;
        if (x < 0 || x >= (1 << PACK_TBITS)) {
            fprintf(stderr, "T overflow in bliss_pack_sign() x=%d\n", x);
            return 0;
        }
        v[i] = x;
    }
    len += aric_enc(&dst[len], maxl - len, v, p->n,
        PACK_TBITS, pack_tdist[sign->set]);
    if (len >= maxl)
        return 0;

    dst[1] = len >> 8;                  // Z offset
    dst[2] = len & 0xFF;

    // compress Z values
    for (i = 0; i < p->n; i++) {
        x = sign->z[i] + (1 << PACK_ZBITS) / 2;
        if (x < 0 || x >=  (1 << PACK_ZBITS)) {
            fprintf(stderr, "Z overflow in bliss_pack_sign() x=%d\n", x);
            return 0;
        }
        v[i] = x;
    }
    len += aric_enc(&dst[len], maxl - len, v, p->n,
        PACK_ZBITS, pack_zdist[sign->set]);
    if (len >= maxl)
        return 0;
    dst[3] = len >> 8;                  // total length
    dst[4] = len & 0xFF;

    return len;
}

// unpack a signature

bliss_signature_t *bliss_unpack_sign(const uint8_t *msg, size_t len)
{
    int set, ptr, i, p1, p2;
    const bliss_param_t *p;
    bliss_signature_t *sign;
    uint32_t v[0x200];

    if (len < 6)
        return NULL;

    set = msg[0];
    if (set < 1 || set > 4)
        return NULL;
    p = &bliss_param[set];

    p1 = (((size_t) msg[1]) << 8) + ((size_t) msg[2]);
    p2 = (((size_t) msg[3]) << 8) + ((size_t) msg[4]);
    if (p2 > len || p1 > p2 || (5 + p->theta) >= len)
        return NULL;

    // cseed
    sign = bliss_sign_new(set);
    for (i = 0; i < p->theta; i++)
        sign->cseed[i] = msg[i + 5];

    // unpack T
    ptr = 5 + p->theta;
    ptr += aric_dec(v, p->n, &msg[ptr], p1 - ptr,
        PACK_TBITS, pack_tdist[sign->set]);
    if (ptr > p1)
        goto unpack_fail;
    for (i = 0; i < p->n; i++)
        sign->t[i] = ((int32_t) v[i]) - (1 << PACK_TBITS) / 2;

    // unpack Z
    ptr = p1;
    ptr += aric_dec(v, p->n, &msg[ptr], p2 - ptr,
        PACK_ZBITS, pack_zdist[sign->set]);
    if (ptr > p2)
        goto unpack_fail;

    for (i = 0; i < p->n; i++)
        sign->z[i] = ((int32_t) v[i]) - (1 << PACK_ZBITS) / 2;

    return sign;

unpack_fail:
    bliss_sign_free(sign);
    return NULL;

}

