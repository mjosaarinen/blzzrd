
// pack.h
// 10-Mar-16  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef PACK_H
#define PACK_H

#include "distr.h"

#ifndef PACK_ZBITS
#define PACK_ZBITS 4
#endif

#ifndef PACK_TBITS
#define PACK_TBITS (GAUSS_BITS + 1)
#endif

extern uint64_t pack_tdist[5][1 << PACK_TBITS];
extern uint64_t pack_zdist[5][1 << PACK_ZBITS];

// intialize
void bliss_pack_init();

// pack a signatures
int bliss_pack_sign(uint8_t *dst, size_t maxl, const bliss_signature_t *sign);

// unpack a signatre
bliss_signature_t *bliss_unpack_sign(const uint8_t *msg, size_t len);

#endif
