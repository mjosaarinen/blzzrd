// blzzrd.h
// 18-Jun-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef BLZZRD_H
#define BLZZRD_H

#include <stdint.h>
#include <stddef.h>

// parameter set

typedef struct {
    int32_t q;                          // field modulus
    int32_t n;                          // ring size (x^n+1)
    int32_t d;                          // bit drop shift
    int32_t p;                          // magic modulus
    int32_t kappa;                      // index vector size
    size_t  theta;                      // cseed in bytes
    int32_t b_inf;                      // infinite norm
    int32_t b_l2;                       // L2 norm
    int32_t nz1;                        // nonzero +-1
    int32_t nz2;                        // nonzero +-2
    int32_t pmax;                       // derived from nt, nz2, n, kappa
    long double sig;                    // standard deviation
    long double m;                      // repetition rate
    const int32_t *w;                   // n roots of unity (mod q)
    const int32_t *r;                   // w[i]/n (mod q)
} bliss_param_t;

// parameter set constants
extern const bliss_param_t bliss_param[];   // standard types

// signature

typedef struct {
    int32_t set;                        // parameter set
    int32_t *t;                         // signature t
    int32_t *z;                         // signature z
    uint8_t *cseed;                     // seed for c_idx
} bliss_signature_t;

// private key

typedef struct {
    int32_t set;                        // parameter set
    int32_t *f;                         // sparse polynomial f
    int32_t *g;                         // sparse polynomial g
    int32_t *a;                         // NTT of f/g
} bliss_privkey_t;

// public key

typedef struct {
    int32_t set;                        // parameter set
    int32_t *a;                         // NTT of f/g
} bliss_pubkey_t;


// == PRIVKEY ==

// Free a private key.
void bliss_privkey_free(bliss_privkey_t *priv);

// Create an empty private key.
bliss_privkey_t *bliss_privkey_new(int set);

// Key generation. Return NULL on failure.
bliss_privkey_t *bliss_privkey_gen(int set);


// == PUBKEY ==

// Free a public key.
void bliss_pubkey_free(bliss_pubkey_t *pub);

// Create an empty public key.
bliss_pubkey_t *bliss_pubkey_new(int set);

// Derive a public key from a private key
bliss_pubkey_t *bliss_pubkey_frompriv(const bliss_privkey_t *priv);


// == SIGNATURE ==

// Free a signature.
void bliss_sign_free(bliss_signature_t *sign);

// Create an empty signature with given parameters.
bliss_signature_t *bliss_sign_new(int set);

// Sign a message.
bliss_signature_t *bliss_sign(const bliss_privkey_t *priv,
    const void *mu, size_t mu_len);

// Verify a signature. Return 0 if signature OK.
int bliss_verify(const bliss_signature_t *sign,
    const void *mu, size_t mu_len, const bliss_pubkey_t *pub);

#endif

