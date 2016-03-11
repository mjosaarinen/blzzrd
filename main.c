// main.c
// 06-May-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blzzrd.h"
#include "sha3.h"
#include "ntt32.h"
#include "distr.h"
#include "pack.h"
#include "blzrand.h"

int main(int argc, char **argv)
{
    int i, set, len;
    bliss_privkey_t *priv;
    bliss_pubkey_t *pub;
    bliss_signature_t *sign;
    double tot;

    // data to be signed
    char msg[] = "Lorem Ipsuxm.";
    size_t msglen;
    msglen = strlen(msg);
    uint8_t packsign[0x1000];

    // init stuff
    blzrand_init();
    gauss_init();
    bliss_pack_init();

    // loop over parameter sets
    for (set = 1; set <= 4; set++) {

        tot = 0.0;

        for (i = 0; i < 1000; i++) {

            // create a private key
            if ((priv = bliss_privkey_gen(set)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_privkey_gen()" , i, set);
                exit(1);
            }

            // derive public key from private key
            if ((pub = bliss_pubkey_frompriv(priv)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_pubkey_frompriv()" , i, set);
                exit(1);
            }

            // sign
            if ((sign = bliss_sign(priv, msg, msglen)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_sign()" , i, set);
                exit(1);
            }

            // pack signature
            len = bliss_pack_sign(packsign, sizeof(packsign), sign);
            tot += len;                 // total
            bliss_sign_free(sign);      // free signature

            // unpack
            sign = bliss_unpack_sign(packsign, len);
            if (sign == NULL) {
                fprintf(stderr, "%04d/%d bliss_unpack_sign() FAIL.\n", i, set);
                exit(1);
            }

            // verify
            if (bliss_verify(sign, msg, msglen, pub)) {
                fprintf(stderr, "%04d/%d bliss_verify() FAIL.\n", i, set);
                exit(1);
            } else {
    //          printf("%d Signature OK.\n", i);
            }

            bliss_sign_free(sign);
            bliss_pubkey_free(pub);
            bliss_privkey_free(priv);
        }
        printf("CLASS %d x %d   Signature avg. %.1f bits\n",
            set, i, 8.0 * tot / ((double) i));
    }

    blzrand_free();

    return 0;
}

