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
    int i, j, set, len;
    bliss_privkey_t *priv = NULL;
    bliss_pubkey_t *pub = NULL;
    bliss_signature_t *sign = NULL;
    double tot;

    clock_t tim, tim_keygen, tim_sign, tim_pack, tim_unpack, tim_verify;

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

        tim_keygen = 0;
        tim_sign = 0;
        tim_pack = 0;
        tim_unpack = 0;
        tim_verify = 0;


        for (i = 0; i < 100; i++) {

            printf("CLASS %d\t%3d %%\r", set, i);
            fflush(stdout);

            // create a private key

            tim = clock();
            for (j = 0; j < 100; j++) {
    
                if (priv != NULL) {
                    bliss_privkey_free(priv);
                    priv = NULL;
                }

                if ((priv = bliss_privkey_gen(set)) == NULL) {
                    fprintf(stderr, "%04d/%d  bliss_privkey_gen()" , i, set);
                    exit(1);
                }
            }
            tim_keygen += clock() - tim;

            // derive public key from private key
            if ((pub = bliss_pubkey_frompriv(priv)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_pubkey_frompriv()" , i, set);
                exit(1);
            }

            // sign

            tim = clock();
            for (j = 0; j < 100; j++) {

                if (sign != NULL) {
                    bliss_sign_free(sign);
                    sign = NULL;
                }
    
                if ((sign = bliss_sign(priv, msg, msglen)) == NULL) {
                    fprintf(stderr, "%04d/%d  bliss_sign()" , i, set);
                    exit(1);
                }
            }
            tim_sign += clock() - tim;

            // pack signature

            tim = clock();
            for (j = 0; j < 100; j++) {
                len = bliss_pack_sign(packsign, sizeof(packsign), sign);
            }
            tim_pack += clock() - tim;

            tot += len;                 // total
            bliss_sign_free(sign);      // free signature
            sign = NULL;

            // unpack

            tim = clock();
            for (j = 0; j < 100; j++) {

                if (sign != NULL) {
                    bliss_sign_free(sign);
                    sign = NULL;
                }

                sign = bliss_unpack_sign(packsign, len);
                if (sign == NULL) {
                    fprintf(stderr, 
                        "%04d/%d bliss_unpack_sign() FAIL.\n", i, set);
                    exit(1);
                }
            }
            tim_unpack += clock() - tim;

            // verify

            tim = clock();
            for (j = 0; j < 100; j++) {
                if (bliss_verify(sign, msg, msglen, pub)) {
                    fprintf(stderr, "%04d/%d bliss_verify() FAIL.\n", i, set);
                    exit(1);
                } else {
        //          printf("%d Signature OK.\n", i);
                }
            }
            tim_verify += clock() - tim;

            if (sign != NULL) {
                bliss_sign_free(sign);
                sign = NULL;
            }    
            if (pub != NULL) {
                bliss_pubkey_free(pub);
                pub = NULL;
            }
            if (priv != NULL) {
                bliss_privkey_free(priv);
                priv = NULL;
            }        
        }
        printf("CLASS %d x %d   Signature avg. %.1f bits\n",
            set, i, 8.0 * tot / ((double) i));
        printf("CLASS %d\tkeygen:\t%fms\n", set, 
                    ((double) tim_keygen) / ((double) 10 * CLOCKS_PER_SEC));
        printf("CLASS %d\tsign:\t%fms\n", set, 
                    ((double) tim_sign) / ((double) 10 * CLOCKS_PER_SEC));
        printf("CLASS %d\tverify: %fms\n", set, 
                    ((double) tim_verify) / ((double) 10 * CLOCKS_PER_SEC));
        printf("CLASS %d\tpack:\t%fms\n", set, 
                    ((double) tim_pack) / ((double) 10 * CLOCKS_PER_SEC));
        printf("CLASS %d\tunpack: %fms\n", set, 
                    ((double) tim_unpack) / ((double) 10 * CLOCKS_PER_SEC));
    }

    blzrand_free();

    return 0;
}

