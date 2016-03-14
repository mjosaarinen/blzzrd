BLZZRD
======

11-Mar-16  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

Centre for Secure Information Technologies (CSIT)
ECIT, Queen's University Belfast, UK

# Introduction

This is an educational implementation of the **BLZZRD** 
Ring-LWE signature scheme, described in more detail
in *Markku-Juhani O. Saarinen*: "Arithmetic Coding and Blinding for Lattice Cryptography", which is
available as [IACR ePrint 2016/276](https://eprint.iacr.org/2016/276).

BLZZRD is an evolutionary version of the
BLISS signature scheme originally published in Crypto '13:
*Léo Ducas, Alain Durmus, Tancrède Lepoint, Vadim Lyubashevsky*:
"Lattice Signatures and Bimodal Gaussians"
Extended version of that paper is available as 
[IACR ePrint 2013/383](https://eprint.iacr.org/2013/383). 
More specifically, this code also implements
the BLISS-B optimizations by Léo Ducas, described in
[IACR ePrint 2014/874](https://eprint.iacr.org/2014/874).

However, this is only educational code. Some shortcuts have been taken and
therefore this should not be used in production in its current form.

The main experimental modifications are:

* Modified random oracle for Post-Quantum Security
* Arithmetic Coding for Signature Compression and Decompression
* Experimental blinding side-channel protections for polynomial ring
	arithmetic and Gaussian sampling.

# Compiling and running

Assuming that you get the tarball open:
```

d$ make
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c main.c -o main.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c ntt32.c -o ntt32.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c distr.c -o distr.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c blzrand.c -o blzrand.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c sha3.c -o sha3.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c param.c -o param.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c keygen.c -o keygen.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c pubpriv.c -o pubpriv.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c pack.c -o pack.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c gari.c -o gari.o
gcc -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING  -c blind.c -o blind.o
gcc  -o xtest main.o ntt32.o distr.o blzrand.o sha3.o param.o keygen.o pubpriv.o pack.o gari.o blind.o  -lm

$ ./xtest 
CLASS 1 x 1000   Signature avg. 5858.5 bits
CLASS 2 x 1000   Signature avg. 5184.5 bits
CLASS 3 x 1000   Signature avg. 6392.4 bits
CLASS 4 x 1000   Signature avg. 6881.4 bits
```
That last line indicates success.

Have fun.

Cheers, -Markku

**ABSOLUTELY NO WARRANTY WHATSOEVER**

