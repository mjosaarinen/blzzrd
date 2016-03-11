# Makefile
# 09-Jun-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

BIN	= xtest
OBJS	= main.o ntt32.o distr.o blzrand.o sha3.o \
	param.o keygen.o pubpriv.o pack.o gari.o blind.o # experimental.o
DIST	= blzzrd

CC	= gcc
CFLAGS	= -Wall -Ofast -march=native -DPOLY_BLINDING -DGAUSS_BLINDING
LIBS	= -lm
LDFLAGS	=
INCS	=

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

clean:
	rm -rf $(DIST)-*.txz $(OBJS) $(BIN) *~

dist:	clean
	cd ..; \
	tar cfvJ $(DIST)/$(DIST)-`date -u "+%Y%m%d%H%M00"`.txz $(DIST)/*
