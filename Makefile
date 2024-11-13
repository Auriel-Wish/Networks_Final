
src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
# LDFLAGS = -lnsl -lssl -lcrypto
LDFLAGS = -lssl -lcrypto
OPENSSL_PREFIX = $(shell brew --prefix openssl)


#CFLAGS (not in their makefile)
CFLAGS = -Wall -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

a.out: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out *.txt
