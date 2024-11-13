
# src = $(wildcard *.c)
# obj = $(src:.c=.o)
# CC = gcc
# LDFLAGS = -lnsl -lssl -lcrypto

# #CFLAGS (not in their makefile)
# CFLAGS = -Wall

# a.out: $(obj)
# 	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# .PHONY: clean
# clean:
# 	rm -f $(obj) a.out *.txt


src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
OPENSSL_PREFIX = $(shell brew --prefix openssl)

CFLAGS = -Wall -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

a.out: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out *.txt