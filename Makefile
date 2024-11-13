
src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc

OPENSSL_PREFIX = $(shell arch -arm64 brew --prefix openssl@3)
# OPENSSL_PREFIX = /usr/local/Cellar/openssl@3/3.4.0
CFLAGS = -Wall -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

a.out: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out *.txt