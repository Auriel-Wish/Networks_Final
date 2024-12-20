src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc -fsanitize=address

OPENSSL_PREFIX = $(shell arch -arm64 brew --prefix openssl@3)
CFLAGS = -Wall -Wextra -g -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lz

a.out: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out *.*.crt *.*.key out.txt