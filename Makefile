src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
OPENSSL_PATH = /usr/local/opt/openssl@3
CFLAGS = -I$(OPENSSL_PATH)/include
LDFLAGS = -L$(OPENSSL_PATH)/lib -lssl -lcrypto

a.out: $(obj)
    $(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
    $(CC) -c $< $(CFLAGS)