
src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
# LDFLAGS = -lnsl -lssl -lcrypto
LDFLAGS = -lssl -lcrypto

#CFLAGS (not in their makefile)
CFLAGS = -Wall

a.out: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out *.txt
