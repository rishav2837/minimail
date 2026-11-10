CC     = gcc
CFLAGS = -Wall -Wextra -O2 -pthread

all: server client

server: server.c common.c common.h
	$(CC) $(CFLAGS) -o $@ server.c common.c -lcrypt

client: client.c common.c common.h
	$(CC) $(CFLAGS) -o $@ client.c common.c

test: all
	python3 tests/test_protocol.py

clean:
	rm -f server client
	rm -rf testdata
