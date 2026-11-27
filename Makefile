CC = gcc
CFLAGS = -std=gnu23 -fdiagnostics-color=always -g -Wall -Wextra
QUIC_LIBS = -lngtcp2 -lngtcp2_crypto_wolfssl -lwolfssl
TCP_LIBS = -lwolfssl

.PHONY: all quic tcp clean

all: quic tcp

quic: quic/quic_client.out quic/quic_server.out

tcp: tcp/tcp_client.out tcp/tcp_server.out

quic/%.out: quic/%.c quic/quic.h
	$(CC) $(CFLAGS) $< -o $@ $(QUIC_LIBS)

tcp/%.out: tcp/%.c
	$(CC) $(CFLAGS) $< -o $@ $(TCP_LIBS)

clean:
	rm -f quic/quic_client.out quic/quic_server.out tcp/tcp_client.out tcp/tcp_server.out
