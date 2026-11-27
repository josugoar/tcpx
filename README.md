# tcpx

> Embedded quic and tcp client and server

## Build

```sh
make
make quic
make tcp
make clean
```

## Run

Both services listen on port `1025` over TCP and UDP respectively.

### TCP

1. Start the server in one terminal.

   ```sh
   cd tcpx
   ./tcp/tcp_server.out
   ```

2. In a second terminal, send a line to the client.

   ```sh
   cd tcpx
   printf 'hello over tcp\n' | ./tcp/tcp_client.out
   ```

3. The server's terminal shows the line.

   ```
   hello over tcp
   ```

### QUIC

1. Start the server in one terminal.

   ```sh
   cd tcpx
   ./quic/quic_server.out 2> quic-server.log
   ```

2. In a second terminal, send a line to the client.

   ```sh
   cd tcpx
   printf 'hello over quic\n' | ./quic/quic_client.out 2> quic-client.log
   ```

3. The server's terminal shows the line.

   ```
   hello over quic
   ```

## Layout

```
tcpx/
├── Makefile
├── quic/
│   ├── quic.h
│   ├── quic_client.c
│   └── quic_server.c
└── tcp/
    ├── tcp_client.c
    └── tcp_server.c
```

## Caveats

- The QUIC client polls its socket for 100 ms after each send rather than running a full event loop, which prevents it from processing ACKs while blocked reading standard input.

- The QUIC server cannot service multiple simultaneous clients and does not handle expiry gracefully so a delayed ACK for a single final data packet is not flushed, which may cause the client to not receive an ACK for the last chunk and for the loss recovery and idle timeouts to remain inactive.

- The QUIC data buffer does not wrap or compact, so a stream larger than `QUIC_DATALEN` that is not acknowledged before the buffer fills will stop accepting new input until the indexes reset.
