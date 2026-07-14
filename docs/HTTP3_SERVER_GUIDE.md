# HTTP/3 server — guide

`http3server` serves HTTP/3 (RFC 9114) to an ordinary `http.Handler`. Each
client-initiated bidirectional QUIC stream carries one request/response
exchange. The QUIC transport, HTTP/3 frame codec, and QPACK field compression
all come from [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client),
which owns the wire format for both roles; this package is the `http.Handler`
adapter on top. It shares nothing with the HTTP/2 server in `server/` — no
`net.Listener`, no `conn/`, a different `ResponseWriter`.

This is an early, deliberately small server. Read
[What it does not do](#what-it-does-not-do) before deploying it anywhere that
matters, and do not expose it to the internet without a rate limiter in front.

## Quick start

`Server` has exactly two fields. There are no options structs and no
per-connection knobs yet.

```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/lodgvideon/poseidon-http-server/http3server"
)

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http3server.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "hello %s %s", r.Method, r.URL.Path)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	log.Fatal(srv.ListenAndServe(context.Background(), ":8443"))
}
```

- `addr` is a UDP `host:port`; port 0 picks one. HTTP/3 runs over UDP — there
  is no TCP socket anywhere in this path.
- A nil `Handler` serves `http.DefaultServeMux`.
- `TLSConfig` must carry the server's certificate(s). It is cloned and forced
  to TLS 1.3; ALPN `"h3"` is filled in when `NextProtos` is unset.
- `ListenAndServe` blocks until `ctx` is cancelled or the listener fails.
  Cancellation is abrupt: connections are closed, in-flight requests are cut
  (see [What it does not do](#what-it-does-not-do)).
- This package speaks only HTTP/3. It does not advertise `Alt-Svc` and has no
  TCP fallback, so a browser will not discover it on its own; pair it with an
  HTTP/1.1 or HTTP/2 endpoint if you need discovery.

To control the transport parameters — the one configuration escape hatch —
build the listener yourself and hand it to `Serve`:

```go
l, err := quic.Listen("127.0.0.1:0", srv.TLSConfig, quic.ServerTransportParams{
	MaxStreamsBidi: 100,             // concurrent requests per connection
	MaxStreamsUni:  4,               // client control + QPACK streams, with slack
	MaxIdleTimeout: 30_000,          // ms; ListenAndServe advertises none
})
if err != nil {
	log.Fatal(err)
}
defer l.Close()
log.Fatal(srv.Serve(ctx, l))
```

`ListenAndServe` uses `MaxStreamsBidi: 100`, `MaxStreamsUni: 4`, and no
`MaxIdleTimeout`. The package's own tests serve this way against the real
poseidon-http-client HTTP/3 client over loopback UDP — nothing mocked
(`http3server/server_test.go`).

## Architecture

Three layers, three goroutine roles:

1. **The listener demuxes one UDP socket** (`quic.Listener`,
   poseidon-http-client `quic/listener.go`). One goroutine reads every
   datagram and routes it by Destination Connection ID to the connection's
   private view of the socket (`connPacketConn`). The server issues fixed
   8-byte CIDs so every short header parses without per-connection state
   (RFC 9000 §5.1 allows any length up to 20). The demux loop does no crypto
   and never blocks on a connection: each view has a bounded inbound queue
   (64 datagrams) and a full queue drops, as a kernel receive buffer would —
   QUIC loss recovery handles it. A datagram whose DCID is unknown starts a
   handshake if it is an Initial and is dropped otherwise.

2. **One goroutine per connection drives `Poll`** (`Server.serveConn`). After
   `Accept`, this goroutine opens the server control stream and sends
   SETTINGS — which RFC 9114 §6.2.1 requires as the control stream's first
   frame — then loops on `Conn.Poll`. The Poll loop is the only thing that
   reads the connection's socket view; it runs receive, ACK, loss detection,
   and flow control, exactly as a client drives its own connection, so the
   server introduces no new concurrency model. Client bidirectional streams
   (requests, IDs 0, 4, 8, … per RFC 9000 §2.1) are handed to per-request
   goroutines; client unidirectional streams (its control and QPACK streams)
   are accepted so they are flow-controlled, but under the static-table QPACK
   profile there is nothing to read from them.

3. **One goroutine per request** (`Server.serveRequest`) buffers the request
   stream to FIN — parking on the stream's readiness between deliveries from
   the Poll loop — runs the handler, and writes the framed response back with
   FIN.

The handshake path: the listener feeds the client's first Initial to
`quic.AcceptInitial`, which derives Initial keys from the client's DCID
(RFC 9001 §5.2) and extracts the ClientHello. `quic.StartServerHandshake`
drives `crypto/tls`'s QUIC server through its first flight; the transport
parameters carry the server's chosen SCID and the client's original DCID,
which the client authenticates (RFC 9000 §7.3). One goroutine per inbound
Initial then reads the client's Finished (bounded at 10 s), builds the
connection with `quic.NewServerConn`, and publishes it to `Accept`. Every
failure just drops the half-open connection: an unauthenticated peer gets no
error reply.

## How a request becomes an `http.Request`

The whole request stream is buffered until the client's FIN, then parsed:

- The first HEADERS frame carries the QPACK field section, decoded under the
  static-table profile (RFC 9204). Pseudo-headers map per RFC 9114 §4.3.1:
  `:method`, `:scheme`, `:path` (all required), `:authority` → `Request.Host`
  and `URL.Host`. An unknown pseudo-header, or a missing required one, makes
  the request malformed. `Proto` is `"HTTP/3.0"`.
- DATA frames are concatenated into `Request.Body`; `ContentLength` is the
  byte count. The handler does not run until the full request has arrived.
- A second HEADERS frame (trailers) is dropped. Unknown and reserved frame
  types on the request stream are ignored (RFC 9114 §7.2.8).

The response is the mirror image, built after `ServeHTTP` returns: `:status`
leads the field section (RFC 9114 §4.3.2), header names are lowercased for
the wire, the section is QPACK-encoded (static table only), then one HEADERS
frame and — if the handler wrote a body — one DATA frame go out, FIN ending
the stream (§4.1).

Failure mapping, request stream → `RESET_STREAM` code:

| Failure | Code |
|---|---|
| stream reset by peer, buffer cap exceeded, or connection ending | `H3_REQUEST_CANCELLED` |
| frames or field section do not decode; malformed request | `H3_MESSAGE_ERROR` |
| response field section exceeds the advertised limit | `H3_INTERNAL_ERROR` |

## Advertised settings and fixed limits

All fixed constants in `http3server/server.go`; none are configurable.

| Limit | Value | Where it bites |
|---|---|---|
| `SETTINGS_MAX_FIELD_SECTION_SIZE` | 64 KiB | request field sections the client may send; response field sections we refuse to exceed |
| `SETTINGS_QPACK_MAX_TABLE_CAPACITY` | 0 | static-table QPACK profile: no dynamic table |
| `SETTINGS_QPACK_BLOCKED_STREAMS` | 0 | decoding never blocks on head-of-line |
| buffered request cap | 1 MiB | headers + body of one request; over → `H3_REQUEST_CANCELLED` |
| `initial_max_streams_bidi` | 100 | concurrent requests per connection |
| `initial_max_streams_uni` | 4 | client control + QPACK encoder/decoder streams, with slack |
| `initial_max_data` | 1 MiB | connection receive window (transport default) |
| handshake bound | 10 s | a half-open connection that never finishes is abandoned |

The static-table QPACK profile is fully conformant: advertising zero table
capacity contractually forbids the client from using dynamic-table
insertions or blocking against us (RFC 9204), so the decoder never maintains
a dynamic table.

`ListenAndServe` advertises no `max_idle_timeout`, so the idle timeout in
effect is whatever the client advertises (RFC 9000 §10.1 takes the smaller of
the two advertised values; a side that advertises none imposes none). Against
a client that also advertises none, a connection has no idle bound — it lives
until the peer closes or `ctx` is cancelled. Use `Serve` with your own
listener to advertise one.

## What it does not do

Deferred, in the spirit of HTTP3_DESIGN.md's non-goals list — each is
spec-optional or an explicit later phase, but you should know before choosing
this server.

**HTTP level:**

- **No streaming response bodies.** The `ResponseWriter` buffers everything:
  the field section must be final before anything is framed, and the current
  writer keeps body framing behind that same barrier. `http.Flusher` is not
  implemented, so SSE and long-poll do not stream. Streaming a body as it is
  written is a later phase.
- **No streaming request bodies.** The handler runs only after the client's
  FIN; a request over 1 MiB is reset, so large uploads do not fit.
- **No trailers**, either direction: request trailers are dropped, and the
  `ResponseWriter` has no way to emit them.
- **No server push, no 0-RTT.**
- **No CONNECT.** A request without `:scheme` and `:path` is treated as
  malformed, which rejects CONNECT (and extended CONNECT) by construction.
- **No graceful drain and no GOAWAY.** Cancelling `ctx` returns from `Serve`
  and closes each connection as its Poll loop observes the cancellation;
  in-flight requests are cut. There is no HTTP/2-`Shutdown` analogue.
- **None of the `server/` machinery**: no middleware chain, no metrics, no
  connection/stream accounting beyond the transport limits above.

**Transport level** (`quic.Listener`, see poseidon-http-client's
`docs/QUIC_SERVER_DESIGN.md`):

- **No Retry / address validation** (RFC 9000 §8.1). The listener answers
  every Initial, and each new Initial starts one goroutine that does real TLS
  work. An unvalidated — possibly spoofed-source — peer can make the server
  burn CPU and send handshake flights. There is **no per-peer rate limiting**
  either. Put this behind a rate limiter before it faces the internet; that
  is not advice, it is the deployment contract.
- **No connection migration.** A connection's peer address is pinned at
  handshake time.
- **No key update on server connections** (RFC 9001 §6 is not armed), and no
  connection ID rotation — one fixed 8-byte SCID per connection.

## Dependencies

`http3server` consumes `quic`, `http3`, `qpack`, and `hpack` from
poseidon-http-client. This is a wider dependency than the rest of this repo:
the HTTP/2 server links only the `frame` + `hpack` codecs, while this package
pulls in the client's whole QUIC engine — packet protection, loss recovery,
flow control. Consequences:

- **Go 1.25** is the floor (poseidon-http-client's `go` directive; this
  module matches).
- **`golang.org/x/crypto`** comes in transitively — QUIC packet protection
  needs its HKDF/AEAD primitives (RFC 9001).

## See also

- `http3server/server.go` — the package is small enough to read.
- [poseidon-http-client `docs/QUIC_SERVER_DESIGN.md`](https://github.com/lodgvideon/poseidon-http-client/blob/main/docs/QUIC_SERVER_DESIGN.md)
  — the S-series design this server is built on.
- [poseidon-http-client `docs/HTTP3_DESIGN.md`](https://github.com/lodgvideon/poseidon-http-client/blob/main/docs/HTTP3_DESIGN.md)
  — the HTTP/3 + QUIC architecture shared by both roles.
- [docs/usage.md](usage.md) — the HTTP/2 server this repo is primarily about.
