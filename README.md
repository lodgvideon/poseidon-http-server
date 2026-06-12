# poseidon-http-server

A low-level, zero-allocation HTTP/2 and gRPC server for Go, built on top of
[poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) codec
libraries. Implements RFC 7540 (HTTP/2) server-side from scratch — no `net/http`,
no `golang.org/x/net/http2`.

**Status:** Phase A — Frame layer reuse + server-side connection.

## Design Principles

- **Zero-allocation** on hot paths: frame codec reuses buffers, sync.Pool for
  stream structs, pre-allocated HPACK tables.
- **HTTP/2 + gRPC**: native HTTP/2 server with gRPC framing (Length-Prefixed
  Messages, trailered status codes) as a first-class citizen.
- **Strict SOLID**: every package has a single responsibility; dependencies flow
  inward through interfaces; extensibility via composition, not inheritance.

## Architecture (SOLID layers)

```
frame/               # Layer A: RFC 7540 frame codec (shared with client)
hpack/               # Layer A: RFC 7541 HPACK encoder/decoder (shared with client)
internal/bytesx/     # Layer A: big-endian helpers
conn/                # Layer B: server-side HTTP/2 connection, streams, flow control
server/              # Layer C: HTTP/2 server (listener, TLS, h2c, handler dispatch)
grpcserver/          # Layer D: gRPC-over-HTTP/2 (LP messages, status codes, trailers)
cmd/poseidon-server/ # Layer E: example binary
docs/                # RFC coverage, benchmarks, design specs
```

### SOLID mapping

| Principle | How it's enforced |
|-----------|-------------------|
| **S** — Single Responsibility | Each package owns exactly one protocol concern: `frame` = codec, `conn` = connection state machine, `server` = accept loop + routing, `grpcserver` = gRPC framing |
| **O** — Open/Closed | Handler interfaces + middleware chain; add behaviour without modifying core |
| **L** — Liskov Substitution | `Handler` interface; `grpcserver.Handler` wraps `server.Handler`; any implementation is interchangeable |
| **I** — Interface Segregation | Small focused interfaces: `FrameWriter`, `StreamReader`, `Handler`, `Middleware` — clients depend only on what they use |
| **D** — Dependency Inversion | `conn.Conn` depends on `FrameWriter`/`FrameReader` interfaces, not concrete `frame.Framer`; `server.Server` depends on `Listener` interface, not `net.Listener` |

## Phases

- **A — Frame layer reuse + server conn** *(in progress)*: reuse `frame` and
  `hpack` packages from poseidon-http-client; server-side `conn.Conn` with
  inbound stream management, SETTINGS handshake (server perspective), flow
  control.
- **B — HTTP/2 server** *(planned)*: `server.Server` with TLS + h2c listen,
  `Handler` interface, header/body routing, graceful shutdown, GOAWAY.
- **C — gRPC framing** *(planned)*: `grpcserver` package with Length-Prefixed
  Message codec, gRPC status trailer encoding/decoding, unary + streaming RPCs.
- **D — Zero-allocation polish** *(planned)*: bench-gate enforcement, buffer
  pools, HPACK slab allocator reuse, profile-guided optimization.

## Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/lodgvideon/poseidon-http-server/server"
)

func main() {
    srv, err := server.NewServer(server.ServerOptions{
        Addr: ":8443",
    })
    if err != nil {
        log.Fatal(err)
    }

    srv.Handle("GET", "/hello", func(ctx context.Context, req *server.Request, w *server.ResponseWriter) error {
        return w.WriteHeaders(200, nil)
    })

    log.Fatal(srv.ListenAndServe(context.Background()))
}
```

## Limits and contracts

- `conn.Conn` is goroutine-safe. Each stream is dispatched to a handler
  goroutine; the handler must not hold the stream after returning.
- Zero-allocation target: 0 allocs/op on the frame codec path, minimal
  allocs on the request dispatch path (header slice from pool).
- `frame.Framer` and `hpack.Encoder`/`Decoder` are NOT goroutine-safe —
  `conn.Conn` serializes writes via mutex, each stream reads from its own
  event channel.

## Commands

```bash
make tidy        # go mod tidy
make lint        # golangci-lint run
make test-race   # go test -race ./...
make bench       # benchmarks with bench-gate
```

## License

Proprietary — LodgVideoN
