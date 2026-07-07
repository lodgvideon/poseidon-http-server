# Poseidon HTTP/2 Server

**Zero-allocation HTTP/2 + gRPC server for Go**, built on [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) codec.

Drop-in `http.Handler` replacement — compatible with **chi**, **echo**, **gin**, and any router built on `net/http`.

## Features

- **Zero allocation** — hot paths (HPACK encode, flow control, status codes) achieve 0 allocs/op
- **HTTP/2 + h2c** — TLS with ALPN negotiation + clear-text (h2c) with prior-knowledge and Upgrade
- **gRPC** — Unary, Server-streaming, Client-streaming, Bidi-streaming; health check + reflection
- **Middleware suite** — Recovery, RequestID, AccessLog, StructuredAccessLog (slog), CORS, Gzip — plus the security & observability middleware below
- **Security hardening** — HTTP/2 Rapid Reset (CVE-2023-44487) mitigation, request body-size limit, slowloris/idle timeouts, gzip decompression-bomb bound, per-client rate limiting (bounded memory), RealIP with trusted-proxy CIDRs, SecurityHeaders (HSTS / nosniff / frame-options / …)
- **Observability** — Prometheus metrics (request + HTTP/2 transport counters), `/healthz` + `/readyz` with drain-aware readiness, opt-in pprof, vendor-neutral tracing hooks
- **Graceful drain** — `Shutdown(ctx)` waits for in-flight streams, sends GOAWAY; readiness flips NOT-ready at drain start
- **Connection & stream limits** — `MaxConcurrentConnections`, `MaxConcurrentStreams` (advertised **and** enforced inbound)
- **Deploy-ready** — 12-factor `poseidon-server` binary, distroless Dockerfile, Helm chart + raw k8s manifests

## Installation

```sh
go get github.com/lodgvideon/poseidon-http-server@latest
```

Requires **Go 1.24+**. The only dependency is the HTTP/2 codec (`frame` + `hpack`)
from [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client);
there are no other third-party runtime dependencies.

```go
import (
    "github.com/lodgvideon/poseidon-http-server/server"
    "github.com/lodgvideon/poseidon-http-server/grpcserver"
    "github.com/lodgvideon/poseidon-http-server/middleware"
)
```

## Quick Start

### HTTP/2 Server

```go
srv, _ := server.NewServer(server.Options{
    Handler:     myHandler,
    IdleTimeout: 30 * time.Second,
})

ln, _ := net.Listen("tcp", ":8080")
srv.Serve(context.Background(), ln)
```

### TLS + ALPN

```go
srv.ListenAndServeTLS(ctx, "cert.pem", "key.pem")
```

### gRPC Server

```go
reg := grpcserver.NewServiceRegistrar()
reg.RegisterService(&grpcserver.ServiceDesc{
    Name: "my.Service",
    Methods: []grpcserver.MethodDesc{
        {Name: "Echo", UnaryHandler: echoHandler},
    },
})

srv, _ := server.NewServer(server.Options{
    Handler: reg.Handler(),
})
```

### Middleware Chain

```go
chain := server.Chain(
    middleware.Recovery(nil),
    middleware.RequestID(),
    middleware.AccessLog(logger),
)

srv, _ := server.NewServer(server.Options{
    Handler: chain(myHandler),
})
```

### Graceful Drain

```go
ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer cancel()

go srv.Serve(ctx, ln)

<-ctx.Done()
shutdownCtx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
defer scancel()
srv.Shutdown(shutdownCtx) // waits for active streams
```

## Benchmarks

### conn/ (per-frame operations)
```
BenchmarkWriteServerHeaders    5554 ns/op    0 B/op    0 allocs/op
BenchmarkWriteServerData       5794 ns/op    0 B/op    0 allocs/op
BenchmarkAcquireSendCredits      54 ns/op    0 B/op    0 allocs/op
BenchmarkOnWindowUpdate           39 ns/op    0 B/op    0 allocs/op
BenchmarkOnDataReceived           53 ns/op    0 B/op    0 allocs/op
```

### grpcserver/ (gRPC hot paths)
```
BenchmarkStatusToHPack      2 ns/op    0 B/op    0 allocs/op
BenchmarkLookup            0 ns/op    0 B/op    0 allocs/op
```

## Packages

| Package | Description |
|---------|-------------|
| `conn` | HTTP/2 connection management (server-side streams, flow control, HPACK) |
| `server` | `net.Handler`-compatible HTTP/2 server with middleware, TLS, h2c |
| `grpcserver` | gRPC layer: ServiceRegistrar, 4 RPC patterns, framing |
| `middleware` | Recovery, RequestID, AccessLog, StructuredAccessLog (slog), Metrics, SecurityHeaders, RateLimit, RealIP, Gzip, CORS, Tracing |

## Requirements

- Go 1.24+
- [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) (codec: frame + hpack) — resolved automatically via `go get`

## Documentation

- **[Usage guide](docs/usage.md)** — configuration, middleware catalog, security hardening, observability, and deployment.
- **[Architecture Decision Records](docs/adr/)** — zero-alloc contract, RFC 7540 choices, ResponseWriter interface, Rapid Reset mitigation, and more.
- **[Examples](examples/)** — runnable servers: HTTP/2, TLS, gRPC, observability, and security.
- **[CHANGELOG](CHANGELOG.md)** — release history and migration notes.

## License

MIT
