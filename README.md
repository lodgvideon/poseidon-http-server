# Poseidon HTTP/2 Server

**Zero-allocation HTTP/2 + gRPC server for Go**, built on [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) codec.

Drop-in `http.Handler` replacement — compatible with **chi**, **echo**, **gin**, and any router built on `net/http`.

## Features

- **Zero allocation** — hot paths (HPACK encode, flow control, status codes) achieve 0 allocs/op
- **HTTP/2 + h2c** — TLS with ALPN negotiation + clear-text (h2c) with prior-knowledge and Upgrade
- **gRPC** — Unary, Server-streaming, Client-streaming, Bidi-streaming
- **Middleware** — Recovery, RequestID, AccessLog, CORS
- **Graceful drain** — `Shutdown(ctx)` waits for in-flight streams, sends GOAWAY
- **Idle timeout** — auto-close idle connections
- **Connection limits** — `MaxConcurrentConnections`, `MaxConcurrentStreams`

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
reg.Register(&grpcserver.ServiceDesc{
    Name: "my.Service",
    Methods: []grpcserver.MethodDesc{
        {Name: "Echo", Handler: echoHandler},
    },
})

srv, _ := server.NewServer(server.Options{
    Handler: reg,
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
| `middleware` | Recovery, RequestID, AccessLog, CORS |

## Requirements

- Go 1.26+
- [poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) (codec: frame + hpack)

## License

MIT
