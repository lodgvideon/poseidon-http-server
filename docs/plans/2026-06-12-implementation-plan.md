# PoseidonHTTPServer — Implementation Plan

> **Goal:** Build a zero-allocation HTTP/2 + gRPC server in Go, reusing the `frame` and `hpack` codec layers from poseidon-http-client.

**Architecture:** Layered SOLID — frame/hpack (reuse) → conn (server-side state machine) → server (accept/route) → grpcserver (gRPC framing). Each layer depends only on interfaces from the layer below.

**Tech Stack:** Go 1.24, `github.com/lodgvideon/poseidon-http-client` (frame + hpack + internal/bytesx)

---

## Step 0.5: Assumptions

| # | Assumption | Source | Risk |
|---|-----------|--------|------|
| 1 | `frame` and `hpack` packages are fully usable from server-side (no client-specific coupling) | Inferred from API: `Framer` is bidirectional | Low — Framer has `WriteServerPreface`-style needs, check |
| 2 | `conn.Conn` is client-only; server needs its own `conn.ServerConn` | Explicit: `NewClientConn` is the only constructor | None |
| 3 | Server-side HTTP/2 connection preface = client preface magic read + server SETTINGS write (RFC 7540 §3.3, §3.4) | RFC 7540 | None |
| 4 | gRPC support = HTTP/2 + Length-Prefixed Messages (5-byte header) + status trailers | RFC 7540 + gRPC spec | None |
| 5 | Zero-allocation target applies to hot path (frame codec + stream dispatch), not startup/shutdown | Inferred from client convention | None |
| 6 | No `net/http` dependency — we accept raw `net.Conn` and do our own TLS/h2c | Explicit from rules | None |

---

## Phases

### Phase A — Server-side connection layer (conn package)

**Goal:** Accept a `net.Conn`, perform HTTP/2 handshake (server perspective), manage inbound streams, flow control, SETTINGS, GOAWAY, PING.

---

#### A.1: Server-side connection preface handler

**Objective:** Read client preface magic (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), send server SETTINGS, await SETTINGS ACK.

**Files:**
- Create: `conn/server_conn.go`
- Create: `conn/server_conn_test.go`

**Design:**
```go
// conn/server_conn.go

// ServerConn manages a single server-side HTTP/2 connection.
// Goroutine-safe for AcceptStream; per-stream methods are single-goroutine.
type ServerConn struct { ... }

// ServerConnOptions configures the server-side connection.
type ServerConnOptions struct {
    // AdvertisedSettings are sent in the initial SETTINGS frame.
    AdvertisedSettings AdvertisedSettings
    // StreamEventBuffer is the per-stream event channel capacity.
    StreamEventBuffer int
}

// NewServerConn performs the HTTP/2 server-side handshake:
//   1. Read client preface magic (24 bytes)
//   2. Send server SETTINGS frame
//   3. Start reader goroutine
func NewServerConn(ctx context.Context, nc net.Conn, opts ServerConnOptions) (*ServerConn, error)

// AcceptStream blocks until a new client-initiated stream arrives
// (HEADERS frame on an idle stream ID). Returns the stream with
// initial headers ready to read via Recv.
func (sc *ServerConn) AcceptStream(ctx context.Context) (*ServerStream, error)

// Close sends GOAWAY(NO_ERROR) and closes the underlying connection.
func (sc *ServerConn) Close() error

// Stats returns point-in-time connection counters.
func (sc *ServerConn) Stats() ConnStats
```

**Verify:** Unit test with `net.Pipe` — read preface magic, verify SETTINGS sent, verify error on bad magic.

**Commit:** `feat(conn): server-side connection preface handler`

---

#### A.2: ServerStream — inbound stream state machine

**Objective:** Represent a server-side stream with state transitions (idle → open → half-closed → closed), receive headers/data/reset events.

**Files:**
- Create: `conn/server_stream.go`
- Create: `conn/server_stream_test.go`

**Design:**
```go
// ServerStream is a single server-side HTTP/2 stream.
// Single-goroutine: handler owns the stream after AcceptStream returns it.
type ServerStream struct { ... }

// ID returns the stream identifier (client-initiated, odd).
func (ss *ServerStream) ID() uint32

// Recv returns the next event on this stream (headers, data, trailers, reset).
// Blocks until an event arrives or the stream/connection is closed.
func (ss *ServerStream) Recv(ctx context.Context) (StreamEvent, error)

// SendHeaders sends a HEADERS frame on this stream.
func (ss *ServerStream) SendHeaders(ctx context.Context, fields []hpack.HeaderField, endStream bool) error

// SendData sends a DATA frame on this stream.
func (ss *ServerStream) SendData(ctx context.Context, p []byte, endStream bool) error

// Close sends RST_STREAM if the stream is still open.
func (ss *ServerStream) Close() error
```

**Verify:** Unit test — push events into channel, verify Recv returns them in order, verify state transitions.

**Commit:** `feat(conn): server-side stream state machine`

---

#### A.3: Inbound flow control (receive side)

**Objective:** Track per-stream and connection-level receive windows, send WINDOW_UPDATE when threshold reached.

**Files:**
- Modify: `conn/server_conn.go`
- Create: `conn/server_flow_test.go`

**Design:**
- `recvWindow` per stream (initial from `SETTINGS_INITIAL_WINDOW_SIZE`, default 65535)
- `connRecvWindow` for connection-level
- `recvWindowRefundThreshold = 32 KiB` (same as client)
- On DATA frame: decrement window; if below threshold → send WINDOW_UPDATE

**Verify:** Test — receive DATA frames, verify WINDOW_UPDATE sent at threshold, verify FLOW_CONTROL_ERROR on overrun.

**Commit:** `feat(conn): inbound flow control with WINDOW_UPDATE`

---

#### A.4: Outbound flow control (send side)

**Objective:** Respect peer's advertised window and MAX_FRAME_SIZE, chunk large writes, block on credit exhaustion.

**Files:**
- Modify: `conn/server_stream.go`
- Create: `conn/server_sendflow_test.go`

**Design:**
- Track `peerInitialWindowSize` and `peerMaxFrameSize` from received SETTINGS
- `SendData` chunks at `min(peerMaxFrameSize, ourMaxFrameSize)`
- `acquireSendCredits` blocks until stream + conn send windows have credit
- Context cancellation wakes blocked writers

**Verify:** Test — set peer window to small value, verify SendData blocks then unblocks on WINDOW_UPDATE.

**Commit:** `feat(conn): outbound flow control for server streams`

---

#### A.5: Dynamic SETTINGS processing (server-side)

**Objective:** Handle client SETTINGS frames, apply side effects (HPACK table resize, window delta retroactive), send SETTINGS ACK.

**Files:**
- Modify: `conn/server_conn.go`
- Create: `conn/server_settings_test.go`

**Design:**
- `onSettings` handler merges into `peerSettings`
- Apply `SETTINGS_INITIAL_WINDOW_SIZE` delta to all open streams (RFC §6.9.2)
- Update HPACK encoder dynamic table size
- Send SETTINGS ACK
- `peerSettings` guarded by `psMu sync.RWMutex`

**Verify:** Test — send SETTINGS with changed INITIAL_WINDOW_SIZE, verify delta applied to existing streams, verify ACK sent.

**Commit:** `feat(conn): dynamic SETTINGS processing with retroactive window resize`

---

#### A.6: GOAWAY drain (server-side)

**Objective:** Server can send GOAWAY to drain connections gracefully. Handle incoming client GOAWAY.

**Files:**
- Modify: `conn/server_conn.go`
- Create: `conn/server_goaway_test.go`

**Design:**
- `(*ServerConn).GoAway(code ErrCode, debug []byte)` — sends GOAWAY with last processed stream ID
- After GOAWAY: AcceptStream returns `ErrGoAway`; existing streams complete
- On incoming GOAWAY from client: record, stop accepting new streams

**Verify:** Test — send GOAWAY mid-connection, verify new AcceptStream fails, verify existing streams drain.

**Commit:** `feat(conn): GOAWAY drain for graceful shutdown`

---

#### A.7: PING keepalive (server-side)

**Objective:** Respond to client PING with ACK. Optionally send server-initiated PING for keepalive.

**Files:**
- Modify: `conn/server_conn.go`
- Create: `conn/server_ping_test.go`

**Design:**
- Inbound non-ACK PING → auto-respond with ACK + same payload
- Optional: `KeepaliveInterval` + `KeepaliveTimeout` config
- Background goroutine sends PING, closes connection on timeout

**Verify:** Test — send PING, verify ACK with same payload. Test keepalive timeout.

**Commit:** `feat(conn): PING echo and server-side keepalive`

---

#### A.8: Integration tests against poseidon-http-client

**Objective:** End-to-end tests using `conn.Conn` (client) → `conn.ServerConn` (server) via `net.Pipe`.

**Files:**
- Create: `conn/integration_test.go`

**Verify:**
- Single stream request/response
- Multiple concurrent streams
- Flow control bidirectional
- GOAWAY graceful drain
- PING/ACK roundtrip
- Settings exchange

**Commit:** `test(conn): integration tests against poseidon-http-client`

---

### Phase B — HTTP/2 server (server package)

**Goal:** Accept network connections, dispatch streams to handlers, support TLS and h2c.

---

#### B.1: Handler interface + request/response types

**Objective:** Define the core handler interface and HTTP request/response abstractions.
**Critical:** The `server` package MUST implement `net/http.Handler` compatibility
so that any `chi.Router`, `http.Handler`, or `http.HandlerFunc` can be used as a
drop-in handler. This is achieved via:

1. `server.Request` wraps `*http.Request` (or implements `io.Reader` for body)
2. `server.ResponseWriter` implements `http.ResponseWriter`
3. `server.Server` accepts `http.Handler` in options
4. Adapter converts `chi.Router` → `server.Handler` automatically

**Files:**
- Create: `server/handler.go`
- Create: `server/handler_test.go`
- Create: `server/adapter.go`       ← net/http compatibility layer
- Create: `server/adapter_test.go`  ← chi/stdlib drop-in tests

**Design:**
```go
// --- Native Poseidon handler (zero-allocation path) ---

// Handler processes a single HTTP/2 request.
type Handler interface {
    ServeHTTP(ctx context.Context, req *Request, w *ResponseWriter) error
}

// HandlerFunc is a convenience adapter for Handler.
type HandlerFunc func(ctx context.Context, req *Request, w *ResponseWriter) error

// Request represents a server-side HTTP/2 request.
type Request struct {
    Method  string
    Path    string
    Headers []hpack.HeaderField
    Body    []byte  // collected if WantBody; nil for streaming
}

// ResponseWriter writes an HTTP/2 response.
type ResponseWriter struct { ... }
func (w *ResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error
func (w *ResponseWriter) WriteData(p []byte) error
func (w *ResponseWriter) WriteTrailers(trailers []hpack.HeaderField) error

// --- Drop-in net/http compatibility ---

// ResponseWriter implements http.ResponseWriter.
// This allows standard middleware (logging, recovery, CORS) to work unchanged.
func (w *ResponseWriter) Header() http.Header
func (w *ResponseWriter) Write(p []byte) (int, error)
func (w *ResponseWriter) WriteHeader(statusCode int)

// FromHTTPHandler adapts any http.Handler (chi.Router, http.HandlerFunc, etc.)
// to a Poseidon Handler. Zero additional allocations on the adapter path.
func FromHTTPHandler(h http.Handler) Handler

// ToHTTPHandler adapts a Poseidon Handler to http.Handler.
func ToHTTPHandler(h Handler) http.Handler

// ServerOptions accepts either Handler or http.Handler:
type ServerOptions struct {
    // Handler is the native Poseidon handler (zero-allocation path).
    Handler Handler
    // HTTPHandler is a drop-in for chi.Router, http.ServeMux, etc.
    // If both are set, Handler takes precedence.
    HTTPHandler http.Handler
}
```

**Drop-in usage with chi:**
```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/lodgvideon/poseidon-http-server/server"
)

func main() {
    r := chi.NewRouter()
    r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hi from Poseidon!"))
    })

    srv, _ := server.NewServer(server.ServerOptions{
        Addr:       ":8443",
        HTTPHandler: r,  // drop-in!
    })
    srv.ListenAndServe(context.Background())
}
```

**Verify:**
- Unit test: HandlerFunc adapter works, ResponseWriter methods produce correct frames
- Integration test: `chi.NewRouter()` → `FromHTTPHandler(r)` → serve request → verify response
- Verify `ResponseWriter` satisfies `http.ResponseWriter` interface at compile time
- Verify `FromHTTPHandler(http.HandlerFunc(...))` roundtrip

**Commit:** `feat(server): handler interface with net/http drop-in compatibility`

---

#### B.2: Middleware chain

**Objective:** Support composable middleware for logging, metrics, auth, etc.

**Files:**
- Create: `server/middleware.go`
- Create: `server/middleware_test.go`

**Design:**
```go
// Middleware wraps a Handler with before/after logic.
type Middleware func(Handler) Handler

// Chain composes middlewares: Chain(m1, m2)(h) = m1(m2(h)).
func Chain(mw ...Middleware) Middleware
```

**Verify:** Test — chain 3 middlewares, verify execution order.

**Commit:** `feat(server): middleware chain`

---

#### B.3: Server — accept loop + stream dispatch

**Objective:** Accept connections, handshake, accept streams, dispatch to handlers in goroutines.

**Files:**
- Create: `server/server.go`
- Create: `server/server_test.go`

**Design:**
```go
type ServerOptions struct {
    Addr              string
    TLSConfig         *tls.Config
    Handler           Handler      // native Poseidon handler
    HTTPHandler       http.Handler // drop-in for chi.Router, etc. (fallback)
    ConnOpts          conn.ServerConnOptions
    MaxConcurrentConn int
    IdleTimeout       time.Duration
}

type Server struct { ... }

func NewServer(opts ServerOptions) (*Server, error)
func (s *Server) ListenAndServe(ctx context.Context) error
func (s *Server) Shutdown(ctx context.Context) error
func (s *Server) Close() error
```

**Verify:** Integration test — start server, connect with poseidon-http-client, do GET, verify response.

**Commit:** `feat(server): accept loop with stream dispatch`

---

#### B.4: H2C (plaintext HTTP/2) support

**Objective:** Support HTTP/2 over cleartext with prior-knowledge handshake.

**Files:**
- Modify: `server/server.go`
- Create: `server/h2c_test.go`

**Design:**
- `DefaultScheme = "h2c"` option
- Detect client preface magic on plaintext connection
- If no TLSConfig → accept as h2c

**Verify:** Test — connect with `conn.PlaintextDialer`, verify request/response works.

**Commit:** `feat(server): h2c plaintext HTTP/2 support`

---

#### B.5: Request body streaming

**Objective:** Stream request body via `io.ReadCloser` instead of buffering entire body.

**Files:**
- Create: `server/body.go`
- Create: `server/body_test.go`

**Design:**
```go
// Request adds:
BodyReader io.ReadCloser // streaming body (nil if already collected)
```

**Verify:** Test — POST large body, verify streaming reads match.

**Commit:** `feat(server): request body streaming`

---

#### B.6: Graceful shutdown

**Objective:** `Shutdown()` sends GOAWAY, waits for in-flight streams to complete with timeout.

**Files:**
- Modify: `server/server.go`
- Create: `server/shutdown_test.go`

**Verify:** Test — start request, trigger shutdown, verify request completes before server exits.

**Commit:** `feat(server): graceful shutdown with GOAWAY`

---

### Phase C — gRPC framing (grpcserver package)

**Goal:** gRPC-over-HTTP/2 with Length-Prefixed Messages, status codes, streaming RPCs.

---

#### C.1: Length-Prefixed Message codec

**Objective:** Encode/decode gRPC LP messages (1 byte compressed flag + 4 bytes length + payload).

**Files:**
- Create: `grpcserver/lpmessage.go`
- Create: `grpcserver/lpmessage_test.go`

**Design:**
```go
// LPMessage is a gRPC Length-Prefixed Message.
type LPMessage struct {
    Compressed bool
    Data       []byte
}

func EncodeLP(dst []byte, msg LPMessage) []byte
func DecodeLP(src []byte) (LPMessage, int, error)
```

**Verify:** Roundtrip encode/decode, zero-allocation on encode path.

**Commit:** `feat(grpcserver): Length-Prefixed Message codec`

---

#### C.2: gRPC status trailer encoding

**Objective:** Encode gRPC status as HTTP/2 trailers (`grpc-status`, `grpc-message`, `grpc-status-details-bin`).

**Files:**
- Create: `grpcserver/status.go`
- Create: `grpcserver/status_test.go`

**Design:**
```go
// Code is a gRPC status code.
type Code uint32
// OK=0, Canceled=1, Unknown=2, ... (canonical codes)

// Status represents a gRPC status.
type Status struct {
    Code    Code
    Message string
    Details []byte // google.protobuf.Any serialized
}

func Trailers(s Status) []hpack.HeaderField
```

**Verify:** Test all status codes produce correct trailers.

**Commit:** `feat(grpcserver): gRPC status trailer encoding`

---

#### C.3: Unary RPC handler

**Objective:** Handle unary gRPC calls — receive request LP message, call handler, respond with LP message + status trailer.

**Files:**
- Create: `grpcserver/unary.go`
- Create: `grpcserver/unary_test.go`

**Design:**
```go
// UnaryHandler processes a unary gRPC request.
type UnaryHandler func(ctx context.Context, req []byte) (resp []byte, err error)

// ServiceRegistrar maps method paths to handlers.
type ServiceRegistrar interface {
    RegisterService(service string, methods map[string]UnaryHandler)
}

// NewUnaryHandler adapts a ServiceRegistrar to a server.Handler.
func NewUnaryHandler(sr ServiceRegistrar) server.Handler
```

**Verify:** Test — register method, call via HTTP/2, verify LP message roundtrip.

**Commit:** `feat(grpcserver): unary RPC handler`

---

#### C.4: Server-streaming RPC

**Objective:** Handler sends multiple LP messages before final status trailer.

**Files:**
- Create: `grpcserver/stream.go`
- Create: `grpcserver/stream_test.go`

**Design:**
```go
// StreamSender sends messages on a server-streaming RPC.
type StreamSender interface {
    Send(msg []byte) error
}

// StreamHandler processes a server-streaming gRPC request.
type StreamHandler func(ctx context.Context, req []byte, send StreamSender) error
```

**Verify:** Test — stream 10 messages, verify all received, verify status trailer.

**Commit:** `feat(grpcserver): server-streaming RPC`

---

#### C.5: Client-streaming + bidirectional streaming RPC

**Objective:** Receive multiple request LP messages, optionally send multiple responses.

**Files:**
- Modify: `grpcserver/stream.go`
- Create: `grpcserver/bidi_test.go`

**Design:**
```go
// StreamReceiver receives messages from client.
type StreamReceiver interface {
    Recv() ([]byte, error) // returns io.EOF on client end-stream
}

// BidiHandler processes a bidirectional streaming RPC.
type BidiHandler func(ctx context.Context, recv StreamReceiver, send StreamSender) error
```

**Verify:** Test bidirectional echo: send 5 messages, echo each, verify all received.

**Commit:** `feat(grpcserver): client-streaming and bidirectional RPC`

---

### Phase D — Zero-allocation polish

**Goal:** Enforce bench-gate: 0 allocs/op on hot paths.

---

#### D.1: Buffer pool audit + slab allocator

**Objective:** Ensure all hot-path allocations go through sync.Pool or slab allocators.

**Files:**
- Modify: `conn/server_conn.go`
- Create: `conn/bench_test.go`

**Design:**
- `streamPool sync.Pool` for `*ServerStream` structs
- `headerSlabPool` reuse from client
- `encBufPool` for HPACK encode buffers
- Pre-allocated `[]hpack.HeaderField` slices

**Verify:** Benchmark — `go test -bench=BenchmarkServerConn -benchmem ./conn/`, verify 0 B/op, 0 allocs/op on frame path.

**Commit:** `perf(conn): zero-allocation buffer pools`

---

#### D.2: Server dispatch bench-gate

**Objective:** Verify accept → dispatch → response path is allocation-free.

**Files:**
- Create: `server/bench_test.go`

**Verify:** Benchmark — `go test -bench=BenchmarkServer -benchmem ./server/`, target < 5 allocs/op on full request path.

**Commit:** `perf(server): bench-gate for request dispatch path`

---

#### D.3: gRPC codec bench-gate

**Objective:** Verify LP message encode/decode is zero-allocation.

**Files:**
- Create: `grpcserver/bench_test.go`

**Verify:** Benchmark — 0 B/op, 0 allocs/op for EncodeLP and DecodeLP.

**Commit:** `perf(grpcserver): zero-allocation LP message codec`

---

## Phase dependency graph

```
A.1 ─→ A.2 ─→ A.3 ─→ A.4 ─→ A.5 ─→ A.6 ─→ A.7 ─→ A.8
                                                       │
                                                       ▼
                                        B.1 ─→ B.2 ─→ B.3 ─→ B.4 ─→ B.5 ─→ B.6
                                                                          │
                                                                          ▼
                                                    C.1 ─→ C.2 ─→ C.3 ─→ C.4 ─→ C.5
                                                                                    │
                                                                                    ▼
                                                              D.1 ─→ D.2 ─→ D.3
```

## Total estimate

| Phase | Tasks | Est. time |
|-------|-------|-----------|
| A — Connection layer | 8 | ~10 дней |
| B — HTTP/2 server | 6 | ~8 дней |
| C — gRPC framing | 5 | ~6 дней |
| D — Zero-alloc polish | 3 | ~4 дня |
| **Total** | **22** | **~28 дней (1 dev)** |

## Verify commands (every phase)

```bash
make test-race   # go test -race ./...
make lint        # golangci-lint run
make bench       # benchmarks
make coverage-gate  # ≥80% coverage
```
