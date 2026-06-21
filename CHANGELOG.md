# Changelog

## [Unreleased]

### Security

- **HTTP/2 Rapid Reset mitigation (CVE-2023-44487).** The conn layer now bounds
  client-initiated RST_STREAM floods with a per-connection budget
  (`max(MaxConcurrentStreams*4, 100)`); exceeding it tears the connection down
  with `GOAWAY(ENHANCE_YOUR_CALM)`. Configurable via
  `ServerConnOptions.MaxRapidResets` (0 = secure default, <0 = disabled,
  >0 = explicit), surfaced through `server.Options.ConnOpts`. Lock-free/zero-alloc.

### Changed (BREAKING)

- **`server.ResponseWriter` is now an interface**, not a concrete struct. The
  `Handler`/`HandlerFunc` signature changed from `*server.ResponseWriter` to
  `server.ResponseWriter`. Migration: drop the `*` — all method names are
  unchanged. This lets middleware intercept the response body by wrapping the
  writer (the canonical Go middleware pattern).
- **Server Push moved to the optional `server.Pusher` interface** (mirroring
  `net/http.Pusher`/`Flusher`/`Hijacker`). Handlers that push now type-assert:
  `if p, ok := w.(server.Pusher); ok { p.Push(...) }`. The concrete writer still
  implements both interfaces.

### Fixed

- **Gzip middleware now actually compresses.** Previously `Gzip()` wrapped the
  writer but passed the *original* writer to the handler, so the body bypassed
  the gzip buffer entirely and nothing was ever compressed. It now buffers the
  response, sets `Content-Encoding: gzip` (and drops `Content-Length`) when the
  body exceeds `MinSize` and the client sent `Accept-Encoding: gzip`, and emits
  the compressed body. Covered by a new end-to-end test (real server + raw H2
  client) asserting `Content-Encoding: gzip` and a clean decompression round-trip.

## [v0.3.0] — 2026-06-15

Zero-allocation HTTP/2 + gRPC server for Go.

### Added

- **Server Push (RFC 7540 §8.2)** — `ResponseWriter.Push` + `PushWithScheme` for
  PUSH_PROMISE on h2 and h2c. Conn-layer `ServerStream.Push` for low-level use.
- **Priority hints in HEADERS (RFC 7540 §5.3)** — server captures the request
  priority payload in `ServerStream.Priority()` and re-emits it in the
  first response HEADERS via `SendHeadersWithPriority`. `PushWithPriority`
  propagates the priority onto the push stream.
- **:path split** — `Request.Path` is now raw back-compat; `Request.RawQuery`
  carries the query string separately. `Push` :scheme is derived from the
  originating request scheme (h2c → "http", h2 → "https").
- **Graceful drain** — `Shutdown(ctx)` waits for in-flight streams and sends
  GOAWAY. Already shipped in v0.2.0, hardened in v0.3.0.
- **gRPC compression** (gzip) — `WithCompressor` registration on the service
  registrar.
- **Prometheus middleware** — request count + duration histograms per path.
- **gRPC health check + reflection (v1alpha + v1)** — standard
  `grpc.health.v1.Health` and `grpc.reflection.v1alpha.ServerReflection`.

### Fixed

- HEADERS frames lost during handshake.
- Response headers now lower-cased (matches `http.ResponseWriter`).
- Push :scheme no longer hard-codes "https"; uses request scheme.
- TestE2E_011 TODO closed; chi-style drop-in example saved.

### Quality

- Conn + server + grpcserver: race-clean.
- golangci-lint clean.
- 0 allocs/op on `writeServerHeaders` benchmark.
- 6 new conn tests + 3 new server tests for priority handling.
