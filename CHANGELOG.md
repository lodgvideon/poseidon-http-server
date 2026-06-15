# Changelog

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
