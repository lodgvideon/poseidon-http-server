# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release hardens Poseidon for production: DoS mitigations, a security/
observability middleware suite, a 12-factor server binary, and container/
Kubernetes deployment assets. It includes one **breaking** API change — see
[Migration](#migration) below.

### Added

- **`poseidon-server` binary (`cmd/poseidon-server`).** 12-factor, secure-by-default
  server: every knob is read from a `POSEIDON_`-prefixed env var with an optional
  flag override, validated before start. Wires a default mux (`GET /`, health
  probes, `/metrics`, opt-in pprof) and a middleware chain (Recovery → RequestID
  → StructuredAccessLog → SecurityHeaders → Metrics), graceful drain on
  SIGINT/SIGTERM, and `--version` build metadata via `-ldflags`. Added a Makefile
  `build` target.
- **`SecurityHeaders` middleware.** Injects HSTS, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options`, `Referrer-Policy`, and an opt-in CSP.
  `DefaultSecurityHeadersConfig()` is secure-by-default (HSTS 1y + includeSubDomains,
  nosniff, `DENY`, `no-referrer`).
- **`RateLimit` middleware.** Self-contained token-bucket limiter; short-circuits
  with `429 Too Many Requests`. Configurable `Rate`/`Burst` and a `Key` function
  (single global bucket by default).
- **`RealIP` middleware.** Resolves the client IP from `X-Forwarded-For`/`X-Real-IP`
  **only** when the immediate peer is in a configured `TrustedProxies` CIDR set
  (secure default: trusts nothing). Exposed via `ClientIP(ctx)`;
  `WithPeerAddr`/`PeerAddr` populate the peer address.
- **`StructuredAccessLog` middleware (`log/slog`).** One structured record per
  request (`method`, `path`, `status`, `duration_ms`, `request_id`,
  `bytes_written`), with level chosen by status class. Additive — does not replace
  the existing Printf-style `AccessLog`. Includes `LoggerFromSlog` adapter.
- **`Tracing` middleware.** Vendor-neutral `Tracer`/`Span` hooks (OpenTelemetry
  semantic-convention attribute keys) with a zero-overhead pass-through when no
  Tracer is set — no otel dependency taken on.
- **Request-duration latency histograms** on `MetricsCollector`
  (`poseidon_request_duration_seconds`, Prometheus default buckets 5ms…10s),
  plus `poseidon_active_requests` gauge. Allocation-free `observe` hot path.
- **HTTP health endpoints.** `HealthHandler`/`HealthState` serve `/healthz`
  (liveness, 200 while serving) and `/readyz` (readiness, 503 while draining).
  `OnDrainStart` hook flips readiness to NOT-ready at the start of `Shutdown`.
- **Opt-in pprof handler.** `server.PprofHandler()` exposes `/debug/pprof/`
  (off by default; logs a warning when enabled).
- **Production `Dockerfile` + `.dockerignore`.** Multi-stage, static binary,
  distroless **nonroot** image.
- **Helm chart + raw k8s manifests** (`deploy/helm`, `deploy/k8s`). Secure defaults:
  HPA, PodDisruptionBudget, the "restricted" Pod Security Standard, Prometheus
  scrape annotations, and **`tcpSocket` probes** (h2c-safe; `httpGet` is
  deliberately unsupported to avoid the h2c-handshake foot-gun).
- **CI/release tooling.** Security-scanning workflow + Dependabot; release
  pipeline via release-please; native fuzz targets for binary-protocol surfaces;
  load/soak harness (`make loadtest`: h2load/ghz/k6); transport + conn frame-edge
  integration tests.

### Changed

- **BREAKING — `server.ResponseWriter` is now an interface**, not a concrete
  struct. The `Handler`/`HandlerFunc` signature changed from
  `*server.ResponseWriter` to `server.ResponseWriter`. Construct test writers via
  `server.NewResponseWriter(stream)`. See [Migration](#migration).
- **BREAKING — Server Push moved to the optional `server.Pusher` interface**
  (mirroring `net/http.Pusher`/`Flusher`/`Hijacker`). Handlers type-assert:
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
- **gRPC `maxRecvMessageSize` is now enforced in `DecodeLPFromBytes`** (found by
  fuzzing) — oversized length-prefixed messages are rejected instead of being
  decoded.

### Security

- **HTTP/2 Rapid Reset mitigation (CVE-2023-44487).** The conn layer now bounds
  client-initiated RST_STREAM floods with a per-connection budget
  (`max(MaxConcurrentStreams*4, floor)`); exceeding it tears the connection down
  with `GOAWAY(ENHANCE_YOUR_CALM)`. Configurable via
  `ServerConnOptions.MaxRapidResets` (0 = secure default, <0 = disabled,
  >0 = explicit), surfaced through `server.Options.ConnOpts`. Lock-free/zero-alloc.
- **Request body-size limit (`MaxRequestBodyBytes`).** Caps inbound bodies (secure
  default 10 MiB) in both buffered mode (rejects with `413` before memory
  balloons) and streaming mode (`BodyReader` returns `ErrBodyTooLarge`). `<0`
  disables.
- **Slowloris / DoS timeouts.** `HandshakeTimeout` (conn, default 10s) bounds the
  HTTP/2 handshake; `IdleTimeout` (server, default 120s) closes idle connections.
  Both treat `<0` as "disabled".

### Migration

The struct→interface change to `server.ResponseWriter` requires source updates:

1. **Handler signature** — drop the pointer:
   `func(ctx, req, w *server.ResponseWriter)` → `func(ctx, req, w server.ResponseWriter)`.
   All method names are unchanged.
2. **Server Push** — type-assert to the new optional interface:
   `if p, ok := w.(server.Pusher); ok { _, _ = p.Push("/style.css", nil) }`.
3. **Why** — an interface lets middleware intercept the response by wrapping the
   writer (embedding + overriding write methods). This is how Gzip now actually
   compresses and how `SecurityHeaders` injects headers.

See `docs/usage.md` for the full production usage guide.

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
