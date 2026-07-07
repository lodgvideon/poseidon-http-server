# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.3](https://github.com/lodgvideon/poseidon-http-server/compare/v0.4.2...v0.4.3) (2026-07-07)


### Dependencies

* bump poseidon-http-client v0.6.0 → v0.7.0 ([#28](https://github.com/lodgvideon/poseidon-http-server/issues/28)) ([c0b5a11](https://github.com/lodgvideon/poseidon-http-server/commit/c0b5a11c5e5e05b893e231b6579f18caf816a2b9))

## [0.4.2](https://github.com/lodgvideon/poseidon-http-server/compare/v0.4.1...v0.4.2) (2026-07-06)


### Bug Fixes

* make the module go-gettable — pin client to v0.6.0, drop local replace ([#25](https://github.com/lodgvideon/poseidon-http-server/issues/25)) ([e1c739a](https://github.com/lodgvideon/poseidon-http-server/commit/e1c739a850a3798f50a523e44bb26464a498079f))

## [0.4.1](https://github.com/lodgvideon/poseidon-http-server/compare/v0.4.0...v0.4.1) (2026-06-23)


### Bug Fixes

* drop release-please component so merged release PRs can be tagged ([#21](https://github.com/lodgvideon/poseidon-http-server/issues/21)) ([2168363](https://github.com/lodgvideon/poseidon-http-server/commit/2168363e6de9f3c768e21d02044a58fd482d6364))
* restore component-carrying release-please title pattern ([#22](https://github.com/lodgvideon/poseidon-http-server/issues/22)) ([8c7ea50](https://github.com/lodgvideon/poseidon-http-server/commit/8c7ea50a6a4857cde94ddbc2d194c6b8fa729e48))

## [0.4.0](https://github.com/lodgvideon/poseidon-http-server/compare/v0.3.0...v0.4.0) (2026-06-23)


### ⚠ BREAKING CHANGES

* ResponseWriter interface (fixes Gzip) + HTTP/2 Rapid Reset mitigation ([#1](https://github.com/lodgvideon/poseidon-http-server/issues/1))

### Features

* **metrics:** surface HTTP/2 transport metrics (conns, bytes, frames, streams, rapid-resets, GOAWAYs) ([#12](https://github.com/lodgvideon/poseidon-http-server/issues/12)) ([1c05177](https://github.com/lodgvideon/poseidon-http-server/commit/1c05177235ea3ed040368bb53c180ea7f3413637))
* **middleware:** bound RateLimit bucket map with eviction (memory-DoS fix) ([#13](https://github.com/lodgvideon/poseidon-http-server/issues/13)) ([6f5eab1](https://github.com/lodgvideon/poseidon-http-server/commit/6f5eab1db016b5491115837252288b8f8431fdf0))
* **middleware:** per-client rate-limit keying + gzip decompression-bomb bound ([#11](https://github.com/lodgvideon/poseidon-http-server/issues/11)) ([4b443b5](https://github.com/lodgvideon/poseidon-http-server/commit/4b443b5a9dabc23e58ad6df114740f16aedc8b1d))
* production-readiness hardening + ResponseWriter interface completion ([#3](https://github.com/lodgvideon/poseidon-http-server/issues/3)) ([2b01ef5](https://github.com/lodgvideon/poseidon-http-server/commit/2b01ef5d1f3db8f5e7910bb370a8c312fe93550f))
* ResponseWriter interface (fixes Gzip) + HTTP/2 Rapid Reset mitigation ([#1](https://github.com/lodgvideon/poseidon-http-server/issues/1)) ([161754b](https://github.com/lodgvideon/poseidon-http-server/commit/161754b944342f4c33ef98a5b913b6229883c51d))


### Bug Fixes

* **grpcserver:** close two health-Watch concurrency bugs (lost update + send-on-closed panic) ([#15](https://github.com/lodgvideon/poseidon-http-server/issues/15)) ([bfdd7ff](https://github.com/lodgvideon/poseidon-http-server/commit/bfdd7fff4435f5251c5c551a773c9491dbe7c195))
* **server,conn:** unblock Serve on Close (bg ctx) + per-stream recv window seeded from advertised window ([#17](https://github.com/lodgvideon/poseidon-http-server/issues/17)) ([e7d878f](https://github.com/lodgvideon/poseidon-http-server/commit/e7d878fd4ba4b22b64715d584d8a43e45f616e6c))
* **server:** forward request body in HTTPRequestToRequest / ToHTTPHandler ([#19](https://github.com/lodgvideon/poseidon-http-server/issues/19)) ([83f234d](https://github.com/lodgvideon/poseidon-http-server/commit/83f234df8bc2e56508c91c29cf0509875feff4b2))
* **server:** wire streaming Request.BodyReader into FromHTTPHandler requests ([#18](https://github.com/lodgvideon/poseidon-http-server/issues/18)) ([a3eaa8e](https://github.com/lodgvideon/poseidon-http-server/commit/a3eaa8e86058a81e7ff78bdda5c7567eac1deb13))

## [Unreleased]

This release hardens Poseidon for production: DoS mitigations, a security/
observability middleware suite, a 12-factor server binary, and container/
Kubernetes deployment assets. It includes a few **breaking** API changes — see
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
  (single global bucket by default). `KeyByClientIP()` buckets per RealIP-resolved
  client IP (the `Key` func receives the request `context.Context` — see Changed).
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
- **HTTP/2 transport metrics.** `(*server.Server).TransportStats()` aggregates
  per-connection counters (`conn.ConnStats`, now including `RapidResets` and
  `GoAwaySent`) across live and closed connections, keeping the byte/frame/stream
  counters monotonic while `ActiveConns` stays a gauge. Wire it into exposition
  with `(*middleware.MetricsCollector).SetTransportSource(srv.TransportStats)` to
  emit `poseidon_connections_active`, `poseidon_bytes_{sent,received}_total`,
  `poseidon_frames_{sent,received}_total`, `poseidon_streams_accepted_total`,
  `poseidon_rapid_resets_total`, and `poseidon_goaways_sent_total` at `/metrics`
  (the `poseidon-server` binary wires this automatically). Byte counts are tallied
  at the framer/transport boundary; `poseidon_request_bytes_total` is now exposed
  too.
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
- **`ResponseWriter` capability finders.** `server.PusherOf(w)` / `server.FlusherOf(w)`
  return the optional `Pusher` / `http.Flusher` capability, walking an
  `Unwrap() server.ResponseWriter` chain (cycle-guarded) so middleware can wrap the
  writer without re-implementing forwarders — the `net/http.ResponseController` model.
  The concrete writer and the Gzip wrapper now implement `http.Flusher`.

### Changed

- **BREAKING — `server.ResponseWriter` is now an interface**, not a concrete
  struct. The `Handler`/`HandlerFunc` signature changed from
  `*server.ResponseWriter` to `server.ResponseWriter`. Construct test writers via
  `server.NewResponseWriter(stream)`. See [Migration](#migration).
- **BREAKING — Server Push moved to the optional `server.Pusher` interface**
  (mirroring `net/http.Pusher`/`Flusher`/`Hijacker`). Reach it through any
  middleware wrappers via `server.PusherOf(w)`; a direct (unwrapped) writer still
  satisfies `w.(server.Pusher)`. Middleware wrappers now expose `Unwrap()` instead
  of re-implementing the three Push methods.
- **BREAKING — `RateLimitConfig.Key` now takes the request context**:
  `func(*server.Request) string` → `func(context.Context, *server.Request) string`.
  This lets a key function read values injected by upstream middleware — most
  importantly the RealIP-resolved client IP — enabling the new
  `KeyByClientIP()` keyer. See [Migration](#migration).
- **`middleware.DecompressBody` now bounds output** at `DefaultMaxDecompressedSize`
  (10 MiB) to mitigate decompression bombs; reading past the cap returns the new
  `ErrBodyTooLarge`. `DecompressBodyLimit(body, maxBytes)` chooses a different cap
  (`maxBytes <= 0` opts out). Behavior change for callers that previously relied on
  unbounded decompression — switch to `DecompressBodyLimit(body, 0)`.

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
- **`ToHTTPHandler` no longer discards the response body.** It previously ran the
  handler against a discard writer and copied only status+headers; it now buffers
  status, headers, and body and replays them onto the `http.ResponseWriter`.

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
- **Decompression-bomb bound on `middleware.DecompressBody`.** A gzipped request
  body that inflates beyond `DefaultMaxDecompressedSize` (10 MiB) now fails with
  `ErrBodyTooLarge` instead of streaming unbounded data into memory. The reader
  caps emitted bytes at the limit and probes one byte past it (rather than using
  `io.LimitReader`, which would silently truncate and mask the attack). Tune via
  `DecompressBodyLimit`. Also closes the underlying source body on `Close()`.
- **Per-client rate limiting via `KeyByClientIP()`.** Buckets the token-bucket
  limiter by the RealIP-resolved client IP; fail-closed (unresolved IP → shared
  bucket) so unidentifiable traffic is throttled rather than exempt.
- **Bounded rate-limiter memory (eviction).** The token-bucket limiter no longer
  grows its per-key bucket map without limit — closing a memory-exhaustion DoS
  reachable via `KeyByClientIP()` (an attacker streaming distinct source IPs,
  trivial over IPv6). It now caps the map at `RateLimitConfig.MaxBuckets`
  (default `DefaultMaxBuckets` = 65536, evicting the oldest bucket via an O(1)
  intrusive list — no scan a flood could amplify into CPU load) and
  opportunistically evicts buckets idle past `BucketIdleTTL` (default
  `max(10m, refill-to-full)`, so an evicted idle bucket has always refilled to
  full and its eviction is loss-free). Both follow the `0 = secure default,
  <0 = disabled, >0 = explicit` convention. The cap is **on by default**: a
  caller wanting the old unbounded behaviour sets `MaxBuckets: -1`. An evicted
  key gets a fresh full bucket on its next request — identical to a first-seen
  key, so eviction grants an attacker no extra capacity.

### Migration

The struct→interface change to `server.ResponseWriter` requires source updates:

1. **Handler signature** — drop the pointer:
   `func(ctx, req, w *server.ResponseWriter)` → `func(ctx, req, w server.ResponseWriter)`.
   All method names are unchanged.
2. **Server Push** — use the capability finder so it works through middleware:
   `if p, ok := server.PusherOf(w); ok { _, _ = p.Push("/style.css", nil) }`.
   A direct (unwrapped) writer still supports `w.(server.Pusher)`.
3. **RateLimit `Key`** — add the leading `context.Context` parameter:
   `func(req *server.Request) string` → `func(ctx context.Context, req *server.Request) string`.
   To key per client IP, replace your custom keyer with `middleware.KeyByClientIP()`
   and ensure `RealIP` runs earlier in the chain.
4. **Why** — an interface lets middleware intercept the response by wrapping the
   writer (embedding + overriding write methods). This is how Gzip now actually
   compresses and how `SecurityHeaders` injects headers. Threading `ctx` into the
   rate-limit key lets it read state (the resolved client IP) that upstream
   middleware put in the context.

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
