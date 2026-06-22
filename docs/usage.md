# Poseidon HTTP/2 Server — Production Usage Guide

A zero-allocation HTTP/2 + gRPC server for Go, built on the
[poseidon-http-client](https://github.com/lodgvideon/poseidon-http-client) codec
(frame + HPACK). This guide covers running Poseidon in production: quick start,
configuration, the middleware catalog, security hardening, observability, and
deployment.

> **API note (BREAKING in the current release):** `server.ResponseWriter` is now
> an **interface**, not a struct. Handlers receive `server.ResponseWriter` (no
> `*`), and HTTP/2 Server Push moved to the optional `server.Pusher` interface.
> See [Migration](#migration-from-the-struct-responsewriter) and `CHANGELOG.md`.

---

## Table of contents

- [Quick start](#quick-start)
- [Configuration](#configuration)
  - [`server.Options`](#serveroptions)
  - [`conn.ServerConnOptions`](#connserverconnoptions)
  - [The `poseidon-server` binary (`POSEIDON_` env vars)](#the-poseidon-server-binary-poseidon_-env-vars)
- [Middleware catalog](#middleware-catalog)
- [Security hardening](#security-hardening)
- [Observability](#observability)
- [Deployment](#deployment)
- [Migration from the struct ResponseWriter](#migration-from-the-struct-responsewriter)

---

## Quick start

### Native handler (zero-allocation path)

```go
package main

import (
	"context"
	"net"

	"github.com/lodgvideon/poseidon-http-server/server"
)

func main() {
	h := server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		return w.WriteData([]byte("hello\n")) // auto-sends 200 if no status set yet
	})

	srv, err := server.NewServer(server.Options{Handler: h})
	if err != nil {
		panic(err)
	}

	ln, _ := net.Listen("tcp", ":8080")
	_ = srv.Serve(context.Background(), ln)
}
```

The native `Handler` signature is:

```go
ServeHTTP(ctx context.Context, req *server.Request, w server.ResponseWriter) error
```

`server.ResponseWriter` embeds `http.ResponseWriter`, so handlers may use either
the native path (`WriteHeaders`/`WriteData`/`WriteTrailers`) or the stdlib path
(`Header()`/`WriteHeader()`/`Write()`).

### Drop-in `http.Handler` (chi/echo/gin)

Any `http.Handler` works via `Options.HTTPHandler`:

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
})

srv, _ := server.NewServer(server.Options{HTTPHandler: mux})
```

`server.FromHTTPHandler` and `server.ToHTTPHandler` bridge the two worlds
explicitly when you need to compose them.

### TLS + ALPN

```go
_ = srv.ListenAndServeTLS(ctx, "cert.pem", "key.pem")
```

### HTTP/2 cleartext (h2c)

```go
srv, _ := server.NewServer(server.Options{
	HTTPHandler: mux,
	H2C:         true, // accept prior-knowledge + HTTP/1.1 Upgrade
})
_ = srv.ListenAndServe(ctx)
```

### gRPC

```go
reg := grpcserver.NewServiceRegistrar()
reg.RegisterService(&grpcserver.ServiceDesc{
	Name: "my.Service",
	Methods: []grpcserver.MethodDesc{
		{Name: "Echo", UnaryHandler: echoHandler},
	},
})

srv, _ := server.NewServer(server.Options{Handler: reg.Handler()})
```

gRPC supports all four RPC patterns (unary, server-streaming, client-streaming,
bidi), gzip compression (registrar `WithCompressor` registration), the standard
`grpc.health.v1.Health` health service, and reflection (`v1alpha` + `v1`).

### Graceful drain

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

go srv.Serve(ctx, ln)
<-ctx.Done()

drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
_ = srv.Shutdown(drainCtx) // closes listener, sends GOAWAY, waits for in-flight streams
```

---

## Configuration

### `server.Options`

| Field | Type | Meaning / sentinels |
|-------|------|---------------------|
| `Addr` | `string` | Listen address for `ListenAndServe`/`ListenAndServeTLS`. |
| `Handler` | `server.Handler` | Native handler. Either this or `HTTPHandler` is required. |
| `HTTPHandler` | `http.Handler` | Stdlib handler (adapted internally). |
| `Middleware` | `[]server.Middleware` | Applied outermost-first around the resolved handler. |
| `ConnOpts` | `conn.ServerConnOptions` | Per-connection HTTP/2 knobs (see below). |
| `MaxConcurrentConnections` | `int` | `0` = unlimited; over-limit connections are accepted then closed. |
| `GracefulShutdownTimeout` | `time.Duration` | Drain budget; `<= 0` defaults to 30s. |
| `Logger` | `server.Logger` | `Printf`-style logger; `nil` uses the stdlib `log` package. |
| `H2C` | `bool` | Enable HTTP/2 cleartext (prior knowledge + HTTP/1.1 Upgrade). |
| `StreamingBody` | `bool` | When true, bodies stream via `Request.BodyReader` instead of buffering into `Request.Body`. |
| `IdleTimeout` | `time.Duration` | `0` = secure default (120s); `<0` = disabled; `>0` = explicit. Resets per stream. |
| `MaxRequestBodyBytes` | `int64` | `0` = secure default (10 MiB); `<0` = unlimited; `>0` = explicit cap. See [body limit](#request-body-size-limit). |
| `OnDrainStart` | `func()` | Invoked once at the very start of `Shutdown`, before the listener closes / GOAWAY is sent. Wire to `HealthState.SetNotReady`. |

`NewServer` validates that exactly one of `Handler`/`HTTPHandler` is set and
applies secure defaults.

### `conn.ServerConnOptions`

| Field | Type | Meaning / sentinels |
|-------|------|---------------------|
| `StreamEventBuffer` | `int` | Per-stream event channel capacity; `<= 0` defaults to 8. |
| `MaxRapidResets` | `int` | RST_STREAM flood budget. `0` = secure default (`max(MaxConcurrentStreams*4, floor)`); `<0` = disabled; `>0` = explicit. See [Rapid Reset](#http2-rapid-reset-cve-2023-44487). |
| `HandshakeTimeout` | `time.Duration` | Bounds the HTTP/2 handshake. `0` = secure default (10s); `<0` = disabled. See [Slowloris](#slowloris--handshake--idle-timeouts). |
| `AdvertisedSettings.MaxConcurrentStreams` | `uint32` | Advertised stream concurrency; defaults to 100 when unset. |

### The `poseidon-server` binary (`POSEIDON_` env vars)

`cmd/poseidon-server` is a 12-factor production binary: every knob is read from a
`POSEIDON_`-prefixed environment variable, with an optional command-line flag
override (flags win over env, which win over secure defaults). It wires a default
mux (`GET /`, health probes, `/metrics`, optional pprof) and a middleware chain
(Recovery → RequestID → StructuredAccessLog → SecurityHeaders → Metrics).

| Env var | Flag | Default | Notes |
|---------|------|---------|-------|
| `POSEIDON_ADDR` | `--addr` | `:8080` | Listen address. Must not be empty. |
| `POSEIDON_IDLE_TIMEOUT` | `--idle-timeout` | `120s` | `<0` disables. |
| `POSEIDON_SHUTDOWN_TIMEOUT` | `--shutdown-timeout` | `30s` | Graceful drain budget; must be `>= 0`. |
| `POSEIDON_HANDSHAKE_TIMEOUT` | `--handshake-timeout` | `10s` | `<0` disables. |
| `POSEIDON_MAX_CONNS` | `--max-conns` | `0` | `0` = unlimited; must be `>= 0`. |
| `POSEIDON_MAX_BODY_BYTES` | `--max-body-bytes` | `10485760` (10 MiB) | Request body cap; must be `>= 0`. |
| `POSEIDON_MAX_RAPID_RESETS` | `--max-rapid-resets` | `0` | `<0` disables mitigation; `0` = package default. |
| `POSEIDON_TLS_CERT` | `--tls-cert` | `""` | Cert and key must be set together. |
| `POSEIDON_TLS_KEY` | `--tls-key` | `""` | Setting both enables HTTPS serving. |
| `POSEIDON_H2C` | `--h2c` | `false` | Enable h2c on the plaintext port. |
| `POSEIDON_ENABLE_PPROF` | `--enable-pprof` | `false` | Exposes `/debug/pprof/`; keep off in production. |

`poseidon-server --version` prints the build metadata injected via the Makefile
`build` target (`-ldflags -X main.version/commit/date`).

```sh
POSEIDON_ADDR=":8080" POSEIDON_H2C=true ./poseidon-server
# or
./poseidon-server --addr :8080 --h2c --idle-timeout 120s
```

---

## Middleware catalog

Middleware has the signature `func(server.Handler) server.Handler`. Compose with
`server.Chain(mw...)` or pass `Options.Middleware` (applied outermost-first).
All middleware below lives in the `middleware` package.

| Middleware | Constructor | What it does |
|------------|-------------|--------------|
| **Recovery** | `Recovery(log Logger)` | Recovers panics in downstream handlers and logs them, preventing a single panic from killing the connection. |
| **RequestID** | `RequestID()` | Generates/propagates a request id, stored in context (`FromContext(ctx)`). |
| **AccessLog** | `AccessLog(log Logger)` | One `Printf`-style access-log line per request. |
| **StructuredAccessLog** | `StructuredAccessLog(*slog.Logger)` | One structured `slog` record per request: `method`, `path`, `status`, `duration_ms`, `request_id` (when set), and `bytes_written` (when the writer exposes it). Level by status class: 5xx→Error, 4xx→Warn, else Info. Emitted even on panic (recorded as 500, then re-raised). |
| **Metrics** | `NewMetricsCollector().Metrics()` | Records request counts, active in-flight gauge, and latency histograms (see [Observability](#metrics)). |
| **SecurityHeaders** | `SecurityHeaders(SecurityHeadersConfig)` | Injects HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy`, and optional CSP. `DefaultSecurityHeadersConfig()` is secure-by-default. |
| **RateLimit** | `RateLimit(RateLimitConfig)` | Token-bucket limiter; short-circuits with **429** when a bucket is empty. Keyed by `cfg.Key(ctx, req)` (single global bucket by default); use `KeyByClientIP()` to bucket per RealIP-resolved client IP (place `RealIP` earlier in the chain). `Rate` (req/s, default 100) + `Burst` (default `max(1, Rate)`). |
| **RealIP** | `RealIP(RealIPConfig)` | Resolves the client IP from `X-Forwarded-For`/`X-Real-IP` **only** when the immediate peer is in `TrustedProxies` (CIDRs/bare IPs). Secure default: trusts nothing. Retrieve with `ClientIP(ctx)`. |
| **Gzip** | `Gzip(GzipConfig)` | Compresses response bodies when the client sends `Accept-Encoding: gzip` and the body exceeds `MinSize` (default 512B). `Level` 1–9 (default 5). Adds `Content-Encoding: gzip`, drops `Content-Length`. |
| **CORS** | `CORS(CORSConfig)` | Cross-origin headers; `DefaultCORSConfig()` provided. |
| **Tracing** | `Tracing(TracingConfig)` | Starts a span per request via a vendor-neutral `Tracer`/`Span` interface (plug in OpenTelemetry without this package depending on it). `nil` Tracer = zero-overhead pass-through. |

Example chain (matching what `cmd/poseidon-server` builds):

```go
metrics := middleware.NewMetricsCollector()
chain := server.Chain(
	middleware.Recovery(logger),
	middleware.RequestID(),
	middleware.StructuredAccessLog(slogLogger),
	middleware.SecurityHeaders(middleware.DefaultSecurityHeadersConfig()),
	metrics.Metrics(),
)
srv, _ := server.NewServer(server.Options{Handler: chain(myHandler)})
```

> Middleware that needs to inspect or rewrite the **response body** (Gzip,
> SecurityHeaders) works by *wrapping* the `ResponseWriter` interface — the
> canonical Go pattern, now possible because `ResponseWriter` is an interface.

---

## Security hardening

Poseidon is **secure by default**: the timeouts, body cap, and Rapid Reset
mitigation are all active unless you explicitly disable them.

### HTTP/2 Rapid Reset (CVE-2023-44487)

A malicious client can open and immediately `RST_STREAM` a flood of streams to
exhaust server work without ever hitting the concurrency limit. The conn layer
bounds client-initiated RST_STREAM with a per-connection budget
(`max(MaxConcurrentStreams*4, floor)`). Exceeding it tears the connection down
with `GOAWAY(ENHANCE_YOUR_CALM)`. The mechanism is lock-free and zero-alloc.

Configure via `conn.ServerConnOptions.MaxRapidResets`
(`server.Options.ConnOpts`) or `POSEIDON_MAX_RAPID_RESETS`:
`0` = secure default, `<0` = disabled, `>0` = explicit budget. **Leave it at the
default** to keep the mitigation on.

### Request body-size limit

`Options.MaxRequestBodyBytes` (or `POSEIDON_MAX_BODY_BYTES`) caps inbound body
size to bound memory and defend against memory-exhaustion DoS via large uploads.
It is enforced in **both** modes:

- **Buffered:** accumulation stops and the request is rejected with **413
  Request Entity Too Large** the moment the cap is exceeded — memory never
  balloons past the cap.
- **Streaming:** `BodyReader` returns `ErrBodyTooLarge` once total bytes read
  exceed the cap.

`0` = secure default (10 MiB), `<0` = unlimited, `>0` = explicit.

### Slowloris / handshake / idle timeouts

- **`HandshakeTimeout`** (`conn`, default 10s) bounds the time to complete the
  HTTP/2 handshake, defeating clients that open a socket and stall.
- **`IdleTimeout`** (`server`, default 120s) closes connections with no
  request/stream activity. Active streams reset the clock; `<0` disables.

### TLS

Use `ListenAndServeTLS(ctx, cert, key)` (or set `POSEIDON_TLS_CERT` +
`POSEIDON_TLS_KEY` together — the binary refuses one without the other). TLS
negotiates HTTP/2 via ALPN. Over plaintext/h2c, HSTS is meaningless; the binary
drops the HSTS header automatically when TLS is not configured.

### Security headers

`SecurityHeaders(DefaultSecurityHeadersConfig())` sends HSTS (1 year,
includeSubDomains), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
and `Referrer-Policy: no-referrer`. CSP is opt-in (a wrong policy breaks pages),
set via `ContentSecurityPolicy`.

---

## Observability

### Metrics

`MetricsCollector` exposes Prometheus exposition text via `MetricsHandler()`
(the binary mounts it at `GET /metrics`). Emitted series:

| Metric | Type | Labels |
|--------|------|--------|
| `poseidon_requests_total` | counter | `method`, `path`, `status` |
| `poseidon_request_duration_seconds` | histogram | `method`, `path` (buckets 5ms…10s + `+Inf`) |
| `poseidon_request_duration_seconds_total` | counter | `method`, `path` |
| `poseidon_active_requests` | gauge | — |

The histogram `observe` path is allocation-free (binary-searched bucket index,
atomic updates).

### Health probes

`HealthHandler(HealthState)` serves two **distinct** probes (mounted by the
binary):

- **`GET /healthz`** (liveness): 200 while the process serves, *even during
  drain*. A failing liveness probe restarts the pod, so it must not depend on
  drain state.
- **`GET /readyz`** (readiness): 200 when ready, **503** once draining begins. A
  failing readiness probe removes the pod from Service endpoints *without* a
  restart — exactly what you want at the start of graceful shutdown.

Wire `HealthState.SetNotReady` into `Options.OnDrainStart` so Kubernetes stops
routing new traffic before in-flight streams drain. A fresh `HealthState` is
ready by default.

### pprof

`server.PprofHandler()` exposes `/debug/pprof/`. It is **opt-in** (`--enable-pprof`
/ `POSEIDON_ENABLE_PPROF=true`) because it surfaces runtime internals — keep it
off in production or restrict access (e.g. NetworkPolicy). The binary logs a
warning when it is enabled.

### Tracing

The `Tracing` middleware starts a span per request (`"<method> <path>"`) carrying
`http.method`, `http.path`, and `http.status_code` (OpenTelemetry-aligned
attribute keys). The `Tracer`/`Span` interfaces are vendor-neutral: provide an
OpenTelemetry adapter in your own code (no otel dependency leaks into Poseidon).
A `nil` Tracer is a zero-overhead pass-through.

### Structured logs

`StructuredAccessLog(*slog.Logger)` emits one structured record per request (see
the [middleware catalog](#middleware-catalog)). The binary configures a JSON
`slog` handler at `info` level on stderr.

---

## Deployment

### Docker

A multi-stage `Dockerfile` builds a static binary into a **distroless nonroot**
image (uid 65532). Build metadata is injected via `-ldflags`.

```sh
docker build -t poseidon-server:local .
docker run --rm -p 8080:8080 -e POSEIDON_H2C=true poseidon-server:local
```

The image runs as nonroot with a read-only root filesystem in the k8s manifests;
mount an `emptyDir` at `/tmp` if scratch space is needed.

### Helm

A production-grade chart lives at `deploy/helm/poseidon-server` with secure
defaults: 3 replicas, HPA (3–10 on 70% CPU), PodDisruptionBudget, the
"restricted" Pod Security Standard (`runAsNonRoot`, `readOnlyRootFilesystem`,
all capabilities dropped, `seccompProfile: RuntimeDefault`), and Prometheus
scrape annotations (`/metrics` on port 8080).

```sh
helm install poseidon deploy/helm/poseidon-server \
  --set image.tag=<immutable-tag> \
  --set config.POSEIDON_H2C=true
```

Application config is rendered into a ConfigMap as `POSEIDON_`-prefixed env vars.
`terminationGracePeriodSeconds` (40s) is kept `>= POSEIDON_SHUTDOWN_TIMEOUT`
(30s) so the server finishes its graceful drain before SIGKILL.

### Raw Kubernetes manifests

Helm-free manifests in `deploy/k8s/` (`kubectl apply -f deploy/k8s/`) mirror the
chart's secure defaults.

### Probe caveat (h2c) — read this

The server speaks **HTTP/2 cleartext (h2c)** on port 8080, serving `/healthz`
and `/readyz` over that same h2c listener. Kubernetes `httpGet` probes speak
**HTTP/1.1** and will **not** complete an h2c handshake — a naive `httpGet`
probe fails against a perfectly healthy pod.

The manifests and chart therefore default to **`tcpSocket`** probes (a successful
TCP accept proves the listener is up). This is h2c-safe but not
readiness-aware (it cannot observe `/readyz` returning 503 during drain — the
server's own graceful drain via `OnDrainStart` + `GracefulShutdownTimeout`
covers that). The codebase implements `grpc.health.v1`
(`grpcserver/health.go`); once the binary exposes a gRPC health listener you can
switch to k8s native **`grpc:`** probes (GA in 1.27+) for readiness-aware health.
`httpGet` is intentionally unsupported to prevent the h2c-handshake foot-gun.

---

## Migration from the struct `ResponseWriter`

`server.ResponseWriter` changed from a concrete **struct** to an **interface**.

1. **Handler signature** — drop the pointer:

   ```go
   // before
   func(ctx context.Context, req *server.Request, w *server.ResponseWriter) error
   // after
   func(ctx context.Context, req *server.Request, w server.ResponseWriter) error
   ```

   All method names are unchanged (`WriteHeaders`, `WriteData`, `WriteTrailers`,
   `Header`, `WriteHeader`, `Write`, `Status`, `Written`).

2. **Server Push** — Push moved to the optional `server.Pusher` interface
   (mirroring `net/http.Pusher`). Type-assert before pushing:

   ```go
   if p, ok := w.(server.Pusher); ok {
       _, _ = p.Push("/style.css", nil)
   }
   ```

   The concrete writer still implements both `ResponseWriter` and `Pusher`.

3. **Why** — an interface lets middleware intercept the response by wrapping the
   writer (embedding it and overriding write methods). This is how the **Gzip**
   middleware now actually compresses (the previous struct-based Gzip silently
   bypassed compression), and how `SecurityHeaders` injects headers.

Construct a writer for tests via `server.NewResponseWriter(stream)`.
