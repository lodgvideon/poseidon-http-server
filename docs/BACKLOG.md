# Backlog

Feature-level user stories for poseidon-http-server, from a walk of the tree on
**2026-08-15**. Every claim here that carries a number was measured on this
machine (windows/amd64, AMD Ryzen 7 7700, Go 1.25) with a throwaway probe, not
estimated; the probe command is quoted with the story so it can be re-run.

Every story is tracked as a GitHub issue; this document is the reasoning and the
evidence behind them, the issues are where the work happens.

| # | Story | Theme | Pri | Size |
|---|---|---|---|---|
| [#68](https://github.com/lodgvideon/poseidon-http-server/issues/68) | PB-01 Bound metric label cardinality (**defect**) | Observability | P0 | M |
| [#69](https://github.com/lodgvideon/poseidon-http-server/issues/69) | PB-02 Middleware under the allocation contract | Observability | P0 | M |
| [#70](https://github.com/lodgvideon/poseidon-http-server/issues/70) | PB-03 Propagate W3C trace context | Observability | P0 | M |
| [#71](https://github.com/lodgvideon/poseidon-http-server/issues/71) | PB-04 Runtime and process metrics | Observability | P1 | S |
| [#72](https://github.com/lodgvideon/poseidon-http-server/issues/72) | PB-05 Expose HTTP/2 internals | Observability | P1 | M |
| [#73](https://github.com/lodgvideon/poseidon-http-server/issues/73) | PB-06 Observability for the HTTP/3 path | Observability | P1 | M |
| [#74](https://github.com/lodgvideon/poseidon-http-server/issues/74) | PB-07 OpenTelemetry adapter module | Observability | P2 | M |
| [#75](https://github.com/lodgvideon/poseidon-http-server/issues/75) | PB-08 Serve HTTP/1.1 | Flexibility | P1 | L |
| [#76](https://github.com/lodgvideon/poseidon-http-server/issues/76) | PB-09 Request deadlines | Flexibility | P1 | S |
| [#77](https://github.com/lodgvideon/poseidon-http-server/issues/77) | PB-10 TLS rotation, SNI, mTLS | Flexibility | P1 | M |
| [#78](https://github.com/lodgvideon/poseidon-http-server/issues/78) | PB-11 Connection and stream lifecycle hooks | Flexibility | P1 | S |
| [#79](https://github.com/lodgvideon/poseidon-http-server/issues/79) | PB-12 gRPC message compression | Flexibility | P1 | M |
| [#80](https://github.com/lodgvideon/poseidon-http-server/issues/80) | PB-13 HTTP/3 lifecycle parity | Flexibility | P1 | M |
| [#81](https://github.com/lodgvideon/poseidon-http-server/issues/81) | PB-14 Load shedding and admission control | Flexibility | P2 | M |
| [#82](https://github.com/lodgvideon/poseidon-http-server/issues/82) | PB-15 Authentication middleware | Flexibility | P2 | M |
| [#83](https://github.com/lodgvideon/poseidon-http-server/issues/83) | PB-16 Compression beyond gzip | Flexibility | P2 | M |
| [#84](https://github.com/lodgvideon/poseidon-http-server/issues/84) | PB-17 gRPC interceptors and codegen | Flexibility | P2 | L |
| [#85](https://github.com/lodgvideon/poseidon-http-server/issues/85) | PB-18 Listener and socket tuning | Flexibility | P2 | S |
| [#86](https://github.com/lodgvideon/poseidon-http-server/issues/86) | PB-19 Binary configuration surface | Flexibility | P2 | S |
| [#87](https://github.com/lodgvideon/poseidon-http-server/issues/87) | `RealIP` dead in production (**defect**) | gRPC lane | P0 | S |
| [#94](https://github.com/lodgvideon/poseidon-http-server/issues/94) | Interop cert + head-to-head vs grpc-go | gRPC lane | P0 | M |
| [#95](https://github.com/lodgvideon/poseidon-http-server/issues/95) | Make lock contention visible | gRPC lane | P0 | S |
| [#90](https://github.com/lodgvideon/poseidon-http-server/issues/90) | Peer identity on the request context | gRPC lane | P0 | S |
| [#88](https://github.com/lodgvideon/poseidon-http-server/issues/88) | gRPC metadata | gRPC lane | P1 | M |
| [#89](https://github.com/lodgvideon/poseidon-http-server/issues/89) | Rich error details | gRPC lane | P1 | S |
| [#92](https://github.com/lodgvideon/poseidon-http-server/issues/92) | Call outcome + per-RPC tap | gRPC lane | P1 | M |
| [#91](https://github.com/lodgvideon/poseidon-http-server/issues/91) | MaxConnectionAge + Grace | gRPC lane | P1 | S |
| [#93](https://github.com/lodgvideon/poseidon-http-server/issues/93) | BDP / dynamic windows | gRPC lane | P1 | M–L |
| [#96](https://github.com/lodgvideon/poseidon-http-server/issues/96) | Keepalive enforcement policy | gRPC lane | P2 | S |

## How to read a story

Each story carries a **Proved by** line naming the gate that will show the work
landed — `make bench-gate`, `make coverage-gate`, `make conformance-gate`,
`make test-race`, `make loadtest`, or an explicit *"new gate"* when none of the
existing ones can see it. A story with no gate is a story that can silently rot,
so the gate is part of the definition of done, not a nicety. Sizes are S (≤1 day),
M (2–4 days), L (a week or more).

## What this backlog is *not*

Transport-level performance — write amplification, receive-path allocations,
O(N) flow-control wakeups, reactor-mode reads — is **already owned by
[#59](https://github.com/lodgvideon/poseidon-http-server/issues/59)**, which has
a measured baseline and a landing order. Nothing here duplicates it. This walk
independently re-measured #59's central finding and it holds: a minimal
`HEADERS` + `DATA(END_STREAM)` response costs **3 `Write` calls** at the
`io.Writer` level (HEADERS coalesces into 1; every DATA frame costs 2, header
then payload), because `frame.Framer` writes straight to the `net.Conn` with no
buffering — `conn/server_conn.go:646`.

The broken bench gate is [#66](https://github.com/lodgvideon/poseidon-http-server/issues/66).
Several stories below say "proved by `make bench-gate`"; #66 is a prerequisite
for all of them.

## Where the project actually stands

**Strong, and unusually so:** the zero-allocation contract on the native write
path is real and gated (ADR-0001). RFC conformance is not a claim but a CI gate
with a coverage matrix behind it (`docs/RFC_COVERAGE.md`, 24 closed MUST-level
obligations). Rapid Reset, slowloris, decompression bombs, and body-size
exhaustion all have named mitigations. The stream state machine is one value with
an ADR (ADR-0009) rather than 56 re-derivations. Fuzz targets run nightly.

**The gap between the README and a production deployment** is not in the
transport. It is that the two properties the project advertises alongside
performance — *observability* and *flexibility out of the box* — stop at the
edge of `conn/`. The metrics middleware every deployment enables allocates 5
times per request and grows its heap without bound on untrusted input. The
tracing middleware cannot join a distributed trace. The server cannot answer an
HTTP/1.1 client. There is no request deadline, no certificate rotation, no
authentication, and no lifecycle hook to build any of it yourself.

That is the shape of this backlog: the core is fast, and everything wrapped
around the core is where the work is.

---

## The gRPC lane — decisions from the 2026-08-15 review

A second review asked a narrower question: what would it take to displace
grpc-go as the RPC server inside a large engineering organisation. It produced
eight decisions, recorded here because each one *removes* work as well as adding
it, and a backlog that only records additions drifts.

1. **Target.** A specialist server for the hot tail first, sold on a benchmark;
   wire compatibility with grpc-go as the destination. A `grpc.ServiceRegistrar`
   shim, letting existing `.pb.go` files register unmodified, comes later and
   only on the compat path — adopting grpc-go's API shape wholesale would mean
   paying its allocation model to win its users.
2. **Evidence.** One test-scope module with a grpc-go dependency and its own
   `go.mod`, serving both the head-to-head benchmark and interop certification.
   The root module's dependency set stays as it is; the README says plainly that
   "one dependency" describes runtime, not tests. (#94)
3. **First workload.** Small unary at high RPS. Connection density and large
   streaming follow; the full matrix is the goal, not the opening move.
4. **Deployment target.** Behind a sidecar. This *removes* xDS, ORCA, channelz,
   binary logging, ALTS and client-side load balancing from scope, and *promotes*
   `MaxConnectionAge` (#91), keepalive enforcement (#96) and precise drain
   semantics to blockers.
5. **gRPC API shape.** The native/compat split that `server/` already has moves
   into `grpcserver/`. `[]byte` handlers stay the allocation-free native path;
   metadata (#88), status details (#89), interceptors and codegen (#84) live on
   the compat path and are allowed to allocate. ADR-0001 extends to say so.
6. **BDP.** Built now (#93) rather than deferred, accepting the risk of changing
   flow-control accounting in `conn/`, because it closes both cross-region and
   direct-ingest deployments. Atomics, not locks.
7. **Locks.** A new design rule: locks cost more than allocations. Contention is
   made *visible* first (#95) — 27 benchmarks in the repo, none parallel — and
   only then is `wmu` reconsidered. That rule is in tension with ADR-0003 and
   resolving it requires a measurement and a superseding ADR, not a preference.
8. **Observability.** The missing piece was a *word*, not a feature. `CONTEXT.md`
   had no term for how a call ended, so `middleware/` read HTTP status — which is
   200 for every failed RPC. **Call outcome** is now a domain term, and #92
   builds the single protocol-neutral value that both HTTP and gRPC populate.

### What this changed in the stories above

- **#84** interceptors + codegen: **P2 → P0.** It is the whole migration surface
  and the parent of #88 and #89.
- **#77** TLS: **split.** Peer-identity plumbing extracted to #90 and done first
  — three issues and one live defect (#87) wait on it.
- **#78** lifecycle hooks: **scope clarified.** Connection/stream level only; it
  does not deliver per-RPC observability, which is #92.
- **#81** load shedding: **P2 → P1.** Overload behaviour is a standard evaluation
  test.
- **#75** HTTP/1.1: **outside this lane.** gRPC is HTTP/2-only. Still valuable,
  still supersedes #50/#51, but it yields when competing with the lane.
- **#72** HTTP/2 internals: **two new consumers**, #95 and #93.

### The honest counterweight

gRPC is not a wire format, it is a governance process, and grpc-go is its
reference implementation. The moat is not framing — this repository demonstrably
does framing well — it is roughly eighty gRFCs of co-evolved behaviour that ship
in grpc-go the quarter they are ratified and are checked against nine other
language stacks in a shared interop matrix. A displacement candidate does not
reach parity once; it tracks a moving specification indefinitely, with a bus
factor of one, against a funded team at the specification's author. And the risk
is asymmetric: a defect in a hand-rolled HPACK is a fleet-wide correctness
incident, not a slowdown — which is not hypothetical here, since the Huffman
symbol-249 defect shipped in v0.4.3 and mis-coded a byte on both HTTP/2 and
HTTP/3.

Decisions 1 and 4 are the answer to that argument: do not promise parity, occupy
the niche where the advantage is measurable. But note what it does to the pitch —
behind a sidecar the transport-level latency win is absorbed by the proxy hop, so
the claim becomes *cheaper in CPU and memory at the same traffic*, not *faster on
the wire*. Decision 3's benchmark should be framed to measure that claim.

---

## Theme 1 — Observability that survives production

### PB-01 — Bound metric label cardinality

**Tracked in [#68](https://github.com/lodgvideon/poseidon-http-server/issues/68)**

**P0** · **Size: M** · **Proved by:** new gate — a memory-bound test asserting
the series count stops growing, plus a `middleware/` allocation benchmark under
`make bench-gate`.

> **As** an operator exposing Poseidon to untrusted traffic,
> **I want** request metrics to have a bounded number of label values,
> **so that** a scanner walking `/users/1`, `/users/2`, … cannot grow the process
> heap until the pod is OOM-killed.

**What is there now.** `MetricsCollector` keys every counter, duration, byte
count and histogram on the raw `req.Path` (`middleware/metrics.go:114`, `:119`,
used at `:225`–`:236`). Nothing normalises the path and nothing evicts. Measured:

```
BenchmarkProbeMetricsCardinality-16   200000   868.9 ns/op   464 B/op   8 allocs/op
                                      100000 counter-keys   100000 histogram-keys
```

100,000 distinct paths produced 100,000 counter series *and* 100,000 histograms,
each histogram holding 11 `atomic.Int64` buckets plus a sum and a count — tens of
megabytes retained, permanently, driven entirely by attacker-chosen input. The
`ratelimit` middleware already solved exactly this problem for its own state
(`DefaultMaxBuckets`, `DefaultBucketIdleTTL`); metrics never got the same
treatment.

**Acceptance criteria**
- [ ] `RateLimitConfig`-style bounds on the collector: a max series count and an
      idle TTL, with documented defaults.
- [ ] A route-template hook (`func(*server.Request) string`) so chi/echo/gin users
      can label by `/users/{id}` instead of the concrete path.
- [ ] On overflow, requests are folded into a single `path="__other__"` series —
      never dropped, never unbounded.
- [ ] A test that drives 1e6 distinct paths and asserts the series count settles
      at the configured bound.
- [ ] `docs/usage.md` states the default bound and how to raise it.

**Notes.** This is the one item in this document that is a live defect rather
than a missing feature, and the only one filed with the `bug` label.

---

### PB-02 — Put the middleware chain under the allocation contract

**Tracked in [#69](https://github.com/lodgvideon/poseidon-http-server/issues/69)**

**P0** · **Size: M** · **Proved by:** `make bench-gate` (after #66), which today
cannot see this package at all.

> **As** a maintainer defending the zero-allocation claim,
> **I want** the middleware every deployment enables to be benchmarked and
> allocation-bounded,
> **so that** "0 allocs/op" describes the request path a user actually runs, not
> just the frame writer underneath it.

**What is there now.** `middleware/` contains **zero benchmarks** — every
`Benchmark*` in the tree lives in `conn/`, `server/`, or `grpcserver/`. So the
layer with the most per-request work in it is the only layer `bench-gate` is
blind to. Measured:

| Middleware | ns/op | B/op | allocs/op |
|---|---|---|---|
| `Metrics()` | 177.4 | 96 | **5** |
| `RequestID()` | 148.4 | 112 | **4** |
| `RealIP()` | 91.4 | 80 | **3** |

A routine chain of `RequestID → RealIP → Metrics → StructuredAccessLog` therefore
costs **12+ allocations per request** sitting directly on top of a transport that
was engineered to zero. The Metrics cost is largely self-inflicted:
`counterKey` is a `fmt.Sprintf` (`middleware/metrics.go:114`) and `durationKey`
is a string concatenation (`:119`), both on the hot path, both re-minted per
request, and then used for four separate map lookups under a shared `RWMutex`.

This also contradicts CLAUDE.md directly: *"Any new hot-path feature must ship
with a benchmark, or it can silently erode the baseline."*

**Acceptance criteria**
- [ ] `middleware/bench_test.go` benchmarks each shipped middleware individually
      and one representative chain, with `-benchmem`.
- [ ] Those benchmarks are in `testdata/benchmarks/baseline.txt` so `bench-gate`
      guards them.
- [ ] `Metrics()` drops to ≤1 alloc/op: pre-resolve the per-route series once and
      cache the pointer bundle, so the steady-state request path does no key
      construction and no map lookup.
- [ ] ADR-0001 is amended to say what the contract is for `middleware/` —
      "allocation-bounded and benchmarked" is a different promise from the native
      write path's "zero", and the difference should be written down rather than
      inferred.

---

### PB-03 — Propagate W3C trace context

**Tracked in [#70](https://github.com/lodgvideon/poseidon-http-server/issues/70)**

**P0** · **Size: M** · **Proved by:** `make conformance-gate` — the W3C Trace
Context recommendation has normative MUST-level text and the repo already has the
machinery to assert against a spec (`docs/RFC_COVERAGE.md`, `TestConformance_*`).

> **As** an SRE debugging a request that crossed six services,
> **I want** Poseidon to continue the caller's trace instead of starting a new one,
> **so that** the trace is one connected tree rather than six disconnected roots.

**What is there now.** Nothing. `grep -rn "traceparent\|tracestate"` over the
whole tree returns no hits. `Tracing()` (`middleware/tracing.go:76`) calls
`Tracer.StartSpan(ctx, name)` and never inspects the inbound field section, so
every span it creates is a root span. The vendor-neutral `Tracer`/`Span`
interfaces are a good decision and should stay — the missing piece is the
extract/inject step around them, which needs no dependency.

Related: `StructuredAccessLog` (`middleware/slog.go`) emits no trace or span id,
so logs cannot be correlated to traces either.

**Acceptance criteria**
- [ ] Parse `traceparent` and `tracestate` per W3C Trace Context, including the
      version/flag rules and the "malformed header is ignored, not fatal" rule.
- [ ] Expose the extracted `SpanContext` on the request context, and pass it to
      `StartSpan` so adapters can make the span a child.
- [ ] Inject `traceparent` on outbound-facing surfaces where the server is the
      caller's peer.
- [ ] `StructuredAccessLog` emits `trace_id` and `span_id` when present.
- [ ] Sampling decision is honoured and exposed, so a downstream adapter does not
      re-decide it.
- [ ] Conformance tests named `TestConformance_W3CTraceContext_*` with the
      normative sentence quoted, and rows added to `docs/RFC_COVERAGE.md`.
- [ ] Zero new dependencies — parsing is a fixed-format 55-byte string.

---

### PB-04 — Runtime and process metrics

**Tracked in [#71](https://github.com/lodgvideon/poseidon-http-server/issues/71)**

**P1** · **Size: S** · **Proved by:** `make coverage-gate` plus a golden-output
test on the exposition text.

> **As** an operator running a performance-critical Go service,
> **I want** goroutine count, GC pause, heap, and fd metrics on the same
> `/metrics` endpoint,
> **so that** the first question after a latency spike — "is it GC, a goroutine
> leak, or the network?" — is answerable without attaching pprof to production.

**What is there now.** `WritePrometheus` (`middleware/metrics.go:272`) emits
`poseidon_*` request and transport series only. There is no `go_goroutines`, no
`go_gc_duration_seconds`, no `go_memstats_*`, no `process_open_fds`. For a server
whose entire value proposition is allocation behaviour, the absence of GC and
heap metrics is a conspicuous hole — the project's headline property is the one
thing an operator cannot observe.

**Acceptance criteria**
- [ ] Export the standard `go_*` set from `runtime/metrics` (not the deprecated
      `runtime.ReadMemStats` path), under the conventional names so existing
      Grafana dashboards work unmodified.
- [ ] Export `process_*` where the platform supports it, degrading silently where
      it does not.
- [ ] Opt-out flag, since a sidecar exporter may already provide these.
- [ ] Still zero third-party dependencies.

---

### PB-05 — Expose HTTP/2 internals: flow control, HPACK, queue depth

**Tracked in [#72](https://github.com/lodgvideon/poseidon-http-server/issues/72)**

**P1** · **Size: M** · **Proved by:** `make loadtest` — the h2load/k6 harness is
where these numbers become legible, and `loadtest/README.md` already documents
the runs.

> **As** an engineer tuning a large-upload or high-fan-out workload,
> **I want** to see how long streams spend blocked on flow control and how full
> the internal queues are,
> **so that** I can tell a slow handler apart from a starved window without
> reading frame dumps.

**What is there now.** `TransportStats` (`server/server.go`) reports bytes,
frames, streams accepted, rapid resets, and GOAWAYs — all *volume*, no
*pressure*. Nothing reports: time blocked in `acquireSendCredits`, current
connection/stream window sizes, HPACK dynamic table occupancy, connection age
distribution, or `acceptCh` depth.

That last one matters more than it looks. `registerStream`
(`conn/server_ops.go:53`) does:

```go
select {
case sc.acceptCh <- s:
default:
    _ = s.Close()
}
```

If the 64-slot accept channel is full, the stream is closed and **nothing counts
it**. In practice the accept loop spawns a goroutine per stream and drains fast,
so this is a blind spot rather than a confirmed live drop — but a silent
`default:` branch on an admission path is exactly the thing that should have a
counter on it before someone has to find it during an incident.

**Acceptance criteria**
- [ ] Counter for streams dropped at the accept channel, exported and logged.
- [ ] Histogram of time blocked on connection- and stream-level flow control.
- [ ] Gauges for current windows and HPACK table size.
- [ ] `ConnRecvWindow` tuning (`conn/server_conn.go:141`) becomes measurable —
      today an operator raising it has no way to see whether it helped.

---

### PB-06 — Observability for the HTTP/3 path

**Tracked in [#73](https://github.com/lodgvideon/poseidon-http-server/issues/73)**

**P1** · **Size: M** · **Proved by:** new gate — extend the transport-stats test
to run against both listeners.

> **As** an operator enabling HTTP/3,
> **I want** the same metrics, health, and access logs I get on HTTP/2,
> **so that** turning on QUIC does not turn off my dashboards.

**What is there now.** `http3server.Server` is two fields — `Handler` and
`TLSConfig` (`http3server/server.go:45`). No stats, no logger, no middleware
integration, no health wiring. `TransportStats` is HTTP/2-only, so every
`poseidon_*` transport series silently excludes HTTP/3 traffic. An operator
running both protocols on one process reads a dashboard that is quietly wrong.

**Acceptance criteria**
- [ ] HTTP/3 connections and streams counted into the same `TransportStats`
      aggregate, or a clearly-labelled parallel one.
- [ ] Access log and metrics middleware work unmodified on the HTTP/3 handler.
- [ ] `docs/HTTP3_SERVER_GUIDE.md` documents what is and is not counted.

See also PB-13, which covers HTTP/3's missing lifecycle controls.

---

### PB-07 — First-party OpenTelemetry adapter, as a separate module

**Tracked in [#74](https://github.com/lodgvideon/poseidon-http-server/issues/74)**

**P2** · **Size: M** · **Proved by:** `make test` in the sub-module + a compile
check that the root module's dependency set is unchanged.

> **As** a team standardised on OTLP,
> **I want** a supported adapter I can import,
> **so that** I do not each write the same 200 lines of glue against the
> `Tracer`/`Span` interfaces.

**What is there now.** `middleware/tracing.go` documents an OTel adapter in a
comment and correctly refuses to take the dependency. That is the right call for
the root module — "exactly one runtime dep" is a documented selling point. The
answer is a *second module* (`otel/go.mod`) in the same repository, which can
depend on whatever it likes without touching the root module's go.mod.

**Acceptance criteria**
- [ ] `github.com/lodgvideon/poseidon-http-server/otel` as its own module.
- [ ] Trace adapter, and a metrics bridge exporting the `poseidon_*` series via
      OTLP.
- [ ] Root `go.mod` provably unchanged; CI asserts it.
- [ ] Tagged and released independently, per the ADR-0008 pattern.

---

## Theme 2 — Flexibility: what a deployment needs and cannot get today

### PB-08 — Serve HTTP/1.1

**Tracked in [#75](https://github.com/lodgvideon/poseidon-http-server/issues/75)**

**P1** · **Size: L** · **Proved by:** `make conformance-gate` — RFC 9112 is
normative and the repo already has an HTTP/1.1 reconciliation document
(`docs/rfc-analysis/HTTP1_SERVER_RECONCILIATION.md`).

> **As** an engineer replacing `net/http` on a public port,
> **I want** the server to answer HTTP/1.1 clients,
> **so that** I do not have to keep a second server or a proxy in front of it
> purely for protocol coverage.

**What is there now.** Plain HTTP/1.1 gets a hand-written 400 and the connection
is closed (`server/h2c.go:119`, reached from `:317` and `:324`). ALPN advertises
only `h2` (`server/tls.go:25`), so a TLS client without HTTP/2 fails
negotiation outright. The h2c path parses an HTTP/1.1 request head already — it
just refuses to serve it unless it carries `Upgrade: h2c`.

This is the single largest gap between "drop-in `http.Handler` replacement" as
the README describes it and what a user gets. Already wanted:
[#50](https://github.com/lodgvideon/poseidon-http-server/issues/50) and
[#51](https://github.com/lodgvideon/poseidon-http-server/issues/51) (duplicates
of each other) ask for the body-streaming half of it.

**Acceptance criteria**
- [ ] `Options.HTTP1` serves HTTP/1.1 on the same listener, keep-alive and
      chunked transfer included.
- [ ] ALPN offers `http/1.1` alongside `h2`, selectable.
- [ ] Requests arrive as the same `server.Request`, so handlers and the whole
      middleware chain are protocol-agnostic.
- [ ] Streaming bodies work on HTTP/1.1 — the substance of #50/#51.
- [ ] `Expect: 100-continue`, `HEAD`, and trailer handling reuse the existing
      conformance tests rather than growing a second set.
- [ ] Explicitly out of the zero-allocation contract, stated in ADR-0001, unless
      a benchmark says otherwise.

**Notes.** Large and worth splitting: (a) ALPN + protocol detection, (b) request
parsing, (c) response writing, (d) streaming bodies. Sequence it so each lands
with its own conformance rows.

---

### PB-09 — Request deadlines

**Tracked in [#76](https://github.com/lodgvideon/poseidon-http-server/issues/76)**

**P1** · **Size: S** · **Proved by:** `make test-race` + `make coverage-gate`.

> **As** a service owner,
> **I want** a per-request timeout,
> **so that** one handler that never returns cannot pin a stream, its goroutine,
> and its flow-control credit for the life of the connection.

**What is there now.** `Options.IdleTimeout` covers connection *idleness* and
`HandshakeTimeout` covers the preface. Neither bounds a handler that has started.
There is no `Timeout()` middleware, no `ReadHeaderTimeout`, no `WriteTimeout`,
and no way to say "this route gets 2 seconds". `net/http` has had
`http.TimeoutHandler` and three timeout fields for years; a server marketed on
robustness should not be behind it.

**Acceptance criteria**
- [ ] `middleware.Timeout(d)` cancelling the request context and answering 503
      (or 504) once, with no double-write against `ResponseWriter`.
- [ ] `Options.WriteTimeout` / `ReadHeaderTimeout` at the server level.
- [ ] Interaction with the gRPC `grpc-timeout` deadline
      (`grpcserver/service.go:148`) is defined and tested — whichever is sooner
      wins, and the RPC still gets a proper `DEADLINE_EXCEEDED` status.
- [ ] A timed-out stream releases its flow-control credit. ADR-0009's history
      says an early return that abandons debited credit is a remote DoS; this
      story adds a new early return to exactly those paths, so that invariant is
      part of its acceptance, not an afterthought.

---

### PB-10 — TLS certificate rotation, SNI, and mTLS

**Tracked in [#77](https://github.com/lodgvideon/poseidon-http-server/issues/77)**

**P1** · **Size: M** · **Proved by:** `make coverage-gate` + a test that swaps a
certificate on a live listener and asserts the new one is served.

> **As** an operator using cert-manager or Vault,
> **I want** certificates to reload without restarting the process,
> **so that** a 90-day rotation is not a rolling restart of every pod.

**What is there now.** `ListenAndServeTLS` calls `tls.LoadX509KeyPair` once at
startup (`server/tls.go:20`). There is no `GetCertificate` callback, no watcher,
no multi-cert SNI, no client-certificate configuration, and no helper to pull an
mTLS peer identity into the request context. `ListenAndServeTLSConfig` lets a
caller build all of it by hand — which every caller then does, differently. The
RFC 9113 §9.2.2 cipher-suite work already in this file shows the project takes
TLS seriously; the operational half is missing.

**Acceptance criteria**
- [ ] A reloading certificate source: watch the files, swap atomically, serve the
      new cert on the next handshake without dropping live connections.
- [ ] Per-SNI certificate selection.
- [ ] mTLS config helper, with the verified client identity on the request
      context and available to the access log.
- [ ] A malformed replacement file logs and keeps the previous certificate — it
      must never take the listener down.
- [ ] Session-ticket key rotation.

---

### PB-11 — Connection and stream lifecycle hooks

**Tracked in [#78](https://github.com/lodgvideon/poseidon-http-server/issues/78)**

**P1** · **Size: S** · **Proved by:** `make coverage-gate`; the hooks are what
several other stories build on, so their own gate is coverage.

> **As** a platform engineer with a requirement nobody upstream anticipated,
> **I want** callbacks on connection open/close and stream start/end,
> **so that** I can build per-tenant accounting or connection-level tracing
> without forking the server.

**What is there now.** `net/http` has `Server.ConnState`. Poseidon has
`OnDrainStart` and nothing else — `grep` for `ConnState|OnConn|Hook` across
`server/` and `conn/` returns only that one field. Everything observable is
therefore whatever the maintainers chose to count, and a user with a different
question has no seam to hang an answer on. This is the "flexibility out of the
box" claim at its weakest point.

**Acceptance criteria**
- [ ] `OnConnOpen`, `OnConnClose` (with the close reason and final `ConnStats`),
      `OnStreamStart`, `OnStreamEnd`.
- [ ] Hooks are nil-checked and allocation-free when unset — benchmarked, so
      adding the seam does not cost the zero-alloc path anything.
- [ ] Documented as running on the connection's reader goroutine, so a blocking
      hook's consequences are the caller's informed choice.
- [ ] PB-05's counters reimplemented on top of these hooks, proving the seam is
      actually sufficient.

---

### PB-12 — gRPC message compression

**Tracked in [#79](https://github.com/lodgvideon/poseidon-http-server/issues/79)**

**P1** · **Size: M** · **Proved by:** `make test` + a `ghz` run in the loadtest
harness against a compressing client.

> **As** a gRPC client with a large payload,
> **I want** the server to accept `grpc-encoding: gzip`,
> **so that** I do not have to disable compression specifically for this server.

**What is there now.** A compressed message is refused:
`Unimplemented — "message compression not supported (no grpc-encoding
negotiated)"` (`grpcserver/service.go:190`). The compressed-flag byte is parsed
and then rejected. Since grpc-go clients enable gzip with one dial option and
many services do, this turns into a confusing runtime failure rather than a
documented limitation.

**Acceptance criteria**
- [ ] Accept `grpc-encoding: gzip` on inbound messages, bounded by the same
      decompression-bomb limit the HTTP gzip middleware already enforces
      (`DefaultMaxDecompressedSize`).
- [ ] Advertise `grpc-accept-encoding` and compress responses when the client
      accepts it.
- [ ] `identity` and unknown encodings handled per the gRPC spec, with the
      correct status code.
- [ ] Per-RPC opt-out, since compressing an already-compressed payload is a loss.

---

### PB-13 — HTTP/3 lifecycle parity

**Tracked in [#80](https://github.com/lodgvideon/poseidon-http-server/issues/80)**

**P1** · **Size: M** · **Proved by:** `make test-race` — the drain path is where
races live; reuse the HTTP/2 shutdown tests.

> **As** an operator running HTTP/3 in Kubernetes,
> **I want** graceful drain, timeouts, and body limits on the QUIC listener too,
> **so that** a rolling deploy does not cut QUIC requests mid-flight.

**What is there now.** `http3server.Serve` (`http3server/server.go:68`) is an
accept loop with `go s.serveConn(...)` and no shutdown path at all — cancelling
the context stops accepting and abandons whatever is in flight. There is no
`Shutdown(ctx)`, no `OnDrainStart`, no idle timeout, no `MaxRequestBodyBytes`, no
connection or stream cap. Every hardening story the HTTP/2 server has accumulated
is absent here. The package doc is honest that push, 0-RTT, and trailers are
missing; the lifecycle gap is not yet written down.

Trailers deserve their own call-out: without them, **gRPC over HTTP/3 is
impossible**, because the gRPC status *is* a trailer (ADR-0004).

**Acceptance criteria**
- [ ] `Shutdown(ctx)` draining in-flight requests, with `OnDrainStart` parity.
- [ ] `Options` struct reaching parity with `server.Options` on timeouts, body
      limits, and concurrency caps.
- [ ] Trailer support, unblocking gRPC-over-HTTP/3.
- [ ] The transport limits the package doc already warns about — no Retry/address
      validation, no per-peer rate limiting — either fixed or restated as a
      `SECURITY.md` deployment requirement.

---

### PB-14 — Load shedding and admission control

**Tracked in [#81](https://github.com/lodgvideon/poseidon-http-server/issues/81)**

**P2** · **Size: M** · **Proved by:** `make loadtest` — an overload run that
must show bounded latency and a rising 503 rate rather than a latency blowout.

> **As** an operator whose service is briefly overloaded,
> **I want** the server to shed load predictably,
> **so that** it degrades instead of queueing every request until all of them
> time out.

**What is there now.** `MaxConcurrentConnections` and `MaxConcurrentStreams` are
hard caps: at the limit, connections are dropped and streams get
`REFUSED_STREAM`. Between "fine" and "refusing" there is nothing — no queue-depth
signal, no latency-based shedding, no way to protect a health endpoint from being
starved by request traffic. A server that markets on performance should have an
answer for the overload region, because that is where performance claims are
actually tested.

**Acceptance criteria**
- [ ] Concurrency limiter with a bounded queue and a fast 503 on overflow,
      including `Retry-After`.
- [ ] Optional latency-based shedding (CoDel-style: shed when sojourn time
      exceeds a target).
- [ ] Health and readiness endpoints exempt, so a shedding server still reports
      its state truthfully.
- [ ] Metrics for shed count and queue depth (depends on PB-05).

---

### PB-15 — Authentication middleware

**Tracked in [#82](https://github.com/lodgvideon/poseidon-http-server/issues/82)**

**P2** · **Size: M** · **Proved by:** `make coverage-gate`; untrusted-input paths
are held above the 80% floor, as `conn/server_untrusted_coverage_test.go`
establishes.

> **As** a developer standing up an internal service,
> **I want** batteries-included auth middleware,
> **so that** I am not hand-rolling constant-time comparison and JWT validation
> in every project.

**What is there now.** Nothing. The only hits for `Authorization` in the tree are
in the CORS allow-list defaults (`middleware/middleware.go:134`). The middleware
suite covers logging, metrics, rate limiting, real IP, security headers, CORS,
and gzip — the full perimeter *except* the part that decides who the caller is.

**Acceptance criteria**
- [ ] `BasicAuth` with constant-time comparison.
- [ ] `APIKey` with a pluggable, constant-time key store.
- [ ] `BearerToken` with a validator interface, so JWT/JWKS can live in the
      separate module (PB-07) without pulling a crypto dependency into root.
- [ ] mTLS identity extraction (pairs with PB-10).
- [ ] Authenticated principal on the request context, and in the access log.
- [ ] Failures are logged without ever logging the credential.

---

### PB-16 — Compression beyond gzip, and compression that streams

**Tracked in [#83](https://github.com/lodgvideon/poseidon-http-server/issues/83)**

**P2** · **Size: M** · **Proved by:** `make bench-gate` for the codec paths;
`make test` for negotiation.

> **As** a service returning large JSON or server-sent events,
> **I want** zstd/brotli and compression that does not buffer the whole response,
> **so that** I get better ratios and my streaming endpoints still stream.

**What is there now.** Gzip only, and by ADR-0006 it buffers the entire response
before compressing — which makes it structurally incompatible with SSE, long-poll,
and gRPC streaming. `Accept-Encoding` selection does not weigh q-values.

**Acceptance criteria**
- [ ] zstd and brotli, behind build tags or the separate module if they would
      otherwise breach the one-dependency rule.
- [ ] Correct q-value negotiation including `identity;q=0` and `*`.
- [ ] A streaming compressor that flushes per write, selectable per route, with
      the buffering trade-off documented.
- [ ] Precompressed static asset support (`.gz`/`.br` sidecar files).
- [ ] ADR-0006 updated — it currently records buffering as the decision, and this
      story changes that decision rather than working around it.

---

### PB-17 — gRPC interceptors and codegen

**Tracked in [#84](https://github.com/lodgvideon/poseidon-http-server/issues/84)**

**P2** · **Size: L** · **Proved by:** `make test` + an example service in
`examples/`.

> **As** a team migrating from grpc-go,
> **I want** interceptors and generated stubs,
> **so that** porting a service is a re-registration rather than a rewrite.

**What is there now.** Handlers are `func(ctx, []byte) ([]byte, error)`
(`grpcserver/service.go`) — the user marshals protobuf by hand. There is no
unary/stream interceptor chain, so cross-cutting concerns must be done in HTTP
middleware where the RPC method and gRPC status are not first-class. `ServiceDesc`
is hand-written per service.

**Acceptance criteria**
- [ ] `UnaryInterceptor` / `StreamInterceptor` chains with grpc-go-compatible
      shapes.
- [ ] A `protoc-gen-poseidon` plugin emitting `ServiceDesc` and typed stubs.
- [ ] Codec interface, so protobuf is pluggable rather than assumed.
- [ ] Migration guide from grpc-go in `docs/`.

**Notes.** The largest item here and the one most worth challenging before
starting. It may be better served by an adapter that reuses grpc-go's generated
code than by a new plugin — decide that before writing the plugin, not after.

---

### PB-18 — Listener and socket tuning

**Tracked in [#85](https://github.com/lodgvideon/poseidon-http-server/issues/85)**

**P2** · **Size: S** · **Proved by:** `make loadtest` — the accept-path win only
shows under concurrent connection churn.

> **As** an operator on a many-core box,
> **I want** `SO_REUSEPORT` and socket-option control,
> **so that** accept does not funnel through one queue while 15 cores idle.

**What is there now.** `net.Listen("tcp", addr)` with defaults, and no
`net.ListenConfig` seam. No `SO_REUSEPORT` (so no multi-acceptor scaling), no
keepalive tuning, no backlog control, no way to set socket options at all without
building the listener yourself and using `Serve`.

**Acceptance criteria**
- [ ] `Options.ListenConfig` accepted and used.
- [ ] `SO_REUSEPORT` helper for Linux/BSD, degrading cleanly elsewhere —
      note the primary dev platform here is Windows, so the fallback path is the
      one that must not break.
- [ ] TCP keepalive and `TCP_NODELAY` documented and configurable.
- [ ] A loadtest run showing accept-path scaling with N acceptors.

---

### PB-19 — Fill out the `poseidon-server` binary

**Tracked in [#86](https://github.com/lodgvideon/poseidon-http-server/issues/86)**

**P2** · **Size: S** · **Proved by:** `make coverage-gate` — `cmd/` is already
tested via the `getenv`-injection seam in `main_test.go`.

> **As** someone deploying the prebuilt binary,
> **I want** the features the library exposes to be reachable from configuration,
> **so that** the binary is a usable product rather than a smoke test.

**What is there now.** 12 environment variables (`cmd/poseidon-server/main.go:70`),
covering timeouts, caps, h2c, pprof, and TLS paths. Not reachable: HTTP/3,
metrics, tracing, rate limiting, security headers, gzip, real-IP trusted proxies
— i.e. most of what the library does. No config file, no log-level control, no
config validation beyond parse errors.

**Acceptance criteria**
- [ ] Env coverage for the middleware suite and HTTP/3.
- [ ] Optional config file, with env taking precedence.
- [ ] `--check-config` that validates and exits, for use as a container
      readiness probe on the config itself.
- [ ] `POSEIDON_LOG_LEVEL` wired to slog.
- [ ] Helm chart values updated in step (`deploy/`).

---

## Suggested order

1. **PB-01 (#68)** — it is a defect, and it is cheap.
2. **PB-02 (#69)** — everything else that touches the request path needs the
   benchmark harness this story builds, and it closes the gap between the
   README's headline claim and the code a user actually runs. Blocked on #66.
3. **PB-03 (#70)** — the largest single hole in "observability out of the box",
   and the one users will hit on day one of a multi-service deployment.
4. **PB-09 (#76)**, **PB-11 (#78)** — small, and several later stories build on
   the hooks.
5. **PB-08 (#75)** — large, high value, and best started once the request path
   has benchmarks around it.

`#59`'s receive-path allocation work is independent of all of the above and can
run in parallel; it touches `conn/`, this backlog mostly does not.

### And in the gRPC lane, in parallel

1. **#87** — the `RealIP` defect. It is shipped, it is in the documented
   security-hardening surface, and it makes a single-client denial of service
   easier than having no rate limiter at all.
2. **#90** — peer identity plumbing. Small, and #87, #77 and #82 all wait on it.
3. **#94** and **#95** — the two measurements. Everything downstream is an
   argument about numbers nobody has yet: whether small unary beats grpc-go, and
   how much `wmu` actually costs. Neither question should be answered by opinion,
   and #95 is blocked on **#66**.
4. **#84** — the API shape, once #94 says whether the wedge is real.

The ordering is deliberate: two defects, then two measurements, then the largest
design commitment in the backlog. Nothing after step 3 should start before the
numbers from step 3 exist.
