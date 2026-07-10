# Load / soak test harness

Manual (and perf-CI) load and soak tests for **poseidon-server**. The server is
**HTTP/2 cleartext (h2c)** — there is no TLS by default — so every tool here must
speak **HTTP/2 over cleartext via prior-knowledge** (not the HTTP/1.1 `Upgrade`
dance, and not ALPN-over-TLS). The one exception is k6, whose HTTP/2 path is
TLS-only; see the caveat below.

These scripts are **not wired into the blocking CI gates**. They run:

- **manually** during perf investigations or before a release, or
- in a dedicated, opt-in **perf CI job** (long-running, separate from the
  unit/race/lint gates).

The target tools (`h2load`, `ghz`, `k6`) are **not installed in normal CI**; each
script no-ops with an install hint (exit 127) when its tool is absent, and the
`make loadtest` target is likewise guarded.

## What to measure

| Metric | What it tells you |
| --- | --- |
| **RPS** (throughput) | requests/sec the server sustains at a given concurrency |
| **p50 / p95 / p99 latency** | tail latency under load — the number that matters for SLOs |
| **error rate** | should be ~0%; all responses 2xx (HTTP) / `OK` (gRPC) |
| **0-alloc expectation** | Poseidon targets zero allocations in hot request paths. A load test does **not** measure allocs directly — pair it with `make bench` (which uses `-benchmem`) and/or run the server under `pprof` (`POSEIDON_ENABLE_PPROF=true`, then `go tool pprof http://127.0.0.1:8080/debug/pprof/allocs`). Steady, low `alloc/op` under sustained load is the signal. |

For **soak** runs, use the duration knobs (`DURATION=…`) and watch RSS / goroutine
count / GC pauses over time (via `/debug/pprof/` and `/metrics`) for leaks.

## Prerequisites — start a server

HTTP (the `cmd/poseidon-server` binary, default `:8080`, h2c):

```sh
# h2c cleartext on :8080
POSEIDON_H2C=true go run ./cmd/poseidon-server --addr :8080 --h2c
# or build first: make build && POSEIDON_H2C=true ./bin/poseidon-server --h2c
```

gRPC (the example service, `:9090`, h2c):

```sh
go run ./examples/grpc-server   # hello.HelloService on :9090
```

## a) HTTP/2 h2c — `h2load` (nghttp2)

```sh
loadtest/h2load.sh                                   # defaults: 100k reqs, 100 clients
REQUESTS=500000 CLIENTS=200 loadtest/h2load.sh
DURATION=30 CLIENTS=200 loadtest/h2load.sh http://127.0.0.1:8080/   # 30s soak
```

`h2load` is invoked with `--h2c`, forcing **HTTP/2 cleartext prior-knowledge**.
Read `finished in … req/s` (RPS), the `time for request` percentile row
(p50/p95/p99), and `status codes: N 2xx`.

Install: `apt-get install -y nghttp2-client` / `brew install nghttp2` / `apk add nghttp2`.

## b) gRPC — `ghz`

```sh
loadtest/ghz.sh                                      # SayHello, 100k reqs, 100 conc
CONCURRENCY=200 TOTAL=500000 loadtest/ghz.sh
DURATION=30s loadtest/ghz.sh 127.0.0.1:9090          # 30s soak
CONFIG=loadtest/ghz.json loadtest/ghz.sh             # config-file mode
```

`ghz` runs with `--insecure` (plaintext **h2c**, no TLS) against
`hello.HelloService/SayHello`, encoded from [`hello.proto`](./hello.proto).
[`ghz.json`](./ghz.json) is an equivalent config-file form. Read `Requests/sec`,
the `Latency distribution` percentiles, and `Status code distribution: OK N`.

Install: `go install github.com/bojand/ghz/cmd/ghz@latest` / `brew install ghz`.

## c) k6 (HTTP) — `k6_http2.js`

```sh
k6 run loadtest/k6_http2.js
VUS=200 DURATION=30s k6 run loadtest/k6_http2.js
BASE_URL=https://127.0.0.1:8443/ EXPECT_H2=true k6 run loadtest/k6_http2.js   # real HTTP/2 over TLS
```

> **HTTP/2 caveat:** k6 only negotiates HTTP/2 via **ALPN over TLS**. It does
> **not** speak h2c prior-knowledge. Against the plain h2c listener it falls back
> to HTTP/1.1 (still a useful latency/throughput smoke). For a genuine HTTP/2 path
> through k6, run the server with TLS (`POSEIDON_TLS_CERT`/`POSEIDON_TLS_KEY`) and
> point `BASE_URL` at `https://…` with `EXPECT_H2=true`. For HTTP/2 **cleartext**
> load, use `h2load.sh` (option a) instead.

Read `http_reqs` (RPS), `http_req_duration` (`p(50)/p(95)/p(99)`), and `checks`.

Install: `brew install k6` / <https://k6.io/docs/get-started/installation/> /
`docker run --rm -i grafana/k6 run - <loadtest/k6_http2.js`.

## d) All-in-one Go harness — `loadgen` (no external tools)

[`loadtest/loadgen`](./loadgen) is a **self-contained** load/soak + profiling
harness written in Go. Unlike h2load/ghz/k6 it needs no external tool and no
separately-started server: it boots **two in-process** poseidon servers (an HTTP/2
TLS mux behind the full middleware onion, plus a gRPC server) and drives them
end-to-end, so one run exercises a broad slice of the feature surface at once and
captures pprof profiles + a resource report. It has unit + end-to-end tests
(`go test ./loadtest/loadgen`), so it runs in the normal test/race gate.

```sh
# smoke it (small + fast)
go run ./loadtest/loadgen -duration=15s -vus=32 -data-size=32MiB

# heavy soak with a 2-minute spike + profiling (run on real hardware)
go run ./loadtest/loadgen \
    -duration=10m -vus=128 -data-size=10GiB -json-items=40000 \
    -spike-after=2m -spike-dur=2m -spike-vus=512 \
    -cpuprofile=cpu.out -memprofile=heap.out
go tool pprof cpu.out    # where CPU goes
go tool pprof heap.out   # where memory goes
```

**One run exercises** a weighted + conditional + nested scenario mix with per-VU
variable state (dozens of distinct calls):

| scenario | feature |
| --- | --- |
| `ping` | hot-path GET — the RPS/latency baseline |
| `login` → `upload+verify` | variable correlation: a session token gates the upload scenario, which streams a large body then does a nested download round-trip |
| `bigparse` / `adaptive` | streams a **~3.3 MiB JSON** response (at the default `-json-items=40000`), parsed element-by-element (bounded memory); `adaptive` branches on the per-VU upload counter (`if`-based selection) |
| `stream` | chunked streaming response |
| `gzip` | asserts the Gzip middleware actually compresses (`Content-Encoding: gzip` round-trip) |
| `headers` | header-heavy request/response (HPACK pressure) |
| `grpc` | unary gRPC echo against the in-process gRPC server — exact round-trip through poseidon's length-prefixed framing + status trailers (hand-rolled client, no grpc-go dependency) |
| `grpc-sstream` / `grpc-cstream` / `grpc-bidi` | gRPC **server-**, **client-**, and **bidi-streaming** echoes — multi-message length-prefixed framing in both directions, asserted per message |
| `metrics` | scrapes the Prometheus `/metrics` exposition under load and asserts a known counter (drives the `MetricsCollector` → `WritePrometheus` path) |
| `health` | poseidon's `/readyz` readiness probe |
| `errors` | error-status paths (404/500/503) |
| `slow` | long-lived streams (concurrency pressure) |
| **spike** | a barrier that **unblocks after `-spike-after`** and blasts `-spike-vus` VUs at a heavy path (big-parse + large upload/download) for `-spike-dur` — the sharp burst |

**Feature coverage (honest).** *Covered:* TLS h2, inbound + outbound flow control,
the enlarged connection recv window (`ConnRecvWindow`), the full middleware onion
(Recovery, RequestID, RealIP, StructuredAccessLog, Tracing, SecurityHeaders, Gzip,
RateLimit, Metrics + its Prometheus exposition), request-body limits, chunked
streaming, HPACK header pressure, error-status handling, health probes, and
**gRPC** (unary + server-, client-, and bidi-streaming; framing + status
trailers). *Not exercised:* server **push**/`PUSH_PROMISE`, h2c (this harness is
TLS-only), ORIGIN/ALTSVC (poseidon has no server-side send API for these frames —
only the client-side receive handlers exist), the rapid-reset budget, and gRPC
reflection. It is a load/soak/profiling tool, not a conformance suite — the
excluded items are covered by the package unit/integration tests instead.

**Streaming, not buffering:** `-data-size` bodies are generated on the fly from a
single shared, read-only 32 KiB buffer (never a per-request allocation), so
`-data-size=10GiB` streams 10 GiB while server + client memory stays flat — the
report's `heap alloc max` shows tens of MiB, not GiB.

**Report:** RPS; error rate over **attempts** (a true fraction — in-flight
requests cut off at the deadline are *not* counted, and a genuine mid-stream body
failure *is*); **sustained** latency p50/p90/p95/p99 plus a separate **spike**
latency line (the burst's own tail, sampled independently); per-scenario iteration
counts; status-code distribution; and a **resource footprint** (max/avg heap
alloc, GC cycles, max goroutines, tracing spans, rendered `/metrics` size) — the
"minimal resources" signal. A healthy run reports **0 errors** even under the
spike. Flags: `go run ./loadtest/loadgen -h`.

> **Scale note:** the flags reach 10 GiB bodies + a 2-minute spike, but that scale
> needs real hardware (time/RAM/CPU). The harness is validated at reduced scale
> (hundreds of MiB, seconds) in the tests and smoke runs; dial the flags up on a
> dedicated load box. The `spike latency` line only appears once heavy iterations
> complete inside the spike window — a very short spike over huge bodies may end
> before any single `heavy` finishes.

## Run via Make

```sh
make loadtest                 # runs the h2c HTTP harness against a running server
LOADTEST=ghz make loadtest    # runs the gRPC harness
LOADTEST=k6  make loadtest    # runs the k6 harness
```

The target **no-ops with a hint** when the selected tool is not installed, so it
is safe to invoke in environments without the perf tooling.
