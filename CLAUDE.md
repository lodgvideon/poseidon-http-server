# CLAUDE.md

Guidance for AI agents working in **poseidon-http-server** — a zero-allocation
HTTP/2 + HTTP/3 + gRPC server for Go, built on the `poseidon-http-client`
codec. Drop-in `http.Handler` replacement (chi/echo/gin/net/http).

## Project shape

- **Language:** Go 1.25, single module `github.com/lodgvideon/poseidon-http-server`.
- **Dependencies:** one **direct** requirement — `poseidon-http-client` (see
  go.mod). Do **not** add third-party runtime deps without a strong reason; "no
  other deps" is a documented selling point (README).

  **Which client packages get linked is measured here, not listed.** This file
  used to assert "the server links only its `frame` and `hpack` packages". That
  sentence has been wrong twice — most recently since the HTTP/3 server landed
  (#47) — because a fixed list cannot survive the next package being added. Ask
  the toolchain instead:

  ```sh
  # every client package linked, transitively
  go list -deps ./... | grep poseidon-http-client
  # which of our packages imports which, directly
  go list -f '{{$p := .ImportPath}}{{range .Imports}}{{$p}} -> {{.}}
  {{end}}' ./... | grep poseidon-http-client | sort -u
  # third-party MODULES a given package drags in
  go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./server | sort -u
  ```

  What that returned on 2026-08-17 (yours wins if it differs): 7 client packages
  imported directly, 12 linked transitively. `server`, `conn`, `grpcserver`,
  `middleware` and the `poseidon-server` binary each link exactly one
  third-party module, the client — the selling point holds for them.
  `http3server` links three (`+ golang.org/x/crypto`, `golang.org/x/sys`), and
  `loadtest/loadgen` five. See `docs/HTTP3_SERVER_GUIDE.md#dependencies`.

  This is load-bearing for upgrade risk, not tidiness. A client bump was cleared
  once on the reasoning "the server links only client `frame`/`hpack`,
  unchanged". That reasoning is dead: a client release touching `quic`, `http3`
  or `qpack` now reaches this repo's code. Run the commands; do not quote a list.

## Package map

| Path | Responsibility |
|---|---|
| `conn/` | HTTP/2 connection + stream state machine — frame loop, flow control, HPACK sync, Rapid-Reset accounting. The performance-critical core. |
| `server/` | High-level `http.Handler`-compatible server: h2c, `/healthz`+`/readyz`, body limits, graceful drain. |
| `server/pprof/` | The opt-in `/debug/pprof/` handler, and **only** place in the module that imports `net/http/pprof`. Split out of `server/` because that import registers on `http.DefaultServeMux` from its `init`, so it armed pprof for every consumer (#210). `server/pprof_isolation_test.go` fails if the edge comes back. |
| `grpcserver/` | gRPC framing, status trailers, health check, reflection. |
| `http3server/` | HTTP/3 over QUIC (RFC 9114). The only package with a wider dependency footprint — see `docs/HTTP3_SERVER_GUIDE.md`. |
| `internal/httpfields/` | The field rules HTTP/2 and HTTP/3 share, **both directions**. Inbound: field-name/value characters, the connection-specific-field ban, `TE: trailers`, request pseudo-headers. Outbound: what a response may not carry, and 1xx not being a final status. Imported by `conn/`, `server/` and `http3server/`; see ADR-0010 before adding anything here. A receiver rejects the message, a sender drops the field — that asymmetry is deliberate. |
| `middleware/` | gzip, metrics (Prometheus), ratelimit, realip, security headers, slog access log, tracing. |
| `cmd/poseidon-server/` | The 12-factor `poseidon-server` binary. |
| `examples/` | Runnable example servers (http, tls, secure, h2c, grpc, push, observability). |
| `loadtest/loadgen/` | Load/soak + profiling harness (see `loadtest/README.md`). |
| `deploy/` | `Dockerfile` (distroless, repo root), Helm chart, raw k8s manifests. |
| `docs/adr/` | Architecture Decision Records — read these before changing core behavior. |

## Commands (all via `make`)

```sh
make build          # ldflags-stamped binary → bin/poseidon-server
make test           # go test -count=1 ./...
make test-race      # go test -race -count=1 ./...   (CI runs with -race)
make coverage-gate  # race coverage + scripts/coverage-gate.sh (min 80%, COVERAGE_MIN)
make bench          # benchmarks, -benchmem
make bench-gate     # scripts/bench-gate.sh — per-metric gate, see below
make contention-gate           # scripts/contention-gate.sh — same-runner A/B, see below
make contention-gate-selftest  # assert that gate still reaches red AND green
make lint           # go vet ./... + golangci-lint run
make tidy           # go mod tidy
```

Fuzz targets exist in `conn/`, `server/`, `grpcserver/` (nightly via
`.github/workflows/fuzz.yml`). Run one locally with
`go test -run=^$ -fuzz=FuzzXxx ./<pkg>`.

## The zero-allocation contract (ADR-0001) — read before touching hot paths

Hot paths achieve **0 allocs/op**. `make bench-gate` enforces that count
*exactly* — but only that one, and only locally. Read the last bullet below
before quoting a green gate as proof of anything else. Concretely:

- `statusBytes` (`server/handler.go`) and the gRPC header slices
  (`grpcserver/service.go`) are **package-level `[]byte` constants that are
  reused, never re-minted**. Do not "simplify" them into `fmt.Sprintf`/string
  building — that reintroduces allocations and breaks the bench gate.
- Pseudo-headers are parsed directly from `[]hpack.HeaderField` (switch on
  `string(h.Name)` — a comparison the compiler does not allocate for).
- The contract is **scoped to the native write path**
  (`WriteHeaders`/`WriteData`/`WriteTrailers`). The stdlib-compat path
  (`Header()` map + `WriteHeader`) and buffering middleware (gzip, ADR-0006)
  **intentionally allocate** — don't chase allocs there.
- **Any new hot-path feature must ship with a benchmark**, or it can silently
  erode the baseline.
- **What the gate actually checks (#138).** `scripts/bench-gate.sh` treats the
  three metrics differently, because they are not equally measurable:
  `allocs/op` is **exact** (any increase benchstat calls significant fails,
  including 0 → N); `sec/op` is gated at **+50%** (`BENCH_THRESHOLD`), a floor
  set above the drift byte-identical code shows on a shared host, so a smaller
  latency regression is invisible to it; `B/op` is **reported and not gated**
  (`BENCH_GATE_BYTES=0`, pending #99). Two further limits: there is **no
  committed baseline** in `testdata/benchmarks/`, so a first run records one
  and passes without comparing (#101); and **CI does not run this gate** —
  `ci.yml`'s `bench` job only smoke-runs the benchmarks once. It is a local
  tool, not a merge gate.

## Locks cost more than allocations — read alongside the alloc contract

Allocations are evil; **locks are worse.** When a design trades a lock for an
allocation, take the allocation. When ordering performance work, rank contention
above allocation count.

Why: an allocation is a steady tax the GC amortises, and `make bench-gate`
already measures it. Lock contention is superlinear in core count and appears
only under concurrency. A connection-wide write mutex serialises every stream on
that connection no matter how many cores are idle, so the allocation contract can
be perfect and the server still not scale.

**What now looks at it (#121).** `make contention-gate` runs
`scripts/contention-gate.sh`: a same-runner A/B on `conn`'s
`_SharedConn`/`_PerConn` pairs that builds both arms locally, runs them
interleaved, and fails when the shared-connection number regresses beyond
`CONTENTION_THRESHOLD` (default +30%). Know its limits before quoting it:

- It is **nightly and non-blocking** (`.github/workflows/perf-nightly.yml`), not
  a required PR check. The false-positive rate of a timing gate on GitHub's
  shared runners has never been measured for this repository; blocking on an
  unmeasured flake rate is how a check gets disabled.
- It gates **`ns_Shared(N)`**, not a ratio — which is what #121 proposed. Worst
  drift over interleaved identical-code passes: `ns_Shared(N)` 8.4%,
  `Shared(N)/Per(N)` 23.4%, `Shared(N)/Per(1)` 92.7%, speedup ratio 63.5%. Every
  normalisation was louder than the number it was meant to stabilise. The
  `_PerConn` control is kept as a **guard** — below a 2× shared/control ratio the
  machine cannot resolve a lock and the pair is reported NOT MEASURABLE rather
  than judged — and as printed context. It does **not** classify a regression as
  contention or work: that classifier's contention branch could not be made to
  fire (below).
- **It cannot see a newly added lock, and neither can anything else here.**
  Wrapping the whole of `writeServerHeaders` in a second connection-wide mutex
  moved the shared arm +2.22% and the control +2.53% — inside noise. `wmu`
  already serialises the path completely, so there is no parallelism left for
  another lock to take away. What the gate detects is **the serialised section
  getting longer**. Do not cite a `_SharedConn` benchmark as evidence that a new
  lock is free; see #205.
- It covers the **HEADERS and DATA pairs only**. `RegisterStream` is
  allocator-bound and its control's median swung 175 ns → 672 ns on identical
  code; the `_TCP` pair cannot resolve a change to what `wmu` protects (#197).
- Unlike `bench-gate` it has **no self-baselining branch**, and
  `scripts/contention-gate-selftest.sh` asserts on every nightly run that the
  gate still reaches red, green, not-measurable and nothing-compared.

Rules that follow:

- **Every new hot-path design must state what it does *instead* of taking a
  lock** — atomics, per-stream or per-P sharding, a single-owner goroutine, an
  immutable snapshot, or a lock-free queue. "It takes a mutex" is an answer that
  needs a reason next to it.
- **Every hot-path benchmark needs a `RunParallel` variant.** A single-goroutine
  `ns/op` says nothing about a lock. As of 2026-08-15 the repo had 27 benchmarks
  and zero parallel ones, which is why this section exists. The parallel ones now
  live in `*_parallel_test.go` (`conn/`, `server/`, `middleware/`,
  `server/integration/`); each `_SharedConn` benchmark is paired with a
  `_PerConn` control doing identical work with the lock out of the picture,
  because a parallel benchmark without a control cannot tell a scalable path
  from a benchmark that never reached the lock. Get the curve with

  ```sh
  go test -run='^$' -bench='Parallel|FCOut' -benchmem \
          -benchtime=500ms -count=10 -cpu=1,2,4,8,16 ./conn ./server ./middleware
  ```

  and the attribution with `-mutexprofile`/`-blockprofile`: `ns/op` is
  circumstantial for a lock claim, a mutex profile is not.
- This rule is **in tension with ADR-0003**, which records "every write is
  serialised under one mutex" (`conn.ServerConn.wmu`) as a deliberate choice, and
  with `CONTEXT.md`'s connection entry. Changing that needs a superseding ADR and
  a measurement, not a quiet edit — see issue #95, which exists to produce the
  measurement first.
- Known sites to weigh against this rule, each now carrying the #95 measurement
  (2026-08-16, Ryzen 7 7700 8C/16T, go1.26.6; method and spreads in that PR):
  - `wmu` (15 call sites, all writes) — **contended, and it is the ceiling.**
    99.2% of all end-to-end mutex delay. One connection's HEADERS throughput
    never improves past one core and is ~34% worse at 16; sixteen connections
    doing the identical work improve 6.3×.
  - Outbound flow-control wakeups — **fixed in #118, keep it fixed.** Was one
    `sync.Cond` for the whole connection (6 `Broadcast()` sites, `Signal()` 0),
    so every grant woke every parked writer: a connection-level WINDOW_UPDATE
    cost 5.5 ns with no waiters and 146 ns with 64, and a per-stream one — which
    can only ever release the stream it names — 19 ns and 395 ns.
    `conn/fc_waiters.go` replaced the condition variable with a private channel
    per waiter on two intrusive lists, so a grant costs what it releases rather
    than what is parked: 4.9 ns and 24 ns at 64 waiters (−96.6% and −93.9%,
    n=30). Both are now flat in the waiter count. Do not reintroduce a shared
    condition variable here; `BenchmarkFCOutStreamGrant` and
    `BenchmarkFCOutCondBroadcast` are what would notice.
  - `Server.mu` (taken per stream in `spawnStream`) — **measured, not
    contended**: 0.0009% of end-to-end mutex delay, and that sliver is
    `newproc`/`newobject`, not the mutex. Leave it alone.
  - `MetricsCollector.mu` — **fixed in #120, keep it fixed.** The request path
    took four map lookups under an `RLock`. It never blocked, and that was the
    point: `RLock`/`RUnlock` on the reader counter were 13.3% of all CPU at
    `-cpu=16` — 100% of the `Int32.Add` traffic — on a path that scaled 1.27×
    from 1 to 16 cores on the run the fix was judged against, and 1.26–1.62×
    across runs.
    `middleware/metrics.go` now publishes an immutable `metricViews` snapshot
    behind an `atomic.Pointer`, rebuilt under the write lock on insert and on
    sweep, so a request does one atomic load and a map lookup and takes **no
    lock and no allocation**, the overflow path included. Cost is 40–78% lower
    at every core count; the *scaling factor* did not improve, because what
    remains is genuinely serial — per-request atomics, tracked in #201. Do not
    put a shared lock back on this path; `middleware/bench_parallel_test.go` is
    what would notice.

## Conventions

- **Commits:** Conventional Commits (`feat:`/`fix:`/`test:`/`deps:`/`chore:` …) —
  the CHANGELOG and versioning are driven by release-please.
- **Coverage floor:** 80% (`COVERAGE_MIN`). Untrusted-input paths are held to
  higher coverage — see `conn/server_untrusted_coverage_test.go`.
- **ADRs are authoritative.** `docs/adr/` is the index; take the count from
  `ls docs/adr/[0-9]*.md`, not from this file — the number written here said 8
  while there were 9, which is what a count in prose does. They cover the alloc
  contract, the goroutine model, gRPC framing, h2c, the `ResponseWriter`
  interface, Rapid-Reset mitigation, the tagged-module consumption of the client
  codec, **stream state as one value** (ADR-0009 — the record behind
  `streamState`/`streamTable` and the four rounds of stream-lifecycle defects
  that produced them; the one an agent touching `conn/` needs first), and
  **message rules above the transport** (ADR-0010 — why `internal/httpfields`
  exists and what may go in it; the one an agent touching either request path
  needs). Cite/update them when changing a decision.

- **Two transports, one set of message rules.** `conn/` (HTTP/2) and
  `http3server/` (HTTP/3) share no code and never will share much — but RFC 9114
  §4.1/§4.2/§4.3 restates RFC 9113 §8.2.1/§8.2.2/§8.3 nearly clause for clause,
  and for a while only `conn/` enforced any of it. `http3server` accepted
  `Transfer-Encoding`, CR/LF in field values, uppercase field names and duplicate
  pseudo-headers that the HTTP/2 door of the same binary refused — a smuggling
  and header-injection differential at the next HTTP/1.1 hop, not a conformance
  nit (issue #209, ADR-0010). Before adding a receiver-side check to either
  package, ask whether it is a property of the **message** or of the
  **transport**. If the message, it goes in `internal/httpfields` and both call
  it; only the reporting differs (PROTOCOL_ERROR vs H3_MESSAGE_ERROR).

## Releasing (has a known gotcha)

Versioning is release-please. It opens/updates the release PR correctly
(including for `deps:` commits) but **does not auto-tag on merge**. Releases are
currently cut **manually** after merging the `release-please--branches--main` PR:

```sh
gh release create vX.Y.Z --target <release-PR-merge-commit>
# then relabel the merged PR: autorelease: pending → autorelease: tagged
```

A green Release run with **no tag** and the PR stuck on `autorelease: pending` is
this quirk, not a build failure. For the released line ask `gh release list -L 1`,
and for the client pin read `go.mod` — both numbers used to be written out here
and both went stale (the client line said v0.11.0 after #184 moved it to
v0.13.0). They are unrelated versions and they drift apart.

## Code discovery: two graphs, and which one answers what

Both are indexed. They are not redundant — reach for them in this order.

**CodeGraph (`codegraph_explore`) — default first stop.** One call answers "how
does X work", "how does X reach Y", or "survey this area", returning verbatim
source grouped by file plus the call paths and a blast-radius summary. It
**auto-syncs** via a file watcher (~2s debounce), so it is current as you edit,
and it prepends a staleness banner naming the files it has not yet re-read —
believe that banner and read those files directly.

**codebase-memory (`query_graph`) — for the questions CodeGraph cannot ask.** Its
Cypher surface carries per-function complexity and hot-path properties that
matter specifically here: `alloc_in_loop`, `linear_scan_in_loop`,
`transitive_loop_depth`, `loop_depth`, `recursive`. Those are the zero-allocation
contract and the contention work expressed as a query — e.g. find every function
that allocates inside a loop on a path reachable from the write path. CodeGraph
has no equivalent. It does **not** auto-sync: re-index after a batch lands, and
check the `head_sha` it is stamped with against your current HEAD before trusting
a line number.

Either way, prefer a graph over `grep` for anything structural. Use `grep` for
text, configs, and non-code files, and always `Read` a file before editing it.

## Worktrees

Worktrees live in **`.claude/worktrees/<name>/`** — that is the project's
convention, so the `using-git-worktrees` skill should use it without asking. The
directory is ignored in `.gitignore` (not only in `.git/info/exclude`), so the
protection survives a fresh clone.

**Each worktree needs its own CodeGraph index.** Run `codegraph init` once inside
a new worktree; the root index does not cover it, and `codegraph.json` explicitly
excludes `.claude/worktrees/**` from the root project. That exclusion is not
tidiness: the four worktrees present when this was written held **576 `.go` files
against the root's 155**, so indexing them together would report every symbol
five times and make the graph worse than no graph.

Querying from the wrong index is the same failure as a stale ticket premise —
plausible answers with line numbers that moved. Confirm which project path you
are querying before trusting an offset.

## Working here

- Code discovery goes through a graph, not `grep` — see the section above for
  which of the two answers what.
- CI = `ci.yml` (build/test/race/lint) + `security.yml` + `fuzz.yml` + `release.yml`;
  all Actions are pinned to commit SHAs (keep it that way for Dependabot).
