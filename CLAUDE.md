# CLAUDE.md

Guidance for AI agents working in **poseidon-http-server** — a zero-allocation
HTTP/2 + gRPC server for Go, built on the `poseidon-http-client` codec
(`frame` + `hpack`). Drop-in `http.Handler` replacement (chi/echo/gin/net/http).

## Project shape

- **Language:** Go 1.25, single module `github.com/lodgvideon/poseidon-http-server`.
- **Dependencies:** exactly **one** runtime dep — `poseidon-http-client` (see go.mod).
  The server links only its `frame` and `hpack` packages. Do **not** add
  third-party runtime deps without a strong reason; "no other deps" is a
  documented selling point (README).

## Package map

| Path | Responsibility |
|---|---|
| `conn/` | HTTP/2 connection + stream state machine — frame loop, flow control, HPACK sync, Rapid-Reset accounting. The performance-critical core. |
| `server/` | High-level `http.Handler`-compatible server: h2c, `/healthz`+`/readyz`, body limits, graceful drain. |
| `grpcserver/` | gRPC framing, status trailers, health check, reflection. |
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
only under concurrency — where, today, **no gate looks at all**. A connection-wide
write mutex serialises every stream on that connection no matter how many cores
are idle, so the allocation contract can be perfect and the server still not
scale.

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
  go test -run='^$' -bench='Parallel|FCOutCond' -benchmem \
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
  - `fcOutCond.Broadcast()` (6 sites, `Signal()` still 0) — **contended, O(N) in
    parked streams.** One connection-level WINDOW_UPDATE costs 4.4 ns with no
    waiters and 155 ns with 64.
  - `Server.mu` (taken per stream in `spawnStream`) — **measured, not
    contended**: 0.0009% of end-to-end mutex delay, and that sliver is
    `newproc`/`newobject`, not the mutex. Leave it alone.
  - `MetricsCollector.mu` (four map lookups per request) — **contended as cache
    traffic, not as waiting.** Barely visible in a mutex profile (an `RLock`
    seldom blocks), yet `RLock`/`RUnlock` on its reader counter are 21.6% of all
    CPU on a path that scales only 1.36× across 16 cores.

## Conventions

- **Commits:** Conventional Commits (`feat:`/`fix:`/`test:`/`deps:`/`chore:` …) —
  the CHANGELOG and versioning are driven by release-please.
- **Coverage floor:** 80% (`COVERAGE_MIN`). Untrusted-input paths are held to
  higher coverage — see `conn/server_untrusted_coverage_test.go`.
- **ADRs are authoritative.** 8 ADRs cover the alloc contract, goroutine model,
  gRPC framing, h2c, ResponseWriter interface, Rapid-Reset mitigation, and the
  tagged-module consumption of the client codec. Cite/update them when changing
  a decision.

## Releasing (has a known gotcha)

Versioning is release-please. It opens/updates the release PR correctly
(including for `deps:` commits) but **does not auto-tag on merge**. Releases are
currently cut **manually** after merging the `release-please--branches--main` PR:

```sh
gh release create vX.Y.Z --target <release-PR-merge-commit>
# then relabel the merged PR: autorelease: pending → autorelease: tagged
```

A green Release run with **no tag** and the PR stuck on `autorelease: pending` is
this quirk, not a build failure. Latest released line: **v0.7.x** (v0.7.1). The
client is pinned at **v0.11.0** in go.mod — check `go.mod` rather than this line,
which has been wrong before: the two versions are unrelated and drift apart.

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
