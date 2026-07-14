# CLAUDE.md

Guidance for AI agents working in **poseidon-http-server** — a zero-allocation
HTTP/2 + gRPC server for Go, built on the `poseidon-http-client` codec
(`frame` + `hpack`). Drop-in `http.Handler` replacement (chi/echo/gin/net/http).

## Project shape

- **Language:** Go 1.24, single module `github.com/lodgvideon/poseidon-http-server`.
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
make bench-gate     # scripts/bench-gate.sh — fails on allocation/latency regression
make lint           # go vet ./... + golangci-lint run
make tidy           # go mod tidy
```

Fuzz targets exist in `conn/`, `server/`, `grpcserver/` (nightly via
`.github/workflows/fuzz.yml`). Run one locally with
`go test -run=^$ -fuzz=FuzzXxx ./<pkg>`.

## The zero-allocation contract (ADR-0001) — read before touching hot paths

Hot paths achieve **0 allocs/op** and this is enforced by `make bench-gate`, not
just advertised. Concretely:

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
this quirk, not a build failure. Latest released line: **v0.4.x** (client pinned
at v0.7.1 in go.mod).

## Working here

- Prefer the **codebase-memory** MCP graph tools for code discovery
  (`search_graph`, `trace_path`, `get_code_snippet`) before grep — the repo is
  indexed.
- CI = `ci.yml` (build/test/race/lint) + `security.yml` + `fuzz.yml` + `release.yml`;
  all Actions are pinned to commit SHAs (keep it that way for Dependabot).
