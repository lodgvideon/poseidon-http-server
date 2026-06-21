# ADR-0001: Zero-allocation contract on hot paths

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

poseidon-http-server targets high-throughput HTTP/2 and gRPC workloads where
per-request garbage-collector pressure dominates tail latency. Every inbound
stream touches the same small set of code paths: writing the `:status`
pseudo-header, encoding HPACK fields, accounting flow-control windows, and (for
gRPC) emitting status trailers. If each of those allocates, a server under load
produces millions of short-lived objects per second, and GC pauses — not CPU —
become the limiting factor.

The project's quality gates already enforce a benchmark baseline
(`make bench-gate`) and the README advertises "0 allocs/op" on hot paths, so the
allocation behaviour is a contract, not an aspiration.

## Decision

Treat the request/response hot path as allocation-free and enforce it with
benchmarks. Concretely:

- **Pre-compute common values.** `statusBytes` (`server/handler.go`) returns
  package-level `[]byte` constants for the common status codes (200, 201, 204,
  301, 302, 304, 400, 401, 403, 404, 500, 502, 503) and only falls back to
  `strconv.AppendInt` into a stack buffer for uncommon codes. The `:status`
  header name (`sColonStatus`) is a package-level slice, never re-created.
- **Pre-allocate header name byte slices** in the gRPC path (`sGRPCStatus`,
  `sGRPCMessage`, `sContentType`, `sContentGRPC` in `grpcserver/service.go`) and
  reuse a single `grpcResponseHeadersSlice` for the response headers.
- **Avoid string→[]byte churn** by parsing pseudo-headers directly from the
  decoded `[]hpack.HeaderField` (e.g. `buildRequest` switches on
  `string(h.Name)`, a comparison the compiler does not allocate for).
- **Batch flow-control work.** Connection-level WINDOW_UPDATE refunds are
  coalesced at `recvWindowRefundThreshold` (32 KiB) instead of per-DATA-frame,
  and Rapid Reset accounting (ADR-0007) is a single atomic increment with no
  allocation.
- **Keep the contract honest with benchmarks.** `bench_test.go` files in `conn`
  and `grpcserver` plus the committed bench baseline and `scripts/bench-gate.sh`
  fail CI on a regression.

## Consequences

- **Positive:** Predictable latency under load; GC pressure scales with payload
  bytes, not request count. The "0 allocs/op" claim is verifiable, not marketing.
- **Positive:** Forces a disciplined API — byte slices are reused, not freshly
  minted, which also keeps the HPACK encoder's dynamic table interactions
  cheap.
- **Negative:** The code is less idiomatic than naive `fmt.Sprintf`/string
  building; contributors must understand why a `[]byte` constant exists and not
  "simplify" it back into an allocation.
- **Negative:** The zero-alloc guarantee is confined to the **native** write
  path (`WriteHeaders`/`WriteData`/`WriteTrailers`). The stdlib-compatibility
  path (`Header()` map + `WriteHeader`) and buffering middleware such as Gzip
  (ADR-0006) intentionally allocate; the contract is scoped, not universal.
- **Negative:** Any new hot-path feature must ship with a benchmark or it can
  silently erode the baseline. The bench gate is the enforcement mechanism.
