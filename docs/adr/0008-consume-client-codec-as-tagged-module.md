# ADR-0008: Consume the client frame/HPACK codec as a tagged module

- **Status:** Accepted (supersedes [ADR-0002](0002-reuse-client-codec-via-relative-replace.md))
- **Date:** 2026-07-06

## Context

[ADR-0002](0002-reuse-client-codec-via-relative-replace.md) wired the server to
the client's `frame`/`hpack` codec through a **relative `replace` directive**
(`replace github.com/lodgvideon/poseidon-http-client => ../poseidon-http-client`)
because the two repositories moved in lockstep and the client was not yet
published as a versioned module. ADR-0002 named the exit criterion explicitly:
*"When the client is published as a tagged module, the `replace` can be dropped
and the `require` pinned to a real version."*

That condition now holds — `poseidon-http-client` publishes semver tags
(`v0.6.0` is the version the server compiles against). Meanwhile the `replace`
approach had a fatal defect for a **library**: a `replace` directive in a
dependency's `go.mod` is ignored by downstream modules, and the `require` was
pinned to the placeholder pseudo-version `v0.0.0-00010101000000-000000000000`.
Any external `go get github.com/lodgvideon/poseidon-http-server@vX` therefore
failed to resolve — the published tags (v0.3.0/v0.4.0/v0.4.1) were **unbuildable
for every outside consumer**. The dependency is load-bearing (the client's
`frame`/`hpack` packages are imported across the `conn`, `server`, and
`middleware` packages), so this was not cosmetic: the module could not be
consumed at all.

## Decision

Drop the `replace` directive and pin the dependency to a published tag:

```go
require github.com/lodgvideon/poseidon-http-client v0.6.0
```

`go mod tidy` resolves the module from the Go module proxy and records its
checksums in a **committed `go.sum`**. The sibling checkout is no longer part
of the build in any environment: CI, Docker, and local `go build ./...` all
fetch the dependency the normal way.

## Consequences

- **Positive — the module is `go get`-able.** External consumers can import
  poseidon-http-server at a tag and build it with no special setup. This is the
  precondition for a real production release.
- **Positive — reproducible, verifiable builds.** The committed `go.sum` pins
  cryptographic checksums; `go mod verify` passes. Builds no longer depend on
  whatever the sibling working tree happens to be checked out at.
- **Positive — simpler CI/Docker.** The `git clone …/poseidon-http-client`
  step is removed from the `Dockerfile` builder stage (along with the
  `client_ref` build-arg) and from the CI/security workflows, so no build
  environment provisions a sibling checkout. With no sibling present, a green
  CI build is itself proof that the module is self-contained. (The
  `.github/workflows` edits land in a small follow-up, as pushing workflow
  files requires a token with `workflow` scope.)
- **Trade-off — codec upgrades are now an explicit version bump.** Previously a
  client fix flowed in automatically via the sibling checkout; now consuming a
  new codec release means bumping the `require` version and re-running
  `go mod tidy`. This is the normal, desirable cost of a versioned dependency:
  upgrades are deliberate and auditable rather than implicit.
- **Single source of truth is preserved.** The server still depends on the one
  battle-tested codec implementation; only the wiring mechanism changed (tagged
  module instead of relative path), so the no-duplication / no-drift benefit of
  ADR-0002 is retained.
