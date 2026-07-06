# ADR-0002: Reuse the client frame/HPACK codec via a relative `replace`

- **Status:** Superseded by [ADR-0008](0008-consume-client-codec-as-tagged-module.md)
- **Date:** 2026-06-21

> **Superseded (2026-07-06):** the client is now published as a tagged module,
> so the relative `replace` was dropped in favour of a versioned `require`
> (`poseidon-http-client v0.6.0`) with a committed `go.sum`. This was required
> to make the server module consumable via `go get`. See
> [ADR-0008](0008-consume-client-codec-as-tagged-module.md). The record below is
> retained for history.

## Context

A server needs exactly the same HTTP/2 wire primitives a client does: a frame
reader/writer (`frame.Framer`, `frame.Handler`, the SETTINGS/HEADERS/DATA/
RST_STREAM/GOAWAY/PING frame types) and an HPACK encoder/decoder. That codec
already exists, battle-tested, in the sibling project
[`poseidon-http-client`](https://github.com/lodgvideon/poseidon-http-client).
Re-implementing framing and HPACK in this repository would duplicate hundreds of
lines of subtle, security-sensitive code and let the two implementations drift.

The two repositories are developed in lockstep but are not yet published as
versioned modules. We needed a way to consume the client's `frame` and `hpack`
packages from server code while both repos are still moving.

## Decision

Depend on the client module and wire it to the local checkout with a **relative
`replace` directive** in `go.mod`:

```go
require github.com/lodgvideon/poseidon-http-client v0.0.0-00010101000000-000000000000

replace github.com/lodgvideon/poseidon-http-client => ../poseidon-http-client
```

Server code imports `github.com/lodgvideon/poseidon-http-client/frame` and
`.../hpack` directly (see `conn/server_conn.go`, `server/server.go`,
`middleware/gzip.go`). The client repo is expected to be checked out as a
**sibling directory** `../poseidon-http-client`.

## Consequences

- **Positive:** Single source of truth for framing and HPACK; no codec
  duplication, no drift between client and server wire handling. Bug fixes in
  the codec benefit both sides immediately.
- **Positive:** Local development is friction-free once the sibling repo is
  cloned — `go build ./...` and `go vet ./...` just work.
- **Negative — CI must clone the sibling.** The relative path does not exist in
  a fresh CI checkout, so **every** CI job (`.github/workflows/ci.yml`) prepends
  a step that `git clone --depth 1 ...poseidon-http-client.git
  ../poseidon-http-client` before building. Forgetting this in a new job makes
  the build fail with an unresolved replace target.
- **Negative — Docker must clone the sibling.** The build context is a single
  repo, so the `Dockerfile` builder stage lays the source out as
  `/src/poseidon-http-server` + `/src/poseidon-http-client` and clones the client
  (pinned via the `client_ref` build-arg, default `main`) into the sibling path
  before `go build`. This is documented at the top of the Dockerfile precisely
  because a naive in-image build would otherwise fail.
- **Negative — no committed `go.sum`.** Because the dependency is resolved from a
  local path rather than the module proxy, the server module ships without a
  `go.sum`; the Docker builder runs `go mod download all || true` and lets `go`
  record checksums at build time.
- **Future migration:** When the client is published as a tagged module, the
  `replace` can be dropped and the `require` pinned to a real version, removing
  the clone steps from CI and Docker. Until then, the sibling-clone consequence
  is the price of sharing the codec.
