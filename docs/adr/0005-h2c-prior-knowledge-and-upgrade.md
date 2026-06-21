# ADR-0005: h2c support — prior knowledge vs HTTP/1.1 Upgrade

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

Many deployments terminate TLS at a load balancer or service mesh and speak
**cleartext HTTP/2 (h2c)** between the proxy and the application. Without TLS
there is no ALPN to negotiate `h2`, so the server must figure out, from the first
bytes on the wire, whether a connecting client intends to speak HTTP/2. RFC 7540
defines two cleartext start mechanisms:

1. **Prior knowledge (§3.4):** the client sends the HTTP/2 connection preface
   (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) immediately. Used by gRPC clients and any
   client configured for h2c directly.
2. **HTTP/1.1 Upgrade (§3.2):** the client sends a normal HTTP/1.1 request with
   `Connection: Upgrade` and `Upgrade: h2c`; the server replies `101 Switching
   Protocols` and then both sides switch to HTTP/2.

The default, TLS-fronted path needs neither of these — it expects a direct HTTP/2
connection. h2c support must be opt-in and must not slow down the default path.

## Decision

Gate h2c behind `Options.H2C` (default `false`). When enabled, `server.Serve`
routes each accepted connection through `detectAndServe` (`server/h2c.go`) which
**peeks** the first bytes without consuming them (a buffered reader) and branches:

- **Bytes match the HTTP/2 preface** → prior-knowledge h2c. Hand the buffered
  reader straight to `conn.NewServerConn` via a `bufioConn` wrapper so the peeked
  bytes are not lost.
- **Bytes look like HTTP/1.1** → parse the request with `http.ReadRequest`. If it
  carries `Upgrade: h2c` (or `h2`), reply `101 Switching Protocols` and continue
  as HTTP/2 over the same connection. Otherwise reply `400 Bad Request` ("Only
  h2c supported") and close.

When `H2C` is `false`, `serveConn` is used directly with no peeking, so the
TLS/direct-HTTP/2 path carries zero detection overhead.

## Consequences

- **Positive — both RFC 7540 cleartext entry points are supported**, so gRPC
  (prior knowledge) and HTTP/1.1-upgrading clients both work behind a
  TLS-terminating proxy. h2c is the documented default for the
  `cmd/poseidon-server` binary and its container image.
- **Positive — the peek-based detector is non-destructive.** The `bufioConn`
  wrapper presents the already-buffered bytes to `NewServerConn`, so the preface
  read in `conn` still sees a complete, correct byte stream.
- **Positive — zero cost when disabled.** The default TLS path never allocates a
  detection buffer or parses an HTTP/1.1 request.
- **Negative — h2c is plaintext.** It is intended for trusted networks (behind a
  proxy / inside a mesh), not the public internet; this is a deployment
  responsibility, not something the server can enforce.
- **Negative — the Upgrade dance buffers one HTTP/1.1 request.** A malformed or
  trickled HTTP/1.1 request is bounded by the connection's read deadline (derived
  from the context) and the handshake timeout in `conn`, but the Upgrade path is
  inherently a little heavier than prior knowledge.
- **Negative — only `h2c`/`h2` upgrade tokens are honoured.** Other upgrade
  protocols (WebSocket, etc.) are rejected with `400`; this server is HTTP/2-only.
