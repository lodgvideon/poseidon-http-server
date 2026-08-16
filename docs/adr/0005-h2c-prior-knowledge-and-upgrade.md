# ADR-0005: h2c support — prior knowledge vs HTTP/1.1 Upgrade

- **Status:** Accepted — amended 2026-07-31 (see *Amendment*)
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
- **Negative — only the `h2c` upgrade token is honoured.** Other upgrade
  protocols (WebSocket, etc.) are rejected with `400`; this server is HTTP/2-only.

## Amendment (2026-07-31) — RFC §3.2 conformance

The HTTP/1.1 conformance audit
([docs/rfc-analysis/HTTP1_SERVER_RECONCILIATION.md](../rfc-analysis/HTTP1_SERVER_RECONCILIATION.md))
found **11 MUST-level violations inside `handleHTTP1Upgrade` alone**, several of
them created by this ADR's original wording. Only the surface of the upgrade had
been built — recognise a token, write `101`, switch — while the §3.2 machinery
was missing entirely, and the acceptance test hid it by opening stream 1 itself
after the `101`, which a conformant client cannot do.

Corrected, with a `TestConformance_*` test per rule (see
[docs/RFC_COVERAGE.md](../RFC_COVERAGE.md)):

- **`Upgrade: h2` is no longer honoured.** *"A server MUST ignore an "h2" token
  in an Upgrade header field"* (RFC 7540 §3.2). The original text of this
  ADR promoted that violation to a documented feature; that sentence is
  withdrawn. `h2` over TLS is negotiated by ALPN and nothing else.
- **`HTTP2-Settings` is now required and validated** — exactly one field, whose
  value must be base64url decoding to a well-formed SETTINGS payload. *"A server
  MUST NOT upgrade the connection to HTTP/2 if this header field is not present
  or if more than one is present"* (RFC 7540 §3.2.1).
- **The upgrading request now receives a response.** It is seeded onto stream 1
  in the half-closed (remote) state via the new `conn.UpgradedRequest` option,
  because *"These frames MUST include a response to the request that initiated
  the upgrade"* (RFC 7540 §3.2) and *"stream 1 is used for the response"*
  (RFC 7540 §3.2). Registering stream 1 also makes the client's next stream
  3 for free. Previously the parsed request was discarded and a conformant
  client hung forever.
- **HTTP/1.0 requests no longer upgrade.** RFC 9110 §7.8 requires the Upgrade
  field be ignored, and §15.2 forbids a `1xx` response to an HTTP/1.0 client.
- **A missing `Host` field is now `400`**, per RFC 9112 §2.2.
- **Upgrade requests carrying content are declined.** Unread HTTP/1.1 body
  octets were previously handed to `conn.NewServerConn` and re-parsed as HTTP/2
  frames — a request-smuggling primitive. Declining is permitted: a server *"can
  respond to the request as though the Upgrade header field were absent"*.

The h2c Upgrade mechanism is **obsolete** in the current HTTP/2 specification:
RFC 9113 *"marks the HTTP2-Settings header field and the h2c upgrade token, both
defined in [RFC7540], as obsolete"* (RFC 9113 §11) and describes the usage
as *"never widely deployed and ... deprecated by this document"*
(RFC 9113 §3.1). Keeping the path — correctly implemented — was chosen over
removing it so existing upgrading clients keep working. If it is ever removed,
drop the `RFC7540` tag from `scripts/rfc-coverage-gate.sh` in the same commit
that deletes the tests.
