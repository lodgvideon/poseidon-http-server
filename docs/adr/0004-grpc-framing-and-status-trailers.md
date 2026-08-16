# ADR-0004: gRPC Length-Prefixed-Message framing + status-trailer design

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

gRPC runs on top of HTTP/2 with its own message framing and its own error model.
A request/response body is not a raw protobuf blob: it is a sequence of
**Length-Prefixed Messages (LPM)**, each a 1-byte compression flag plus a 4-byte
big-endian length plus that many payload bytes. The RPC outcome is **not** the
HTTP `:status` (which is `200` even for failed RPCs); it is carried in HTTP/2
**trailers** as `grpc-status` (a numeric code) and `grpc-message`.

The `grpcserver` package layers gRPC onto the native `server.Handler` /
`server.ResponseWriter` API (ADR-0006) without pulling in `google.golang.org/grpc`.
It needs to encode/decode LPM and emit the trailer-based status correctly so that
standard gRPC clients interoperate.

## Decision

Implement gRPC framing and status as small, self-contained pieces.

**LPM framing (`grpcserver/framing.go`).** `EncodeLP`/`DecodeLP` handle the
5-byte header (`grpcMessageHeader`) and payload. Decoding enforces a maximum
message size (`maxRecvMessageSize`, 4 MiB) via `DecodeLPWithLimit`, returning
`ErrMessageTooLarge` rather than allocating an attacker-controlled buffer. A
byte-slice variant (`DecodeLPFromBytes`) checks the size limit **before** the
`grpcMessageHeader+length` arithmetic to avoid integer overflow.

**Status codes (`grpcserver/status.go`).** The full canonical gRPC code set is a
typed `Code` with a `String()` method; `RPCStatus{Code, Message}` is the
error-bearing value and implements `error` with the standard
`rpc error: code = ... desc = ...` format.

**Trailer-based status.** Every RPC — success or failure — completes by writing
`grpc-status`/`grpc-message` as HTTP/2 trailers via
`ResponseWriter.WriteTrailers`. `statusToHPack` (`service.go`) builds the trailer
fields from pre-allocated header-name byte slices (ADR-0001). Errors use a
**trailers-only** response: `writeGRPCError` sends headers (`:status 200` +
`content-type: application/grpc`) then the status trailers, with no body — exactly
what a gRPC client expects for an early failure.

## Consequences

- **Positive — wire-compatible with standard gRPC clients** without depending on
  `google.golang.org/grpc`, keeping the dependency surface tiny.
- **Positive — the status model maps cleanly onto HTTP/2 trailers**, which the
  native `ResponseWriter` already supports (trailers are sent as a HEADERS frame
  with END_STREAM; see ADR-0006), so no special-casing in the core write path.
- **Positive — bounded memory on decode.** The size limit is enforced on every
  decode path, and the byte-slice path is overflow-safe, so a malformed or
  hostile length prefix cannot trigger a huge allocation.
- **Positive — zero-allocation status emission.** Trailer header names are
  package-level byte slices, honouring the ADR-0001 contract on the gRPC hot path.
- **Negative — compression flag is parsed but not auto-applied.** The framing
  carries the `FlagCompressed` bit; per-message compression negotiation
  (`grpc-encoding`) is the caller's responsibility, not transparently handled by
  the framing layer.
- **Negative — `grpc-status-details-bin`** (rich error details) has a header
  constant defined but the helper `StatusToTrailers` emits only `grpc-status` and
  `grpc-message`; structured details must be added by the handler if needed.
- **Negative — 4 MiB default cap** may be too small for some payloads; it is a
  constant today rather than a per-service option, so larger messages require a
  code change to `maxRecvMessageSize` or use of `DecodeLPWithLimit` directly.
- **Negative — deliberate deviation from RFC 9110 §6.5.1.** That section closes
  with: *"Because of the potential for trailer fields to be discarded in
  transit, a server SHOULD NOT generate trailer fields that it believes are
  necessary for the user agent to receive"* (RFC 9110 §6.5.1). `grpc-status`
  is exactly such a field — it carries the outcome of the call, and every
  terminal path in `grpcserver/service.go` ends by emitting it as a trailer.
  This is not incidental; it is what the gRPC protocol specifies, so the
  deviation is accepted rather than fixed.

  The SHOULD NOT states its own rationale — trailers may be *discarded in
  transit* — and RFC 9110 §6.5.1 also supplies the condition that removes it:
  *"The presence of the keyword "trailers" in the TE header field … indicates
  that the client is willing to accept trailer fields, on behalf of itself and
  any downstream clients … only that the trailer section(s) will not be dropped
  by any of the clients"* (RFC 9110 §6.5.1). The gRPC-over-HTTP/2 spec
  requires clients to send `te: trailers`, so in a conformant gRPC exchange the
  hazard the rule guards against does not arise.

  **Residual risk, named rather than waved away:** this server does not verify
  that `te` was sent. `HeaderTE` is declared in `grpcserver/status.go` and has
  no production reader. A client that omits `te: trailers` and sits behind an
  intermediary that drops trailer sections would lose the call outcome silently.
  Enforcing it — rejecting a `te`-less request — was considered and declined:
  it would break hand-rolled and some proxied clients that work today, for a
  gain that is on paper only, since the check would fold into the existing
  content-type pass in `grpcserver/service.go` and cost nothing to add later if
  that trade ever changes.
