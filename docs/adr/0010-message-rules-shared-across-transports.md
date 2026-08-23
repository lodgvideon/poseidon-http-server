# ADR-0010: Message rules live above the transport that carries them

- **Status:** Accepted
- **Date:** 2026-08-23

## Context

This server speaks HTTP over two transports. `conn/` implements HTTP/2 over TCP
(RFC 9113); `http3server/` implements HTTP/3 over QUIC (RFC 9114). They share no
code: `http3server` imports neither `conn` nor `server`, and reimplements the
request path from decoded field section to `http.Request`.

Most of what the two do differently is genuinely different — frame layout, flow
control, HPACK versus QPACK, PROTOCOL_ERROR versus H3_MESSAGE_ERROR. But some of
what they do is not about the transport at all. Whether `Transfer-Encoding` may
appear in a field section, whether a field value may contain CR, whether a field
name may contain an uppercase octet, whether `:method` may appear twice — these
are properties of an HTTP *message*. RFC 9114 §4.1/§4.2/§4.3 restates RFC 9113
§8.2.1/§8.2.2/§8.3 nearly clause for clause, because the rules are the same
rules.

Those rules were implemented once, unexported, inside `conn/field_validation.go`.
`http3server` could not reach them, so it had none of them. Measured against
`buildRequest` before this ADR, the HTTP/3 path accepted every one of:

- `connection`, `proxy-connection`, `keep-alive`, `transfer-encoding`, `upgrade`
- CR, LF and NUL anywhere in a field value; leading or trailing whitespace
- uppercase and empty field names; an interior colon in a name
- `te` carrying anything other than `trailers`
- duplicate pseudo-headers, pseudo-headers after regular fields, userinfo in
  `:authority`

while the HTTP/2 path on the same binary refused all of them (issue #209).

Two of those have consequences past conformance. A request arriving over HTTP/3
carrying an attacker-chosen `Transfer-Encoding`, or a CRLF-split field value, and
then forwarded to an HTTP/1.1 backend, is a request-smuggling and
header-injection differential between two front doors of one process. The class
of defect is not "somebody forgot a check": it is that the code had no place
where such a check could be written once.

The structural reading is the same one ADR-0009 records for stream state. `conn`
measures I=0.00, A=0.00 → D=1.00 on Martin's metrics: maximally stable, zero
exported abstraction, and volatile. Everything depends on it and nothing can
extend it, so a second transport had no option but to copy — and a copy drifts.

## Decision

**Rules that are properties of an HTTP message live in `internal/httpfields`, and
every transport calls them. Rules that are properties of a transport stay in that
transport's package.**

`internal/httpfields` owns:

- the RFC 9110 §5.5 / RFC 9113 §8.2.1 / RFC 9114 §4.2 field-name and field-value
  character rules (`Prohibited`)
- the connection-specific-field ban and the `TE: trailers` exception (`Prohibited`)
- the trailer-section rule that a trailer carries no pseudo-header (`Prohibited`)
- request pseudo-header presence, uniqueness, ordering, and `:authority` userinfo
  (`ValidRequestPseudoHeaders`)

`conn/` and `http3server/` keep everything that needs to know about frames,
streams, dynamic tables, or error codes — including **how** a malformed message
is reported, which differs: RFC 9113 §8.1.1 makes it a stream error of type
PROTOCOL_ERROR, RFC 9114 §4.1.2 a stream error of type H3_MESSAGE_ERROR. The
shared package returns a boolean and names no error code, so neither transport
has to bend to the other.

The package is `internal/`, not public. The dependency inversion this ADR is
about is inside the module; exporting it would add a public contract to maintain
forever in exchange for nothing.

Two constraints bind anything added here:

1. **Allocation-free.** `Prohibited` runs once per decoded field inside the HTTP/2
   decode callback (`conn/server_handler.go`). Length-first switches and
   `string(b) == "lit"` are load-bearing, not style. `TestProhibited_NoAllocations`
   and `TestValidRequestPseudoHeaders_NoAllocations` pin it.
2. **Transport-agnostic.** If a rule needs to know which transport is asking, it
   does not belong here.

## Consequences

- **Positive — the gap is closed and cannot silently reopen.** Both transports
  call one implementation. `http3server/fieldvalidation_test.go` pins 26 rejection
  cases and 10 acceptance cases on the HTTP/3 path; disabling the two call sites
  turns all 26 red.
- **Positive — `conn` gets less concrete without getting slower.** A same-runner
  interleaved A/B of `BenchmarkOnHeaders` across the move (n=6, Ryzen 7 7700,
  go1.25) showed 5 allocs/op → 5 allocs/op, B/op byte-identical, and sec/op
  1.101µs → 1.082µs (p=0.699 — no detectable change). The cross-package call does
  not cost anything measurable because these functions contain loops and were
  never inlined into the callback in the first place.
- **Positive — a third transport is cheap.** Whatever comes next gets the message
  rules by importing them.
- **Negative — a new place to look.** A reader tracing "why was my request
  rejected" now has two files to open instead of one. The call sites in
  `conn/server_handler.go` and `http3server/server.go` cite the section numbers to
  make the hop obvious.
- **Negative — the boundary has to be defended.** The temptation will be to push
  the *next* almost-shared rule in here even when it needs transport knowledge.
  The test is the one stated above: if it needs to know who is asking, it stays
  out.
- **Neutral — this does not make `http3server` conformant.** It closes one class.
  What else RFC 9114 requires that `http3server` does not do is tracked separately;
  in particular this server still does not surface a trailer section at all, and
  `decodeRequest` discards one rather than validating it, which is why
  `Prohibited` is called with `isTrailer=false` on the HTTP/3 path.
