# ADR-0007: Rapid Reset (CVE-2023-44487) mitigation strategy

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

CVE-2023-44487 ("HTTP/2 Rapid Reset") is a denial-of-service technique that
abuses HTTP/2 stream multiplexing: a client opens a stream (HEADERS), the server
begins doing work for it, and the client immediately sends `RST_STREAM` to cancel
it — then repeats, thousands of times per second. Each open-then-reset cycle is
cheap for the attacker but forces the server to allocate a stream, spawn a
handler goroutine (ADR-0003), and tear it all down. Because the streams are reset
before they "count" against in-flight limits, naive `MaxConcurrentStreams` does
not stop the flood.

A server that spawns a goroutine per stream (ADR-0003) is precisely the shape
this attack targets, so a mitigation is mandatory, not optional.

## Decision

Track and budget client-initiated resets that cancel a stream **before it
produced useful work**, and tear the connection down once the budget is exceeded.

- **Account only "rapid" resets.** `ServerConn.onClientRSTStream(_, rapid bool)`
  (`conn/server_ops.go`) increments an atomic counter (`rapidResetCount`) **only**
  when `rapid == true` — i.e. the RST cancelled a stream that had not yet done
  useful work. Benign post-completion cancellations are ignored, so legitimate
  client-side `context` cancellations never trip the defense.
- **Budget proportional to advertised concurrency.** The cap is
  `Options.ConnOpts.MaxRapidResets` with a secure default of
  `max(MaxConcurrentStreams * 4, 100)` (the floor `rapidResetFloor = 100` keeps
  low-concurrency configs tolerant of bursts). `0` selects the default, a
  negative value disables the mitigation, a positive value sets an explicit
  budget. This mirrors the Go `x/net/http2` fix philosophy: secure-by-default,
  scaled to concurrency so normal cancellation traffic never trips it.
- **Trip with GOAWAY(ENHANCE_YOUR_CALM).** When `rapidResetCount` exceeds the
  budget, `onClientRSTStream` returns a `connError{code: ErrCodeEnhanceYourCalm}`.
  The reader loop (`conn/server_conn.go`) sees this as a connection-fatal error,
  emits `GOAWAY` with that code (so the peer learns *why*), and tears the
  connection down — shedding the abusive client without affecting other
  connections.
- **Hot-path-safe.** The accounting is a single atomic load of the budget plus,
  for rapid resets, one atomic increment and a comparison. No allocation, honouring
  ADR-0001.

## Consequences

- **Positive — bounded blast radius.** A Rapid Reset flood costs the attacker one
  connection: after `MaxRapidResets` abusive resets the connection is GOAWAYed,
  not the whole server. Goroutine churn from the attack is capped.
- **Positive — no collateral damage to legitimate clients.** Only pre-work resets
  count, so apps that cancel in-flight RPCs (a normal gRPC pattern) are unaffected.
- **Positive — secure by default with an escape hatch.** Operators get protection
  with zero configuration; the budget is tunable, and the mitigation can be
  explicitly disabled (negative value) for trusted environments or testing.
- **Positive — protocol-correct teardown.** Using `ENHANCE_YOUR_CALM` in GOAWAY is
  the RFC-7540-sanctioned signal for "you are misbehaving, back off," so
  well-behaved clients understand the close.
- **Negative — heuristic boundary.** "Rapid" is defined as "reset before useful
  work"; the exact classification lives in the conn layer. A sophisticated
  attacker who lets a tiny amount of work happen before resetting could raise the
  cost of tripping the budget, though never below the open-handler cost.
- **Negative — per-connection counter, not per-client.** An attacker can open many
  connections, each with its own budget. This mitigation pairs with, but does not
  replace, connection-level limits (`MaxConcurrentConnections`) and upstream
  rate-limiting (the `RateLimit` middleware).
