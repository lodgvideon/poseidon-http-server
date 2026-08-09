# ADR-0009: Stream state is one value, not a set of flags

- **Status:** Accepted
- **Date:** 2026-08-09

## Context

RFC 9113 §5.1 defines a stream as a six-state machine — idle, reserved, open,
half-closed (local), half-closed (remote), closed — and almost every obligation
in the specification is stated as a function of that state: which frames may
arrive, which may be sent, what a violation costs, whether an identifier may be
reused, what the GOAWAY last-stream-id may name.

`conn/` implemented all of it without ever naming a state. The information lived
in five booleans on `ServerStream` (`localEnded`, `remoteEnded`, `closed`,
`headersSent`, `headersReceived`), in membership of the connection's stream map,
and in two atomic counters — and each call site composed its own answer out of
them. An architecture review counted **56 such sites**.

The cost was not aesthetic. Three rounds of conformance fixes each shipped a new
defect in the files they had just touched, and all three were the same shape:
a question about stream state answered by re-deriving it locally, one derivation
disagreeing with its neighbours.

- The GOAWAY last-stream-id scanned every key in the map with no odd/even
  filter, though the two counting loops beside it filtered — so a live push
  stream could be reported as the last stream the *peer* opened, and a client
  reads that as "everything below was processed" and stops retrying.
- A reset set `closed` on one path and deregistered the stream on another, so
  two of the four reset paths left it in the map with its context uncancelled.
- A stream could be registered before the SETTINGS that size its windows were
  published, and the §6.9.2 retroactive delta never reached it.

Writing "is this stream closed" correctly required knowing which of five fields
mattered *here* and which lock covered them. That is not a property a reviewer
can check, and three consecutive reviews did not.

## Decision

Give the state a name and a single owner, in two pieces.

**`streamTable` (`conn/stream_table.go`)** owns the identifier space and the
live population of one connection. Parity lives in one function; the counts are
maintained rather than scanned; the last peer identifier is a field, so there is
no loop left in which to forget the filter. Admission and release are single
exits, so a stream cannot be closed without being removed or removed without
being closed. Admission seeds a new stream's send window *under the table lock*,
which is what makes §6.9.2's retroactive walk atomic with respect to it.

**`streamState` (`conn/stream_state.go`)** is the per-stream half: the five
booleans packed into one word, read with one atomic load and advanced with one
compare-and-swap. No bit is separately readable or separately writable, and that
is the point — every defect above came from reading a subset and acting on it.
`advance(delta)` returns the state as it was *before* the transition, because
that is what callers actually need: "was this the first reset", "is this second
field section a trailer", "did that transition close the stream" are questions
about the edge, not the level, and answering them from a separate read is what
let two of them race.

Having a state made one more obligation checkable, and it was being violated:
§5.1 (`rfc9113.txt:1082`) forbids sending anything but PRIORITY on a closed
stream, but `SendHeaders`/`SendData` checked on entry and wrote much later — a
DATA write waits in `acquireSendCredits` for as long as the peer withholds
window. `authorizeSend` re-reads the state inside the `wmu` write-lock critical
section, immediately before the frame is handed to the framer. Because every
reset path records the reset *before* acquiring `wmu`, a writer holding `wmu`
cannot miss a reset that has already reached the wire.

## Consequences

The RFC's vocabulary is now in the code, and `CONTEXT.md` defines it once for
the repo. A reviewer asking "may this stream still be written to" reads
`Writable()` rather than reconstructing `!closed && !localEnded` and then
checking that both fields were maintained on all six reset paths.

Reads got cheaper: `remoteHalfEnded`, the trailer test and the two send-side
gates are one atomic load each where they were a mutex acquisition. Nothing on
the zero-allocation hot path changed shape, and `bench-gate` holds
(`BenchmarkOnHeaders` unchanged at 5 allocs/op).

The state is deliberately not the six named states of §5.1 but the five
independent facts they are made of. Two of the six (idle, reserved) are not
properties of a `*ServerStream` at all — idle means no stream object exists, and
that question belongs to `streamTable`. Splitting the machine across two types
is the trade-off accepted here: the alternative, one enum covering both, would
have to represent "this identifier has never been used", which no per-stream
value can.

`authorizeSend` is scoped to HEADERS and DATA on purpose. RST_STREAM,
WINDOW_UPDATE and PRIORITY do not pass through it and must not: the RST_STREAM
that closes a stream is written by a path that has just recorded the reset, and
gating it on that same state would keep the §6.9.1 `FLOW_CONTROL_ERROR` and the
event-overflow `INTERNAL_ERROR` resets off the wire entirely.

It also introduced a refusal on a live connection where there had been none, and
with it an accounting duty that did not exist before: `acquireSendCredits` debits
both flow-control windows before the write, and a window is replenished only by
the peer's WINDOW_UPDATE for octets it actually received (§6.9.1). Credit spent
on a frame that is then refused is gone for the life of the connection, and the
connection-level window belongs to every stream — four cancelled downloads would
have stranded all of them. `releaseSendCredits` gives it back.

That refund has to saturate, not wrap, and the reason is worth recording because
it is the same trap a third time. `onWindowUpdate` bounds an incoming grant
against the window *as it stands* — which is already net of octets debited and
not yet written. A peer may therefore legally bring a window to exactly 2^31-1
while a chunk is outstanding, and adding that chunk back on top overflows `int32`
to roughly -2^31: `avail` stays at or below zero for every stream on the
connection, and no WINDOW_UPDATE a peer would ever send can lift it out. The
wedge the refund exists to prevent, reached from the other side. The excess can
only exist because the peer credited octets it never received, which is its own
§6.9.1 violation, so this endpoint caps at the maximum rather than tearing the
connection down over arithmetic it chose to do itself.
