# RFC 9113 conformance audit — poseidon-http-server

HTTP/2 is the protocol this server actually speaks, and it had never been
audited against its own specification. The earlier audit covered RFC 9110
(semantics), RFC 9112 (HTTP/1.1 syntax, reachable only through the h2c probe)
and RFC 7540 §3.2 (the upgrade mechanism 9113 obsoletes but does not replace);
it left the frame layer, the stream state machine and flow control untouched.

## Method

594 obligations were extracted from `RFC9113_FACTS.md`, the verified fact
catalog built for poseidon-http-client, and filtered to the 200 whose audience
includes a server, an origin, an endpoint or a receiver. Those were split into
eight groups and each group given to a judge with read access to the code and
no ability to write.

Every non-PASS finding then went to two adversarial verifiers with opposite
standing instructions — one told to assume *the code already complies* and hunt
for the guard the judge missed, the other told to read the quoted text as a
lawyer and find the precondition that makes the rule not bind. Both default to
`real_gap = false`; a finding survives only if both, having re-read the code,
say otherwise.

135 findings were judged. 25 were overturned outright, 18 split, 92 confirmed.
The overturn rate — 18.5% — is far below the 60% the HTTP/1.1 audit produced,
and that difference is itself informative rather than suspicious: the earlier
audit was largely re-discovering gaps that previous rounds had already closed,
whereas `conn/` genuinely had no RFC 9113 conformance test at all.

The 94 surviving findings were then clustered by root cause — *what single
change closes all of these* — into 17 clusters, and each cluster handed to a
challenger whose prior was that the cluster was wrong. One cluster died
entirely; 18 individual findings were killed inside surviving clusters.

## Root cause

Every cluster traces to the same shape: **the server treats a question it cannot
answer as a question that does not need answering.**

- The frame codec reports a protocol violation as a plain sentinel carrying no
  HTTP/2 error code, because only a receiver can decide what an error means for
  its role. The reader loop had no mapping table, so it treated *"the codec
  returned an error"* as an opaque terminal condition and exited silently. The
  peer learned nothing — no GOAWAY, no code, just a socket that stopped
  answering.
- `lookupStream` returns nil for a stream that is idle, closed, reset or
  refused. §5.1 demands a connection error for the first and at most a stream
  error for the rest, so every caller doing `if s == nil { return nil }` was
  answering four different questions with one wrong answer.
- Field validation checked values and never names, so a name was implicitly
  assumed well-formed.

Where the answer *was* knowable, it usually already existed and was simply
never consulted: `maxClientStreamID` makes "idle" provable, `ReadFrame` returns
the `FrameHeader` alongside the error, the push counter bounds the even
identifiers. Almost nothing here needed new state.

## What was closed

Sixteen of seventeen clusters, across five commits. The per-obligation mapping
is in [../RFC_COVERAGE.md](../RFC_COVERAGE.md); the summary:

| Cluster | Effect before the fix |
|---|---|
| Codec errors unreported | Every frame-size and stream-id violation killed the connection silently; the transport was never closed, leaking a socket per attempt |
| HPACK decode failure | Answered RST_STREAM(CANCEL) — telling the client to retry on a connection whose shared dynamic table was already unrecoverable |
| No idle state | DATA, RST_STREAM and WINDOW_UPDATE on a never-opened stream silently ignored; frames after END_STREAM delivered to the handler behind its own EOF |
| Connection window leak | DATA on a retired stream never debited or refunded, so connection credit drained monotonically until every stream wedged |
| Field names unvalidated | `Content-Length` accepted verbatim while every comparison downstream is lowercase; `x-forwarded-for:extra` split into two fields at the next HTTP/1.1 hop |
| Connection-specific fields | Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade and a non-`trailers` TE all accepted |
| Reset lifecycle | A peer RST_STREAM left the stream writable, so a handler reacting to it sent a second RST — the loop §5.4.2 exists to prevent |
| REFUSED_STREAM on overflow | Promised the client a request was unprocessed and safely retryable when it had already been dispatched |
| GOAWAY lifecycle | last-stream-id could increase; shutdown announced the real identifier in one shot, making in-flight streams look unprocessed; the client's GOAWAY was ignored by push |
| Push preconditions | Push from a pushed stream, from a retired stream, past the peer's concurrency limit, or with a malformed promise |
| SETTINGS | A second SETTINGS frame reverted every parameter it omitted; one ACK for however many frames arrived; unknown identifiers stored, so sixteen invented ones displaced every real setting |
| Idle connections | `Options.IdleTimeout` documented a close that never happened; `AcceptStream` never observed the reader's death |
| Cookies | Split Cookie fields — which §8.2.3 recommends and browsers produce — lost every crumb after the first on the stdlib path |
| TLS | ALPN and TLS 1.2 were configured, never verified; a caller-supplied config or an already-established connection bypassed both |

## What was not closed, and why

Two obligations remain open. Both are recorded in
[../RFC_COVERAGE.md](../RFC_COVERAGE.md) with the same reasoning: §5.2.2's
"read as soon as data is available" needs a dedicated writer goroutine, which
amends [ADR-0003](../adr/0003-serverconn-accept-stream-goroutine-model.md) and is a design change rather
than a conformance patch; and the §5.1.1-versus-§5.1 tension over a field
section arriving for a just-reset stream cannot be resolved without
per-identifier memory, so the explicit MUST wins.

## Two things the process caught that the findings did not

**A test that could not fail.** `TestIdleTimeout` asserted that a read errors
after the idle timeout. Before the fix the server closed nothing, so the read
sat until its own deadline and the resulting i/o timeout was indistinguishable
from a shutdown — the test passed for the wrong reason for its whole life. It
now drains until the read fails and asserts the GOAWAY.

**A test that pinned the bug.** `TestDepth_StrayFrames_Tolerated` asserted that
RST_STREAM on an idle stream is tolerated. §6.4 makes that a connection error,
so tolerating it was the defect the test was protecting. Its PRIORITY half is
legitimate and stays; the RST_STREAM half moved into the §5.1 conformance suite
with the opposite assertion.

Separately, `scripts/bench-gate.sh` cannot currently fail: with no committed
baseline it records the current run and passes, so the 0 allocs/op contract
[ADR-0001](../adr/0001-zero-allocation-hot-path-contract.md) describes is advertised but
unenforced on a fresh checkout. That is tracked separately; this audit verified
the contract by hand instead (the native write path is unchanged at 0
allocs/op).

## The review of the repairs

The 13 confirmed findings above were repaired in one commit, and that commit was
then reviewed on its own — because a repair written to close a review is exactly
where the next defect hides. Four reviewers raised 14 findings; 13 survived a
refute-by-default verifier, deduplicating to six distinct defects. Two are worth
recording because they are the same mistake seen twice:

**The HPACK trap, from the encoder side.** The repair for over-large field
sections measured the block *after* `EncodeBlock` and refused to write it. But
`EncodeBlock` has already inserted into the connection's shared dynamic table, so
refusing left the encoder holding entries the peer never received — and every
later response on that connection decoded as garbage or failed outright. This is
the decode-side invariant the audit had documented three times over, walked into
from the other direction. The size decision now happens before encoding, from a
conservative bound on the uncompressed field section.

**A fix that traded truncation for a leak.** Closing a connection on the idle
deadline cut off long in-flight requests, so the repair declined to close a busy
one — but still returned from the accept loop, leaving a socket that was open,
untracked by Shutdown, and deaf to every subsequent request. The correct repair
was to keep waiting, not to stop closing.

The CI failure on the pull request was a third: a 1 MiB upload to a handler
lagging a few milliseconds behind the wire was killed mid-request. The chain ran
five deep — RST_STREAM(INTERNAL_ERROR), because the per-stream event channel
overflowed, because it holds eight events, because the peer could send far more
than eight frames, because the receive window was refunded when bytes ARRIVED
rather than when the application read them, so the window bounded nothing. The
per-stream window is now refunded on consumption (§5.2.1: "The sender of a
flow-controlled frame MUST NOT send more than the receiver allows" means nothing
if the receiver always allows more); the connection window keeps its
receipt-time refund, because §6.9 requires every frame be counted there and
gating it on one application's reading would let a single slow handler wedge the
connection. `ServerConnOptions.StreamEventBuffer`, documented and plumbed
through `server/` but ignored for every client stream, now applies.

That failure was only visible because this branch changed the overflow reset
from REFUSED_STREAM to INTERNAL_ERROR. A Go client silently retries the first,
so the defect had been there, hidden, the whole time.

## Upstream

Two defects belong to the codec module and were filed there rather than worked
around locally:

- **poseidon-http-client#402** — `frame.ErrInvalidPadding` is exported,
  documented and never returned; the real sentinel is
  `internal/bytesx.ErrInvalidPadding`, which no consumer can import. A padding
  violation is therefore unidentifiable from outside the module.
- **poseidon-http-client#401** — `ErrSettingsLength` is returned both for a
  length that is not a multiple of 6 (a real FRAME_SIZE_ERROR) and for a
  perfectly legal SETTINGS frame carrying more than sixteen entries, which
  `SettingsParams`'s fixed array cannot hold.

One thing was *not* filed upstream, and the reason is worth recording. The
codec discards frame types it does not recognise before calling any handler
method, which makes §5.5's ban on an extension frame inside a field block
unreachable from the handler — so it looked like it needed a new codec
callback. It does not: `ReadFrame` returns the `FrameHeader` for those frames
too, and the reader loop can enforce the rule in four lines. The challenger
overturned that conclusion, which is exactly what the adversarial pass is for.
