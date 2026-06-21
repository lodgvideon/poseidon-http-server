# ADR-0003: `ServerConn` accept-stream + per-stream-goroutine model

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

HTTP/2 multiplexes many concurrent streams over one TCP connection. The server
must read frames from a single socket (frames for all streams are interleaved on
the wire) yet dispatch each request to a handler that can block on I/O,
downstream calls, or `context` cancellation — without one slow handler stalling
the others.

There are two classic shapes. (a) A single event loop that runs handlers inline:
simple, but any blocking handler halts all streams. (b) A reader goroutine that
fans frames out to per-stream goroutines: more goroutines, but isolation between
streams. We needed an accept API that feels like `net.Listener.Accept` so the
`server` layer can stay a thin accept loop, and we needed handlers to run
concurrently.

## Decision

Split responsibilities across two layers with a channel-based, per-stream
goroutine model.

**`conn.ServerConn` owns the socket.** Exactly one reader goroutine
(`readerLoop` in `conn/server_conn.go`) calls `fr.ReadFrame` and dispatches each
frame through a `frame.Handler` into per-`ServerStream` event channels
(`StreamEvent` values: `EventHeaders`, `EventData`, `EventTrailers`,
`EventReset`). All writes to the framer are serialized under a single mutex
(`wmu`); flow-control windows, the streams map, and PING waiters each have their
own lock. New client-initiated streams are delivered to a buffered `acceptCh`.

**`AcceptStream(ctx)` is the accept primitive.** It blocks until the reader
pushes a new stream onto `acceptCh` (or the context is cancelled / connection
closes), mirroring `Accept` semantics.

**The `server` layer runs one goroutine per stream.** `server.acceptLoop`
(`server/server.go`) loops on `AcceptStream` and launches `go s.serveStream(...)`
for each. `serveStream` reads the stream's events (HEADERS first, then buffered
or streaming body) and invokes the handler. An in-flight `sync.WaitGroup` tracks
active streams so `Shutdown` can drain them gracefully.

## Consequences

- **Positive — stream isolation.** A handler blocking on I/O only blocks its own
  goroutine; other streams keep flowing because the reader goroutine never runs
  handler code.
- **Positive — clean layering.** `ServerConn` is reusable and testable on its own
  (it knows nothing about handlers); the `server` package is a thin accept +
  routing loop. This matches the SOLID notes in `server/handler.go`.
- **Positive — graceful shutdown falls out naturally.** Because each stream is a
  tracked goroutine, `Shutdown` sends GOAWAY, waits on the in-flight WaitGroup,
  and only force-closes on context timeout.
- **Positive — idle-timeout integration is cheap.** `acceptLoop` wraps
  `AcceptStream` in a per-stream `context.WithTimeout(IdleTimeout)`, so an idle
  multiplexed connection is reaped without a blanket socket read deadline that
  would break keep-alive.
- **Negative — goroutine-per-stream cost.** A flood of streams spawns a flood of
  goroutines. This is bounded by the advertised `MaxConcurrentStreams` and,
  critically, by the Rapid Reset mitigation (ADR-0007) which caps streams that
  are opened only to be reset.
- **Negative — careful synchronization.** The single-reader / many-writer design
  requires disciplined locking (`wmu` serializes framer writes; per-concern
  mutexes elsewhere). Per-stream methods are documented as single-goroutine; only
  `AcceptStream` and `Close` are safe to call concurrently.
- **Negative — backpressure is per-stream-channel.** Each stream has a bounded
  event buffer (`StreamEventBuffer`, default 8); a handler that stops reading its
  stream eventually applies HTTP/2 flow-control backpressure rather than buffering
  unboundedly.
