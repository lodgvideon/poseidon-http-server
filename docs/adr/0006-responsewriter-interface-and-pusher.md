# ADR-0006: `ResponseWriter` as an interface + Push via optional `Pusher`

- **Status:** Accepted
- **Date:** 2026-06-21

## Context

The original `server.ResponseWriter` was a **concrete struct**. That made the
native zero-allocation write path (ADR-0001) easy but had a fatal flaw for
middleware: there was no way to *intercept* the response. Compression
(`Gzip`), security headers, and any other response-transforming middleware need
to sit between the handler and the wire — buffering, rewriting headers, or
re-encoding the body before it is flushed. With a concrete writer the only escape
hatch is reflection or copying, neither acceptable.

Separately, HTTP/2 Server Push (RFC 7540 §8.2) is a capability only *some*
writers have (a real stream can push; a test/adapter sink cannot). Bolting three
`Push*` methods onto every writer would bloat the core interface and force every
implementation — including trivial test doubles and the `http.Handler` bridge — to
implement push.

## Decision

**Make `ResponseWriter` an interface (breaking change).** It embeds
`http.ResponseWriter` (so handlers get the stdlib API for free) and adds the
native methods `WriteHeaders`/`WriteData`/`WriteTrailers` plus
`Status`/`StatusCode`/`Written`. The concrete implementation (`responseWriter`)
is **unexported**; callers obtain one via `NewResponseWriter` or, internally, via
`newConnResponseWriter`.

**Middleware wraps by embedding.** Because the type is now an interface, a
middleware embeds a `server.ResponseWriter` in its own struct and overrides only
the methods it cares about. The Gzip middleware (`middleware/gzip.go`) does
exactly this: `gzipResponseWriter` embeds the wrapped writer, buffers every
`WriteData`/`Write`, and on `flush()` (deferred as `ServeHTTP` unwinds) decides
whether to compress, injects `Content-Encoding: gzip`, drops `Content-Length`,
and emits headers + body in one shot. When the client does not accept gzip the
original writer is passed through untouched — zero interception overhead.

**Push is a separate optional `Pusher` interface** (mirroring how `net/http`
keeps `Pusher`/`Flusher`/`Hijacker` separate). It declares `Push`,
`PushWithScheme`, and `PushWithPriority`. Handlers and middleware reach it by
type-assertion:

```go
if p, ok := w.(server.Pusher); ok {
    p.Push("/style.css", nil)
}
```

Writers without a real stream simply don't implement `Pusher` (or return
`server.ErrPushNotSupported`). Wrapping middleware forwards the `Pusher` calls so
enabling, e.g., Gzip does not silently disable Push.

## Consequences

- **Positive — middleware can intercept the response.** This single change
  unlocked Gzip, SecurityHeaders, metrics, and any future response transformer,
  all by embedding and overriding. The interface doc comment calls this out
  explicitly.
- **Positive — small core interface.** Push lives in `Pusher`, so the common case
  (no push) keeps `ResponseWriter` lean and test doubles trivial.
- **Positive — dual API preserved.** Embedding `http.ResponseWriter` means
  chi/echo/gin handlers work unchanged, while performance-sensitive handlers use
  the native zero-alloc methods.
- **Negative — BREAKING API change.** Code that referred to the old concrete
  `ResponseWriter` struct (field access, struct literals) no longer compiles and
  must migrate to the interface + `NewResponseWriter` constructor. This is the
  headline breaking change for the release documenting these ADRs.
- **Negative — Push is discoverable only by type-assertion.** Callers must remember
  the `w.(server.Pusher)` check; there is no compile-time guarantee a given writer
  pushes. This matches stdlib ergonomics but is a known papercut.
- **Negative — wrapping writers must forward `Pusher` (and re-implement the write
  methods consistently).** A middleware that embeds but forgets to forward
  `Push*` would break push for downstream handlers; Gzip forwards all three
  explicitly as the reference pattern.
- **Negative — buffering middleware forfeits the zero-alloc contract.** Gzip holds
  the whole body in memory and allocates; the ADR-0001 guarantee is scoped to the
  native path, and interception is an opt-in trade of streaming for simplicity.
