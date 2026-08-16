# Domain glossary

The words this codebase uses for the things it manipulates. Architecture
vocabulary — module, interface, depth, seam, adapter, leverage, locality — is
separate and lives in the `codebase-design` skill; this file is only about the
domain.

Most terms come from RFC 9113. Where the RFC names something, we use the RFC's
name and cite the section, so a reader can always go and check.

## Connection

One TCP (or TLS) connection carrying multiplexed HTTP/2 traffic, owned by
`conn.ServerConn`. Exactly one **reader goroutine** reads frames from it and
dispatches them; every write is serialised under one mutex. See
[ADR-0003](docs/adr/0003-serverconn-accept-stream-goroutine-model.md).

## Stream

One request/response exchange, `conn.ServerStream`. Identified by a **stream
identifier**: odd for client-initiated, even for server-initiated (RFC 9113
§5.1.1). The parity is not decoration — several rules turn on it, and forgetting
to filter by it has already produced a defect.

**Stream state** is RFC 9113 §5.1's six-state machine: *idle*, *reserved
(local)*, *reserved (remote)*, *open*, *half-closed (local)*, *half-closed
(remote)*, *closed*. Which frames are legal, and whether an illegal one is a
stream error or a connection error, depends on it.

- **idle** — never opened. Provable from the identifier alone, against the
  highest identifier seen. Distinct from *closed*, and confusing the two is a
  conformance error in both directions.
- **half-closed (remote)** — the client has sent END_STREAM; the server may
  still be writing its response. A stream stays registered here.
- **reserved (local)** — the server has sent PUSH_PROMISE but not yet the
  pushed response.
- **closed** — finished or reset. A closed stream is deregistered, so *absence
  from the registry* is not by itself evidence of any one state.

In the code the machine is split across two types, because two of its states are
not properties of a stream object at all. `conn.streamTable` owns the identifier
space, and answers *idle* — which means no stream exists, so no per-stream value
could hold it. `conn.streamState` is the per-stream half: the five independent
facts the remaining states are made of (request field section received, remote
half ended, response field section sent, local half ended, reset), packed into
one word. `advance` returns the state as it was *before* the transition, because
callers ask about the edge — "was this the first reset", "is this second field
section a trailer" — not the level. See [ADR-0009](docs/adr/0009-stream-state-as-one-value.md).

## Frame, field section, field block

**Frame** — the wire unit. **Field section** — what HTTP calls headers or
trailers, i.e. the decoded list. **Field block** — the HPACK-encoded bytes that
carry a field section, possibly split across a HEADERS frame and CONTINUATION
frames.

The connection has **one shared HPACK dynamic table** in each direction. A field
block that is rejected must *still* be fed to the decoder, and a field block that
is not going to be sent must *not* reach the encoder — otherwise the two ends
disagree and every later field section on the connection decodes wrongly. This is
the single most load-bearing invariant in `conn/`, and it has been violated in
both directions.

## Flow-control window

Credit, in octets, that the peer may spend sending body bytes. There are two
levels, and they are deliberately asymmetric here:

- the **connection window** is refunded when a frame *arrives*, because RFC 9113
  §6.9 requires every flow-controlled frame be counted whatever becomes of its
  stream;
- the **per-stream window** is refunded when the application *reads* the bytes,
  because a window refunded on arrival bounds nothing.

## Stream error / connection error

RFC 9113 §5.4. A **stream error** resets one stream and the connection survives;
a **connection error** sends GOAWAY and ends everything. Which one a violation
deserves is fixed by the RFC, is frequently not the intuitive choice, and is the
distinction most of this repository's conformance work has been about.

## Native path / compat path

Two ways a handler writes a response. The **native path** —
`WriteHeaders`/`WriteData`/`WriteTrailers` — is allocation-free by contract
([ADR-0001](docs/adr/0001-zero-allocation-hot-path-contract.md)). The **compat
path** — the `net/http` `Header()` map plus `WriteHeader` — intentionally
allocates. Several behaviours are currently implemented once per path; that is a
known locality problem, not a design.

## Call, and call outcome

A **call** is one request/response exchange as the *application* sees it. On
HTTP it is a request; on gRPC it is an RPC. It rides on exactly one stream, so
"call" and "stream" are one-to-one — but they are not the same word, because a
stream is a transport thing with transport states and a call is an application
thing with an application result.

The **call outcome** is how a call ended: an outcome code, the class it falls
into (succeeded, the caller was wrong, we were wrong), and the sizes and
duration that go with it. It is deliberately *protocol-independent*, because the
concept has two encodings and only two: HTTP writes it as a status code, gRPC
writes it as a `grpc-status` trailer.

That distinction is load-bearing and its absence has already cost us. Anything
that reads the HTTP status in order to learn how a call went is reading one of
the two encodings of a concept it should be reading directly — and on gRPC it
gets 200 for every failure, because the real answer is in the trailers. A layer
that wants outcomes and reaches for status codes is making a category error, not
a shortcut.

## RPC vocabulary

From the gRPC HTTP/2 protocol specification and the gRFCs, not from RFC 9113.

- **Service** and **method** — the two halves of the `:path` that select a
  handler. A **method** has one of four shapes: unary, server-streaming,
  client-streaming, bidirectional-streaming.
- **Metadata** — the application's own key/value pairs on a call, carried in the
  request field section, in an initial response field section, and in trailers.
  Keys ending `-bin` carry binary values and are base64-encoded on the wire.
  Metadata is a distinct concept from *field section*: a field section is the
  transport's carrier, metadata is what the application put in it, and the
  transport's own pseudo-headers and framing fields are not metadata.
- **Status** — the outcome of an RPC: a code, a message, and optionally typed
  details. It travels in the **trailers**, which is why an RPC that failed still
  has a successful HTTP response around it. See
  [ADR-0004](docs/adr/0004-grpc-framing-and-status-trailers.md).
- **Trailers-Only** — the shape a response takes when it carries a status and
  nothing else: one field section with END_STREAM, no separate initial section.

## Conformance test

A test whose assertion is derived from the RFC text, quoting the governing
sentence with a `file:line` into the spec source, never from what the
implementation happens to do. Named `TestConformance_RFC<digits>_Sec<n>_*` so
`scripts/rfc-coverage-gate.sh` can find it. The mapping from obligation to test
is [docs/RFC_COVERAGE.md](docs/RFC_COVERAGE.md); adding a row there is how a
normative requirement becomes something CI can fail on.
