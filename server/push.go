package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// Server Push — high-level API (RFC 7540 §8.2)
//
// This wraps the low-level conn.ServerStream.Push with a ResponseWriter
// for the pushed response. Push lives on the optional Pusher interface, which a
// handler reaches via PusherOf (it walks any middleware wrappers' Unwrap chain)
// to promise additional resources.
//
// Example:
//
//   func handler(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
//       // Push style.css the client will need, if the writer supports it.
//       if p, ok := server.PusherOf(w); ok {
//           if pushed, err := p.Push("/style.css", nil); err == nil {
//               pushed.WriteData([]byte("body { color: red }"))
//           }
//       }
//       // Send main response.
//       return w.WriteData([]byte("<html>...</html>"))
//   }
// ---------------------------------------------------------------------------

// ErrPushNotSupported is returned when the underlying stream does not
// support push (e.g. ResponseWriter is not backed by a real stream).
var ErrPushNotSupported = errors.New("poseidon: server push not supported by this stream")

// ErrPushAlreadySent is returned when Push is called after the response
// headers have been sent.
var ErrPushAlreadySent = errors.New("poseidon: cannot push after response headers sent")

// scheme constants — extracted for the goconst linter and to keep
// "https" / "http" usage discoverable across the package.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// pusher is the subset of connStreamWriter that supports Push.
// We use a separate type to keep the check explicit.
type pusher interface {
	canPush() (pushableStream, bool)
}

// pushableStream is the subset of conn.ServerStream we need for Push.
type pushableStream interface {
	ID() uint32
	Push(ctx context.Context, fields []hpack.HeaderField) (*conn.ServerStream, error)
	PushWithPriority(ctx context.Context, fields []hpack.HeaderField, prio *frame.Priority) (*conn.ServerStream, error)
}

// pusher returns the underlying stream if this ResponseWriter can issue
// push promises. Currently only connStreamWriter-backed writers support it.
func (w *responseWriter) pusher() (pushableStream, bool) {
	if cs, ok := w.sw.(pusher); ok {
		return cs.canPush()
	}
	return nil, false
}

// ErrPushNoAuthority is returned when a PUSH_PROMISE would have to be emitted
// without an ":authority": neither the originating request nor the caller
// supplied one.
//
// RFC 9113 §8.4 (rfc9113.txt:2811): "The header fields in PUSH_PROMISE and any
// subsequent CONTINUATION frames MUST be a valid and complete set of request
// header fields (Section 8.3.1)." Without an authority the promised request's
// target URI has an empty host, which RFC 9110 §4.2 forbids a sender from
// generating — and a conformant client "MUST respond on the promised stream
// with a stream error ... of type PROTOCOL_ERROR" (rfc9113.txt:2815). Refusing
// locally is strictly better than emitting a promise guaranteed to be reset.
var ErrPushNoAuthority = errors.New("poseidon: cannot push without an :authority; promised request would have an empty host")

// promiseFields builds the complete request field set for a PUSH_PROMISE.
//
// The authority defaults to the originating request's — a pushed resource
// belongs to the same origin as the request that triggered it. A caller-supplied
// ":authority" overrides it and is hoisted into the pseudo-header block, because
// pseudo-headers "MUST appear in a field block before all regular field lines"
// (rfc9113.txt:2619) and must not repeat (:2624).
func (w *responseWriter) promiseFields(promisePath, promiseScheme string, promiseHeaders []hpack.HeaderField) ([]hpack.HeaderField, error) {
	if promiseScheme == "" {
		promiseScheme = schemeHTTPS
	}
	authority := ""
	if w.req != nil {
		authority = w.req.Authority
	}
	callerSuppliedAuthority := false
	for _, h := range promiseHeaders {
		if string(h.Name) == ":authority" {
			authority, callerSuppliedAuthority = string(h.Value), true
			break
		}
	}
	if authority == "" {
		return nil, ErrPushNoAuthority
	}

	fields := make([]hpack.HeaderField, 0, 4+len(promiseHeaders))
	fields = append(fields,
		hpack.HeaderField{Name: []byte(":method"), Value: []byte("GET")},
		hpack.HeaderField{Name: []byte(":path"), Value: []byte(promisePath)},
		hpack.HeaderField{Name: []byte(":scheme"), Value: []byte(promiseScheme)},
		hpack.HeaderField{Name: []byte(":authority"), Value: []byte(authority)},
	)
	for _, h := range promiseHeaders {
		if callerSuppliedAuthority && string(h.Name) == ":authority" {
			continue // already emitted above, in the pseudo-header block
		}
		fields = append(fields, h)
	}
	return fields, nil
}

// Push creates a PUSH_PROMISE on the current stream and returns a
// ResponseWriter for writing the pushed response.
//
// The promiseHeaders describe the response that will be sent. If nil,
// the path and method are derived from the request. The method defaults
// to GET.
//
// Push must be called BEFORE the main response headers are sent.
//
// The :scheme pseudo-header is derived from the originating request's
// scheme (RFC 7540 §8.2: "the server SHOULD use the same scheme as
// the request"). If the writer has no request context (e.g. constructed
// directly via NewResponseWriter for tests), "https" is used as a
// safe default. Use PushWithScheme to override explicitly.
func (w *responseWriter) Push(promisePath string, promiseHeaders []hpack.HeaderField) (ResponseWriter, error) {
	return w.PushWithScheme(promisePath, w.deriveScheme(), promiseHeaders)
}

// PushWithScheme is like Push but lets the caller override the :scheme
// pseudo-header on the PUSH_PROMISE. Useful when scheme negotiation
// requires explicit signalling (e.g. h2c -> http).
func (w *responseWriter) PushWithScheme(promisePath, promiseScheme string, promiseHeaders []hpack.HeaderField) (ResponseWriter, error) {
	if w.written {
		return nil, ErrPushAlreadySent
	}

	// Get the underlying stream.
	ps, ok := w.pusher()
	if !ok {
		return nil, ErrPushNotSupported
	}

	fields, err := w.promiseFields(promisePath, promiseScheme, promiseHeaders)
	if err != nil {
		return nil, err
	}

	// Issue PUSH_PROMISE and create the push stream.
	pushStream, err := ps.Push(context.Background(), fields)
	if err != nil {
		return nil, fmt.Errorf("poseidon: push failed: %w", err)
	}

	// Wrap it in a ResponseWriter.
	return &responseWriter{
		sw:  &connStreamWriter{stream: pushStream},
		ctx: pushStream.Context(), // cancel a pushed response on push-stream reset
		req: w.req,                // propagate request context for nested Push
	}, nil
}

// PushWithPriority is like Push but lets the caller attach an RFC 7540
// §5.3 priority payload to the pushed response. The priority is emitted
// in the first response HEADERS frame of the push stream; the PUSH_PROMISE
// frame itself does not carry the priority block.
//
// Pass nil for prio to behave like Push.
func (w *responseWriter) PushWithPriority(promisePath string, promiseHeaders []hpack.HeaderField, prio *frame.Priority) (ResponseWriter, error) {
	return w.pushWithPriorityAndScheme(promisePath, w.deriveScheme(), promiseHeaders, prio)
}

// pushWithPriorityAndScheme is the merged implementation: scheme + priority.
func (w *responseWriter) pushWithPriorityAndScheme(promisePath, promiseScheme string, promiseHeaders []hpack.HeaderField, prio *frame.Priority) (ResponseWriter, error) {
	if w.written {
		return nil, ErrPushAlreadySent
	}
	ps, ok := w.pusher()
	if !ok {
		return nil, ErrPushNotSupported
	}
	fields, err := w.promiseFields(promisePath, promiseScheme, promiseHeaders)
	if err != nil {
		return nil, err
	}

	pushStream, err := ps.PushWithPriority(context.Background(), fields, prio)
	if err != nil {
		return nil, fmt.Errorf("poseidon: push failed: %w", err)
	}
	return &responseWriter{
		sw:  &connStreamWriter{stream: pushStream},
		ctx: pushStream.Context(),
		req: w.req,
	}, nil
}

// deriveScheme returns the request's :scheme if available, otherwise
// "https" as a safe default. Mirrors the original request to comply
// with RFC 7540 §8.2 (the server SHOULD use the same scheme).
func (w *responseWriter) deriveScheme() string {
	if w.req != nil && w.req.Scheme != "" {
		return w.req.Scheme
	}
	return schemeHTTPS
}
