package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// Server Push — high-level API (RFC 7540 §8.2)
//
// This wraps the low-level conn.ServerStream.Push with a ResponseWriter
// for the pushed response. The handler calls Push on the request to
// promise additional resources that the client will need.
//
// Example:
//
//   func handler(ctx context.Context, req *server.Request, w *server.ResponseWriter) error {
//       // Push style.css the client will need.
//       pushed, err := w.Push("/style.css", nil)
//       if err == nil {
//           pushed.WriteData([]byte("body { color: red }"))
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
}

// pusher returns the underlying stream if this ResponseWriter can issue
// push promises. Currently only connStreamWriter-backed writers support it.
func (w *ResponseWriter) pusher() (pushableStream, bool) {
if cs, ok := w.sw.(pusher); ok {
	return cs.canPush()
}
return nil, false
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
func (w *ResponseWriter) Push(promisePath string, promiseHeaders []hpack.HeaderField) (*ResponseWriter, error) {
	return w.PushWithScheme(promisePath, w.deriveScheme(), promiseHeaders)
}

// PushWithScheme is like Push but lets the caller override the :scheme
// pseudo-header on the PUSH_PROMISE. Useful when scheme negotiation
// requires explicit signalling (e.g. h2c -> http).
func (w *ResponseWriter) PushWithScheme(promisePath, promiseScheme string, promiseHeaders []hpack.HeaderField) (*ResponseWriter, error) {
	if w.written {
		return nil, ErrPushAlreadySent
	}

	// Get the underlying stream.
	ps, ok := w.pusher()
	if !ok {
		return nil, ErrPushNotSupported
	}

	if promiseScheme == "" {
		promiseScheme = schemeHTTPS
	}

	// Build the request headers for the promised response.
	fields := make([]hpack.HeaderField, 0, 4+len(promiseHeaders))
	fields = append(fields,
		hpack.HeaderField{Name: []byte(":method"), Value: []byte("GET")},
		hpack.HeaderField{Name: []byte(":path"), Value: []byte(promisePath)},
		hpack.HeaderField{Name: []byte(":scheme"), Value: []byte(promiseScheme)},
	)
	fields = append(fields, promiseHeaders...)

	// Issue PUSH_PROMISE and create the push stream.
	pushStream, err := ps.Push(context.Background(), fields)
	if err != nil {
		return nil, fmt.Errorf("poseidon: push failed: %w", err)
	}

	// Wrap it in a ResponseWriter.
	return &ResponseWriter{
		sw:      &connStreamWriter{stream: pushStream},
		req:     w.req, // propagate request context for nested Push
	}, nil
}

// deriveScheme returns the request's :scheme if available, otherwise
// "https" as a safe default. Mirrors the original request to comply
// with RFC 7540 §8.2 (the server SHOULD use the same scheme).
func (w *ResponseWriter) deriveScheme() string {
	if w.req != nil && w.req.Scheme != "" {
		return w.req.Scheme
	}
	return schemeHTTPS
}
