// Package server provides a high-level HTTP/2 server built on the conn package.
//
// It handles TLS + h2c listening, accepts connections, dispatches inbound
// streams to registered handlers, and manages graceful shutdown.
//
// Design (SOLID):
//   - S: owns only the accept loop + routing
//   - O: extensible via Handler interface and Middleware chain
//   - L: any Handler implementation is interchangeable
//   - I: small interfaces — Handler, Middleware, Listener
//   - D: depends on Listener and Handler interfaces, not concrete types
package server

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

// Handler is the native zero-allocation HTTP/2 handler interface.
// Implementations must be safe for concurrent use if registered on a
// shared server; the server dispatches each stream to the handler in its
// own goroutine.
type Handler interface {
	ServeHTTP(ctx context.Context, req *Request, w *ResponseWriter) error
}

// HandlerFunc is a type adapter that allows the use of ordinary functions
// as Handler values.
type HandlerFunc func(ctx context.Context, req *Request, w *ResponseWriter) error

// ServeHTTP calls f(ctx, req, w).
func (f HandlerFunc) ServeHTTP(ctx context.Context, req *Request, w *ResponseWriter) error {
	return f(ctx, req, w)
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

// Request represents a server-side HTTP/2 request.
type Request struct {
	Method     string
	Path       string
	Scheme     string // "https" or "http" (h2c)
	Authority  string // :authority pseudo-header
	Headers    []hpack.HeaderField
	Trailers   []hpack.HeaderField // trailing headers (after body)
	Body       []byte              // collected body; nil if streaming
	BodyReader io.ReadCloser       // streaming body reader; nil if collected

	streamID uint32 // internal: HTTP/2 stream identifier
}

// StreamID returns the HTTP/2 stream identifier for this request.
func (r *Request) StreamID() uint32 { return r.streamID }

// ---------------------------------------------------------------------------
// Internal stream writer abstraction
// ---------------------------------------------------------------------------

// streamWriter abstracts the underlying stream write operations so that
// tests can provide mocks without needing a real conn.ServerStream.
type streamWriter interface {
	sendHeaders(ctx context.Context, headers []hpack.HeaderField, endStream bool) error
	sendData(ctx context.Context, p []byte, endStream bool) error
	streamID() uint32
}

// connStreamWriter adapts *conn.ServerStream to the streamWriter interface.
type connStreamWriter struct {
	stream *conn.ServerStream
}

func (w *connStreamWriter) sendHeaders(ctx context.Context, headers []hpack.HeaderField, endStream bool) error {
	return w.stream.SendHeaders(ctx, headers, endStream)
}

func (w *connStreamWriter) sendData(ctx context.Context, p []byte, endStream bool) error {
	return w.stream.SendData(ctx, p, endStream)
}

func (w *connStreamWriter) streamID() uint32 {
	return w.stream.ID()
}

// canPush returns the underlying stream if it supports push.
// This satisfies the pusher interface used by server.ResponseWriter.Push.
func (w *connStreamWriter) canPush() (pushableStream, bool) {
	if w.stream == nil {
		return nil, false
	}
	return w.stream, true
}

// ---------------------------------------------------------------------------
// ResponseWriter
// ---------------------------------------------------------------------------

// ResponseWriter implements both native Poseidon methods and the
// http.ResponseWriter interface, allowing handlers to use either API.
//
// Native (zero-allocation) path:
//
//	w.WriteHeaders(200, hpackHeaders)
//	w.WriteData(body)
//	w.WriteTrailers(trailers)
//
// Stdlib-compatible path:
//
//	w.Header().Set("Content-Type", "text/plain")
//	w.WriteHeader(200)
//	w.Write(body)
type ResponseWriter struct {
	sw      streamWriter
	headers http.Header
	status  int
	written bool
}

// NewResponseWriter creates a ResponseWriter backed by the given ServerStream.
func NewResponseWriter(stream *conn.ServerStream) *ResponseWriter {
	return &ResponseWriter{
		sw: &connStreamWriter{stream: stream},
	}
}

// newResponseWriterWithSW creates a ResponseWriter with a custom streamWriter
// (for testing).
func newResponseWriterWithSW(sw streamWriter) *ResponseWriter {
	return &ResponseWriter{sw: sw}
}

// StatusCode returns the HTTP status code that was set via WriteHeaders or
// WriteHeader. Returns 0 if no status has been set yet.
func (w *ResponseWriter) StatusCode() int { return w.status }

// Compile-time interface check.
var _ http.ResponseWriter = (*ResponseWriter)(nil)

// --- Native Poseidon methods ------------------------------------------------

// WriteHeaders sends response headers with the given status code and extra
// HPACK header fields. If headers have already been sent this is a no-op.
func (w *ResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	if w.written {
		return nil
	}
	w.status = status
	w.written = true

	// Pre-computed :status value for common codes.
	statusVal := statusBytes(status)

	fields := make([]hpack.HeaderField, 0, 1+len(headers))
	fields = append(fields, hpack.HeaderField{
		Name:  sColonStatus,
		Value: statusVal,
	})
	fields = append(fields, headers...)

	return w.sw.sendHeaders(context.Background(), fields, false)
}

// WriteData sends response body data. If headers have not been sent yet it
// auto-sends a 200 response before writing data.
func (w *ResponseWriter) WriteData(p []byte) error {
	if !w.written {
		if err := w.WriteHeaders(http.StatusOK, nil); err != nil {
			return err
		}
	}
	return w.sw.sendData(context.Background(), p, false)
}

// WriteTrailers sends trailing headers using SendHeaders with endStream=true
// (the conn package does not expose a dedicated trailer method).
func (w *ResponseWriter) WriteTrailers(trailers []hpack.HeaderField) error {
	return w.sw.sendHeaders(context.Background(), trailers, true)
}

// --- http.ResponseWriter interface ------------------------------------------

// Header returns the header map that will be sent by WriteHeader.
// Lazy-initialised on first access.
func (w *ResponseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

// Write sends response body data, implementing io.Writer. If headers have not
// been sent yet, auto-sends a 200 response.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if err := w.sw.sendData(context.Background(), p, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteHeader sends an HTTP response header with the provided status code.
// If headers have already been sent (via WriteHeaders or a prior WriteHeader
// call) this is a no-op, matching stdlib behaviour.
func (w *ResponseWriter) WriteHeader(statusCode int) {
	if w.written {
		return
	}
	w.status = statusCode
	w.written = true

	// Build HPACK fields from stored http.Header.
	hdr := w.headers
	if hdr == nil {
		hdr = make(http.Header)
	}
	statusVal := statusBytes(statusCode)
	fields := make([]hpack.HeaderField, 0, 1+len(hdr))
	fields = append(fields, hpack.HeaderField{
		Name:  sColonStatus,
		Value: statusVal,
	})
	for k, vv := range hdr {
		lower := strings.ToLower(k)
		for _, v := range vv {
			fields = append(fields, hpack.HeaderField{
				Name:  []byte(lower),
				Value: []byte(v),
			})
		}
	}

	_ = w.sw.sendHeaders(context.Background(), fields, false)
}

// Status returns the HTTP status code set via WriteHeaders or WriteHeader.
func (w *ResponseWriter) Status() int { return w.status }

// Written reports whether headers have been sent.
func (w *ResponseWriter) Written() bool { return w.written }

// ---------------------------------------------------------------------------
// Adapters: http.Handler ↔ Handler
// ---------------------------------------------------------------------------

// FromHTTPHandler adapts any [http.Handler] (chi.Router, http.ServeMux, etc.)
// to a Poseidon [Handler].
func FromHTTPHandler(h http.Handler) Handler {
	return HandlerFunc(func(ctx context.Context, req *Request, w *ResponseWriter) error {
		httpReq, err := NewHTTPRequest(req)
		if err != nil {
			return err
		}
		httpReq = httpReq.WithContext(ctx)
		h.ServeHTTP(w, httpReq)
		return nil
	})
}

// ToHTTPHandler adapts a Poseidon [Handler] to [http.Handler].
func ToHTTPHandler(h Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := HTTPRequestToRequest(r)
		// We use a discard streamWriter since ToHTTPHandler is a bridge.
		pw := newResponseWriterWithSW(&discardStreamWriter{})
		if err := h.ServeHTTP(r.Context(), req, pw); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for k, vv := range pw.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		if pw.Status() > 0 {
			w.WriteHeader(pw.Status())
		}
	})
}

// discardStreamWriter is a no-op streamWriter for adapter use.
type discardStreamWriter struct{}

func (*discardStreamWriter) sendHeaders(_ context.Context, _ []hpack.HeaderField, _ bool) error {
	return nil
}
func (*discardStreamWriter) sendData(_ context.Context, _ []byte, _ bool) error {
	return nil
}
func (*discardStreamWriter) streamID() uint32 { return 0 }

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// NewHTTPRequest builds a standard [http.Request] from a Poseidon [Request].
func NewHTTPRequest(req *Request) (*http.Request, error) {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := req.Authority
	if host == "" {
		host = "localhost"
	}
	urlStr := scheme + "://" + host + req.Path
	httpReq, err := http.NewRequest(req.Method, urlStr, nil)
	if err != nil {
		return nil, err
	}
	if req.Body != nil {
		httpReq.Body = &closeableReader{data: req.Body}
		httpReq.ContentLength = int64(len(req.Body))
	}
	for _, h := range req.Headers {
		httpReq.Header.Add(string(h.Name), string(h.Value))
	}
	return httpReq, nil
}

// HTTPRequestToRequest converts a standard [http.Request] to a Poseidon [Request].
func HTTPRequestToRequest(r *http.Request) *Request {
	headers := make([]hpack.HeaderField, 0, len(r.Header))
	for k, vv := range r.Header {
		for _, v := range vv {
			headers = append(headers, hpack.HeaderField{
				Name:  []byte(k),
				Value: []byte(v),
			})
		}
	}
	return &Request{
		Method:    r.Method,
		Path:      r.URL.Path,
		Scheme:    r.URL.Scheme,
		Authority: r.URL.Host,
		Headers:   headers,
	}
}

// closeableReader wraps a byte slice as io.ReadCloser.
type closeableReader struct {
	data []byte
	pos  int
}

func (r *closeableReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *closeableReader) Close() error { return nil }

// ---------------------------------------------------------------------------
// Pre-computed byte slices for zero-allocation hot paths
// ---------------------------------------------------------------------------

var sColonStatus = []byte(":status")

// statusBytes returns pre-allocated byte slice for common HTTP status codes.
// Falls back to strconv.AppendInt for uncommon codes.
func statusBytes(code int) []byte {
	switch code {
	case 200:
		return sStatus200
	case 201:
		return sStatus201
	case 204:
		return sStatus204
	case 301:
		return sStatus301
	case 302:
		return sStatus302
	case 304:
		return sStatus304
	case 400:
		return sStatus400
	case 401:
		return sStatus401
	case 403:
		return sStatus403
	case 404:
		return sStatus404
	case 500:
		return sStatus500
	case 502:
		return sStatus502
	case 503:
		return sStatus503
	default:
		var buf [6]byte
		return strconv.AppendInt(buf[:0], int64(code), 10)
	}
}

var (
	sStatus200 = []byte("200")
	sStatus201 = []byte("201")
	sStatus204 = []byte("204")
	sStatus301 = []byte("301")
	sStatus302 = []byte("302")
	sStatus304 = []byte("304")
	sStatus400 = []byte("400")
	sStatus401 = []byte("401")
	sStatus403 = []byte("403")
	sStatus404 = []byte("404")
	sStatus500 = []byte("500")
	sStatus502 = []byte("502")
	sStatus503 = []byte("503")
)
