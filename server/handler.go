// Package server provides a high-level HTTP/2 server built on the conn layer.
//
// The server package accepts either a native [Handler] or any [http.Handler]
// (chi.Router, http.ServeMux, http.HandlerFunc, etc.) and dispatches incoming
// HTTP/2 streams to the handler. The [ResponseWriter] implements
// [http.ResponseWriter], so standard middleware works unchanged.
package server

import (
	"context"
	"net/http"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Native Poseidon handler (zero-allocation path)
// ---------------------------------------------------------------------------

// Handler processes a single HTTP/2 request.
type Handler interface {
	ServeHTTP(ctx context.Context, req *Request, w *ResponseWriter) error
}

// HandlerFunc is a convenience adapter for Handler.
type HandlerFunc func(ctx context.Context, req *Request, w *ResponseWriter) error

// ServeHTTP implements Handler.
func (f HandlerFunc) ServeHTTP(ctx context.Context, req *Request, w *ResponseWriter) error {
	return f(ctx, req, w)
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// Request represents a server-side HTTP/2 request.
type Request struct {
	// Method is the HTTP method (GET, POST, etc.).
	Method string

	// Path is the :path pseudo-header value.
	Path string

	// Scheme is the :scheme pseudo-header value ("http" or "https").
	Scheme string

	// Authority is the :authority pseudo-header value (host:port).
	Authority string

	// Headers contains all non-pseudo request headers.
	Headers []hpack.HeaderField

	// Body is the collected request body. Nil until fully received.
	Body []byte
}

// ResponseWriter writes an HTTP/2 response. It also implements
// [http.ResponseWriter] so that standard net/http middleware works.
type ResponseWriter struct {
	statusCode int
	headers    http.Header
	wroteHead  bool
	body       []byte
	trailers   []hpack.HeaderField
}

// WriteHeaders sends the response HEADERS frame.
func (w *ResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	w.statusCode = status
	w.wroteHead = true
	for _, h := range headers {
		w.headers.Set(string(h.Name), string(h.Value))
	}
	return nil
}

// WriteData appends response body data.
func (w *ResponseWriter) WriteData(p []byte) error {
	if !w.wroteHead {
		_ = w.WriteHeaders(200, nil)
	}
	w.body = append(w.body, p...)
	return nil
}

// WriteTrailers sets the response trailers.
func (w *ResponseWriter) WriteTrailers(trailers []hpack.HeaderField) error {
	w.trailers = trailers
	return nil
}

// StatusCode returns the status code set via WriteHeaders.
func (w *ResponseWriter) StatusCode() int { return w.statusCode }

// Body returns the accumulated response body.
func (w *ResponseWriter) Body() []byte { return w.body }

// Trailers returns the response trailers.
func (w *ResponseWriter) Trailers() []hpack.HeaderField { return w.trailers }

// ---------------------------------------------------------------------------
// http.ResponseWriter compatibility
// ---------------------------------------------------------------------------

// Header implements http.ResponseWriter.
func (w *ResponseWriter) Header() http.Header { return w.headers }

// Write implements http.ResponseWriter.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	if err := w.WriteData(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteHeader implements http.ResponseWriter.
func (w *ResponseWriter) WriteHeader(statusCode int) {
	_ = w.WriteHeaders(statusCode, nil)
}

// compile-time check
var _ http.ResponseWriter = (*ResponseWriter)(nil)

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
		pw := NewResponseWriter()
		if err := h.ServeHTTP(r.Context(), req, pw); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for k, vv := range pw.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		if pw.StatusCode() > 0 {
			w.WriteHeader(pw.StatusCode())
		}
		_, _ = w.Write(pw.Body())
	})
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// NewResponseWriter creates a zero-value ResponseWriter.
func NewResponseWriter() *ResponseWriter {
	return &ResponseWriter{headers: make(http.Header)}
}

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
		return 0, http.ErrBodyReadAfterClose
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *closeableReader) Close() error { return nil }
