package middleware

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// RequestID echoes the id it assigns (#213).
//
// The middleware documented an X-Request-ID response header and set it nowhere:
// the id existed only inside the process, which cannot do the one thing a
// request id is for — matching a client's report to a server's log line.
//
// It has to reach the response through a wrapping writer, not a plain
// w.Header().Set: a handler answering through the native WriteHeaders path never
// looks at that map. Both paths are asserted below, and so is the auto-200 each
// of them has.
// ---------------------------------------------------------------------------

// recordingWriter is a server.ResponseWriter that records what a handler sent,
// on both write paths.
type recordingWriter struct {
	hdr     http.Header
	native  []hpack.HeaderField
	body    []byte
	status  int
	written bool
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{hdr: http.Header{}}
}

func (w *recordingWriter) Header() http.Header { return w.hdr }

func (w *recordingWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status, w.written = status, true
	// Mirror the real writer: the stdlib map becomes the field section.
	for k, vv := range w.hdr {
		for _, v := range vv {
			w.native = append(w.native, hpack.HeaderField{
				Name: []byte(strings.ToLower(k)), Value: []byte(v),
			})
		}
	}
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *recordingWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	if w.written {
		return nil
	}
	w.status, w.written = status, true
	w.native = append(w.native, headers...)
	return nil
}

func (w *recordingWriter) WriteData(p []byte) error {
	if !w.written {
		_ = w.WriteHeaders(http.StatusOK, nil)
	}
	w.body = append(w.body, p...)
	return nil
}

func (w *recordingWriter) WriteTrailers(_ []hpack.HeaderField) error { return nil }
func (w *recordingWriter) Status() int                               { return w.status }
func (w *recordingWriter) StatusCode() int                           { return w.status }
func (w *recordingWriter) Written() bool                             { return w.written }

var _ server.ResponseWriter = (*recordingWriter)(nil)

// sentRequestID returns the x-request-id the writer ended up sending, from
// whichever path put it there.
func (w *recordingWriter) sentRequestID() string {
	for _, f := range w.native {
		if strings.EqualFold(string(f.Name), "x-request-id") {
			return string(f.Value)
		}
	}
	return ""
}

// runRequestID drives the middleware over one request and returns the writer and
// the id the handler saw in its context.
func runRequestID(t *testing.T, req *server.Request, h server.HandlerFunc) (*recordingWriter, string) {
	t.Helper()
	w := newRecordingWriter()
	var seen string
	wrapped := RequestID()(server.HandlerFunc(func(ctx context.Context, r *server.Request, rw server.ResponseWriter) error {
		seen = FromContext(ctx)
		return h(ctx, r, rw)
	}))
	if err := wrapped.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return w, seen
}

func TestRequestID_EchoesOnEveryWritePath(t *testing.T) {
	t.Parallel()

	paths := map[string]server.HandlerFunc{
		"native WriteHeaders": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		},
		"native WriteHeaders with other fields": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteHeaders(200, []hpack.HeaderField{
				{Name: []byte("content-type"), Value: []byte("text/plain")},
			})
		},
		"stdlib WriteHeader": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			w.WriteHeader(200)
			return nil
		},
		"stdlib Write with no explicit status": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			_, err := w.Write([]byte("hi"))
			return err
		},
		"native WriteData with no explicit status": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteData([]byte("hi"))
		},
	}

	for name, h := range paths {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, seen := runRequestID(t, &server.Request{Method: "GET", Path: "/"}, h)

			sent := w.sentRequestID()
			if sent == "" {
				t.Fatal("no x-request-id reached the response; the id never leaves the process")
			}
			if seen == "" {
				t.Fatal("no id in the handler's context")
			}
			if sent != seen {
				t.Errorf("sent %q but the context carried %q; a log line and a client report "+
					"would not match", sent, seen)
			}
		})
	}
}

// TestRequestID_EchoesTheClientsValue pins that an id assigned upstream survives
// this hop, which is what makes it useful across a chain of services.
func TestRequestID_EchoesTheClientsValue(t *testing.T) {
	t.Parallel()

	req := &server.Request{
		Method:  "GET",
		Path:    "/",
		Headers: []hpack.HeaderField{{Name: []byte("x-request-id"), Value: []byte("client-123")}},
	}
	w, seen := runRequestID(t, req, func(_ context.Context, _ *server.Request, rw server.ResponseWriter) error {
		return rw.WriteHeaders(200, nil)
	})
	if seen != "client-123" {
		t.Errorf("context id = %q, want the client's %q", seen, "client-123")
	}
	if got := w.sentRequestID(); got != "client-123" {
		t.Errorf("echoed %q, want the client's %q", got, "client-123")
	}
}

// TestRequestID_HandlerValueWins covers the other direction: a handler that sets
// the header deliberately must not have it overwritten or duplicated.
func TestRequestID_HandlerValueWins(t *testing.T) {
	t.Parallel()

	cases := map[string]server.HandlerFunc{
		"native": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteHeaders(200, []hpack.HeaderField{
				{Name: []byte("x-request-id"), Value: []byte("handler-choice")},
			})
		},
		"stdlib": func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			w.Header().Set("X-Request-Id", "handler-choice")
			w.WriteHeader(200)
			return nil
		},
	}

	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, _ := runRequestID(t, &server.Request{Method: "GET", Path: "/"}, h)
			if got := w.sentRequestID(); got != "handler-choice" {
				t.Errorf("sent %q, want the handler's %q", got, "handler-choice")
			}
			var n int
			for _, f := range w.native {
				if strings.EqualFold(string(f.Name), "x-request-id") {
					n++
				}
			}
			if n != 1 {
				t.Errorf("x-request-id appears %d times, want exactly 1", n)
			}
		})
	}
}

// TestRequestID_WriterUnwraps keeps the wrapper from silently disabling optional
// capabilities. securityResponseWriter has the same method for the same reason:
// without Unwrap, server.PusherOf and server.FlusherOf stop at this writer and a
// handler loses Server Push just because RequestID is in the chain.
func TestRequestID_WriterUnwraps(t *testing.T) {
	t.Parallel()

	inner := newRecordingWriter()
	w := &requestIDResponseWriter{ResponseWriter: inner, id: "x"}
	if w.Unwrap() != server.ResponseWriter(inner) {
		t.Error("Unwrap did not return the wrapped writer")
	}
}
