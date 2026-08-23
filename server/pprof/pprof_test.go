package pprof_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
	pprofhandler "github.com/lodgvideon/poseidon-http-server/server/pprof"
)

// recorderWriter is a server.ResponseWriter backed by an httptest recorder.
//
// The handler is driven natively rather than through server.ToHTTPHandler
// because that adapter cannot carry a server-shaped request: HTTPRequestToRequest
// takes the authority from r.URL.Host, which net/http leaves empty on every
// request a server receives, so the round trip back through FromHTTPHandler
// fails with ErrNoAuthority and answers 400 (issue #211). Testing through it
// would measure that bug instead of this handler.
type recorderWriter struct {
	*httptest.ResponseRecorder
	status  int
	written bool
}

func newRecorderWriter() *recorderWriter {
	return &recorderWriter{ResponseRecorder: httptest.NewRecorder()}
}

func (w *recorderWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status, w.written = status, true
	w.ResponseRecorder.WriteHeader(status)
}

func (w *recorderWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseRecorder.Write(p)
}

func (w *recorderWriter) WriteHeaders(status int, _ []hpack.HeaderField) error {
	w.WriteHeader(status)
	return nil
}

func (w *recorderWriter) WriteData(p []byte) error {
	_, err := w.Write(p)
	return err
}

func (w *recorderWriter) WriteTrailers(_ []hpack.HeaderField) error { return nil }
func (w *recorderWriter) Status() int                               { return w.status }
func (w *recorderWriter) StatusCode() int                           { return w.status }
func (w *recorderWriter) Written() bool                             { return w.written }

// compile-time proof the fake really is the interface under test.
var _ server.ResponseWriter = (*recorderWriter)(nil)

func serve(t *testing.T, path, rawQuery string) *recorderWriter {
	t.Helper()
	h := pprofhandler.Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
	full := path
	if rawQuery != "" {
		full += "?" + rawQuery
	}
	w := newRecorderWriter()
	req := &server.Request{
		Method:    http.MethodGet,
		Path:      full,
		RawQuery:  rawQuery,
		Scheme:    "http",
		Authority: "example.com",
	}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP(%s): %v", full, err)
	}
	return w
}

func TestHandler_Index(t *testing.T) {
	w := serve(t, "/debug/pprof/", "")
	if w.Status() != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Status())
	}
	if body := w.Body.String(); !strings.Contains(body, "pprof") {
		t.Fatalf("body carries no pprof index marker; got %q", body)
	}
}

func TestHandler_NamedProfiles(t *testing.T) {
	cases := []struct{ path, query string }{
		{"/debug/pprof/heap", "debug=1"},
		{"/debug/pprof/goroutine", "debug=1"},
		{"/debug/pprof/allocs", "debug=1"},
		{"/debug/pprof/threadcreate", "debug=1"},
		{"/debug/pprof/cmdline", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if w := serve(t, tc.path, tc.query); w.Status() != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Status())
			}
		})
	}
}

// TestHandler_UsesAnIsolatedMux pins the half of the contract that keeps this
// handler predictable: it serves its own mux, not http.DefaultServeMux. If it
// ever fell back to the default mux, whatever else the process registered there
// would start answering through it.
func TestHandler_UsesAnIsolatedMux(t *testing.T) {
	const canary = "/zz-default-mux-canary"
	http.DefaultServeMux.HandleFunc(canary, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	if w := serve(t, canary, ""); w.Status() == http.StatusTeapot {
		t.Fatal("the handler served a route registered on http.DefaultServeMux")
	}
}
