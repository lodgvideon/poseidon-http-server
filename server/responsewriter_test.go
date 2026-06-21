package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Test doubles: a base writer that supports Pusher + Flusher, and wrappers
// that expose Unwrap() but do NOT themselves implement the capabilities.
// ---------------------------------------------------------------------------

// pushFlushRW is a minimal ResponseWriter that ALSO implements Pusher and
// http.Flusher — standing in for the concrete responseWriter at the base of a
// wrapper chain.
type pushFlushRW struct {
	header  http.Header
	pushed  []string
	flushed int
	written bool
	status  int
}

func newPushFlushRW() *pushFlushRW { return &pushFlushRW{header: make(http.Header)} }

func (f *pushFlushRW) Header() http.Header { return f.header }
func (f *pushFlushRW) Write(p []byte) (int, error) {
	f.written = true
	return len(p), nil
}
func (f *pushFlushRW) WriteHeader(status int) { f.status = status; f.written = true }
func (f *pushFlushRW) WriteHeaders(status int, _ []hpack.HeaderField) error {
	f.status = status
	f.written = true
	return nil
}
func (f *pushFlushRW) WriteData([]byte) error                  { f.written = true; return nil }
func (f *pushFlushRW) WriteTrailers([]hpack.HeaderField) error { return nil }
func (f *pushFlushRW) Status() int                             { return f.status }
func (f *pushFlushRW) StatusCode() int                         { return f.status }
func (f *pushFlushRW) Written() bool                           { return f.written }

func (f *pushFlushRW) Push(path string, _ []hpack.HeaderField) (ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock
}
func (f *pushFlushRW) PushWithScheme(path, _ string, _ []hpack.HeaderField) (ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock
}
func (f *pushFlushRW) PushWithPriority(path string, _ []hpack.HeaderField, _ *frame.Priority) (ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock
}
func (f *pushFlushRW) Flush() { f.flushed++ }

// plainRW is a ResponseWriter with NO optional capabilities and NO Unwrap.
type plainRW struct{ pushFlushRWNoCaps }

// pushFlushRWNoCaps embeds the base methods but neither Pusher nor Flusher nor
// Unwrap, so it is a dead-end for the finders.
type pushFlushRWNoCaps struct{ header http.Header }

func newPlainRW() *plainRW { return &plainRW{pushFlushRWNoCaps{header: make(http.Header)}} }

func (f *pushFlushRWNoCaps) Header() http.Header                         { return f.header }
func (f *pushFlushRWNoCaps) Write(p []byte) (int, error)                 { return len(p), nil }
func (f *pushFlushRWNoCaps) WriteHeader(int)                             {}
func (f *pushFlushRWNoCaps) WriteHeaders(int, []hpack.HeaderField) error { return nil }
func (f *pushFlushRWNoCaps) WriteData([]byte) error                      { return nil }
func (f *pushFlushRWNoCaps) WriteTrailers([]hpack.HeaderField) error     { return nil }
func (f *pushFlushRWNoCaps) Status() int                                 { return 0 }
func (f *pushFlushRWNoCaps) StatusCode() int                             { return 0 }
func (f *pushFlushRWNoCaps) Written() bool                               { return false }

// wrapRW is a wrapping ResponseWriter that implements Unwrap() but provides no
// optional capability of its own — exactly like a middleware that doesn't push.
type wrapRW struct {
	ResponseWriter
}

func (w *wrapRW) Unwrap() ResponseWriter { return w.ResponseWriter }

// selfCycleRW implements Unwrap() returning itself, to exercise cycle guarding.
type selfCycleRW struct{ ResponseWriter }

func (w *selfCycleRW) Unwrap() ResponseWriter { return w }

// ---------------------------------------------------------------------------
// PusherOf / FlusherOf
// ---------------------------------------------------------------------------

func TestPusherOf_ThroughDoubleWrap(t *testing.T) {
	t.Parallel()
	base := newPushFlushRW()
	// security(gzip(real)) double-wrap, neither wrapper implements Pusher.
	wrapped := &wrapRW{ResponseWriter: &wrapRW{ResponseWriter: base}}

	p, ok := PusherOf(wrapped)
	if !ok {
		t.Fatal("PusherOf did not find the Pusher through the double wrap")
	}
	if _, err := p.Push("/style.css", nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(base.pushed) != 1 || base.pushed[0] != "/style.css" {
		t.Fatalf("pushed = %v, want [/style.css]", base.pushed)
	}
}

func TestFlusherOf_ThroughDoubleWrap(t *testing.T) {
	t.Parallel()
	base := newPushFlushRW()
	wrapped := &wrapRW{ResponseWriter: &wrapRW{ResponseWriter: base}}

	f, ok := FlusherOf(wrapped)
	if !ok {
		t.Fatal("FlusherOf did not find the Flusher through the double wrap")
	}
	f.Flush()
	if base.flushed != 1 {
		t.Fatalf("flushed = %d, want 1", base.flushed)
	}
}

func TestPusherOf_DirectWriter(t *testing.T) {
	t.Parallel()
	base := newPushFlushRW()
	if _, ok := PusherOf(base); !ok {
		t.Fatal("PusherOf should find a directly-supplied Pusher")
	}
}

func TestPusherOf_NoPushableBase(t *testing.T) {
	t.Parallel()
	// A wrapper over a base with no push capability returns (nil, false).
	wrapped := &wrapRW{ResponseWriter: newPlainRW()}
	if p, ok := PusherOf(wrapped); ok || p != nil {
		t.Fatalf("PusherOf = (%v, %v), want (nil, false)", p, ok)
	}
}

func TestFlusherOf_NoFlushableBase(t *testing.T) {
	t.Parallel()
	wrapped := &wrapRW{ResponseWriter: newPlainRW()}
	if f, ok := FlusherOf(wrapped); ok || f != nil {
		t.Fatalf("FlusherOf = (%v, %v), want (nil, false)", f, ok)
	}
}

func TestPusherOf_CycleGuard(t *testing.T) {
	t.Parallel()
	// Unwrap returns self: must terminate, not loop forever.
	c := &selfCycleRW{}
	if _, ok := PusherOf(c); ok {
		t.Fatal("PusherOf should report no Pusher for a self-cycling wrapper")
	}
	if _, ok := FlusherOf(c); ok {
		t.Fatal("FlusherOf should report no Flusher for a self-cycling wrapper")
	}
}

// ---------------------------------------------------------------------------
// Concrete responseWriter implements http.Flusher (no-op).
// ---------------------------------------------------------------------------

func TestResponseWriter_FlushIsNoOpButSatisfiesFlusher(t *testing.T) {
	t.Parallel()
	w, _ := newTestWriter()
	f, ok := FlusherOf(w)
	if !ok {
		t.Fatal("concrete responseWriter should satisfy http.Flusher via FlusherOf")
	}
	f.Flush() // must not panic
}

// ---------------------------------------------------------------------------
// ToHTTPHandler forwards the response body (the discard bug).
// ---------------------------------------------------------------------------

func TestToHTTPHandler_ForwardsBody(t *testing.T) {
	t.Parallel()
	poseidonHandler := HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		w.Header().Set("x-custom", "yes")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello body"))
		return nil
	})

	httpHandler := ToHTTPHandler(poseidonHandler)
	rec := httptest.NewRecorder()
	httpHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/test", http.NoBody))

	if rec.Code != 201 {
		t.Errorf("Status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("x-custom"); got != "yes" {
		t.Errorf("x-custom = %q, want yes", got)
	}
	if got := rec.Body.String(); got != "hello body" {
		t.Errorf("body = %q, want %q", got, "hello body")
	}
}

func TestToHTTPHandler_ForwardsBodyNativePath(t *testing.T) {
	t.Parallel()
	poseidonHandler := HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		_ = w.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("text/plain")},
		})
		return w.WriteData([]byte("native body"))
	})

	httpHandler := ToHTTPHandler(poseidonHandler)
	rec := httptest.NewRecorder()
	httpHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/n", http.NoBody))

	if rec.Code != 200 {
		t.Errorf("Status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("content-type"); got != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", got)
	}
	if got := rec.Body.String(); got != "native body" {
		t.Errorf("body = %q, want %q", got, "native body")
	}
}
