package middleware

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Fake Tracer/Span — records what the middleware reports
// ---------------------------------------------------------------------------

type fakeSpan struct {
	mu     sync.Mutex
	name   string
	attrs  map[string]any
	status int
	ended  bool
}

func (s *fakeSpan) SetAttribute(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attrs == nil {
		s.attrs = make(map[string]any)
	}
	s.attrs[key] = value
}

func (s *fakeSpan) SetStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

func (s *fakeSpan) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
}

func (s *fakeSpan) snapshot() (name string, attrs map[string]any, status int, ended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string]any, len(s.attrs))
	for k, v := range s.attrs {
		cp[k] = v
	}
	return s.name, cp, s.status, s.ended
}

type fakeTracer struct {
	mu    sync.Mutex
	spans []*fakeSpan
}

func (tr *fakeTracer) StartSpan(ctx context.Context, name string) (context.Context, Span) {
	sp := &fakeSpan{name: name}
	tr.mu.Lock()
	tr.spans = append(tr.spans, sp)
	tr.mu.Unlock()
	return ctx, sp
}

func (tr *fakeTracer) last() *fakeSpan {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.spans) == 0 {
		return nil
	}
	return tr.spans[len(tr.spans)-1]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestTracing_RecordsMethodPathStatus(t *testing.T) {
	tr := &fakeTracer{}
	done := make(chan struct{})

	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		defer close(done)
		return w.WriteHeaders(201, nil)
	})

	mw := Tracing(TracingConfig{Tracer: tr})
	ln := startTestServer(t, mw(handler))
	sendRequest(t, ln.Addr().String())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler timed out")
	}

	// Span End() happens after the handler returns (on the server goroutine).
	deadline := time.Now().Add(5 * time.Second)
	for {
		sp := tr.last()
		if sp != nil {
			if _, _, _, ended := sp.snapshot(); ended {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("span was not ended within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sp := tr.last()
	if sp == nil {
		t.Fatal("no span was started")
	}
	name, attrs, status, ended := sp.snapshot()
	if !ended {
		t.Fatal("span End() was not called")
	}
	if name != "GET /test" {
		t.Errorf("span name = %q, want %q", name, "GET /test")
	}
	if attrs["http.method"] != "GET" {
		t.Errorf("http.method = %v, want GET", attrs["http.method"])
	}
	if attrs["http.path"] != "/test" {
		t.Errorf("http.path = %v, want /test", attrs["http.path"])
	}
	if attrs["http.status_code"] != 201 {
		t.Errorf("http.status_code attr = %v, want 201", attrs["http.status_code"])
	}
	if status != 201 {
		t.Errorf("span status = %d, want 201", status)
	}
}

func TestTracing_NilTracerPassesThrough(t *testing.T) {
	called := make(chan struct{}, 1)
	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return w.WriteHeaders(200, nil)
	})

	// Nil Tracer => the middleware must be a pure pass-through (zero overhead),
	// returning the original handler unchanged.
	mw := Tracing(TracingConfig{Tracer: nil})
	wrapped := mw(handler)

	ln := startTestServer(t, wrapped)
	sendRequest(t, ln.Addr().String())

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called through nil-tracer pass-through")
	}
}

func TestTracing_DefaultStatusIsOK(t *testing.T) {
	tr := &fakeTracer{}
	done := make(chan struct{})

	// Handler that writes a body without explicitly setting a status: the
	// effective status is 200, which the span must record.
	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		defer close(done)
		return w.WriteData([]byte("ok"))
	})

	mw := Tracing(TracingConfig{Tracer: tr})
	ln := startTestServer(t, mw(handler))
	sendRequest(t, ln.Addr().String())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler timed out")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if sp := tr.last(); sp != nil {
			if _, _, _, ended := sp.snapshot(); ended {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("span was not ended within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_, attrs, status, _ := tr.last().snapshot()
	if status != 200 {
		t.Errorf("span status = %d, want 200", status)
	}
	if attrs["http.status_code"] != 200 {
		t.Errorf("http.status_code attr = %v, want 200", attrs["http.status_code"])
	}
}

// TestTracing_HandlerPanic verifies the span is ENDED (not leaked) even when the
// handler panics, and that the panic still propagates to outer middleware.
func TestTracing_HandlerPanic(t *testing.T) {
	tr := &fakeTracer{}
	panicked := make(chan struct{})

	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		close(panicked)
		panic("boom")
	})

	// Recovery (outer) catches the re-raised panic; Tracing must still End the span.
	chain := server.Chain(Recovery(nil), Tracing(TracingConfig{Tracer: tr}))
	ln := startTestServer(t, chain(handler))
	sendRequest(t, ln.Addr().String())

	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if sp := tr.last(); sp != nil {
			if _, _, _, ended := sp.snapshot(); ended {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("span was not ended after handler panic (span leak)")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_, _, status, ended := tr.last().snapshot()
	if !ended {
		t.Fatal("span End() not called on panic")
	}
	if status != 500 {
		t.Errorf("span status on panic = %d, want 500", status)
	}
}

// TestTracing_ErrorPropagation verifies a handler error is returned unchanged and
// the span is still ended. Unit-level: the handler returns without writing, so a
// nil-stream ResponseWriter is never touched.
func TestTracing_ErrorPropagation(t *testing.T) {
	tr := &fakeTracer{}
	wantErr := errors.New("handler failed")

	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		return wantErr
	})

	mw := Tracing(TracingConfig{Tracer: tr})
	gotErr := mw(handler).ServeHTTP(context.Background(),
		&server.Request{Method: "GET", Path: "/e"}, server.NewResponseWriter(nil))

	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("error = %v, want %v", gotErr, wantErr)
	}
	if sp := tr.last(); sp == nil {
		t.Fatal("no span started")
	} else if _, _, _, ended := sp.snapshot(); !ended {
		t.Fatal("span End() not called when handler returns error")
	}
}

// Compile-time check that the fake satisfies the interfaces.
var (
	_ Tracer = (*fakeTracer)(nil)
	_ Span   = (*fakeSpan)(nil)
)
