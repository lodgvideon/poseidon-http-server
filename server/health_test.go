package server

import (
	"context"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// HealthState
// ---------------------------------------------------------------------------

func TestHealthState_DefaultReady(t *testing.T) {
	hs := NewHealthState()
	if !hs.Ready() {
		t.Fatal("NewHealthState should be ready by default")
	}
}

func TestHealthState_SetNotReady(t *testing.T) {
	hs := NewHealthState()
	hs.SetNotReady()
	if hs.Ready() {
		t.Fatal("Ready should be false after SetNotReady")
	}
}

func TestHealthState_SetReady(t *testing.T) {
	hs := NewHealthState()
	hs.SetNotReady()
	hs.SetReady(true)
	if !hs.Ready() {
		t.Fatal("Ready should be true after SetReady(true)")
	}
	hs.SetReady(false)
	if hs.Ready() {
		t.Fatal("Ready should be false after SetReady(false)")
	}
}

// ---------------------------------------------------------------------------
// Liveness — /healthz
// ---------------------------------------------------------------------------

func TestHealthHandler_Liveness_AlwaysOK(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)

	// Liveness is 200 even when not ready (draining).
	hs.SetNotReady()

	w, sw := newTestWriter()
	req := &Request{Method: http.MethodGet, Path: "/healthz"}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", w.Status())
	}
	if len(sw.headersSent) == 0 {
		t.Fatal("expected headers to be written")
	}
}

// ---------------------------------------------------------------------------
// Readiness — /readyz
// ---------------------------------------------------------------------------

func TestHealthHandler_Readiness_OKWhenReady(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)

	w, _ := newTestWriter()
	req := &Request{Method: http.MethodGet, Path: "/readyz"}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", w.Status())
	}
}

func TestHealthHandler_Readiness_503WhenDraining(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)

	// Simulate drain start.
	hs.SetNotReady()

	w, _ := newTestWriter()
	req := &Request{Method: http.MethodGet, Path: "/readyz"}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503 when draining", w.Status())
	}
}

func TestHealthHandler_ReadyThen503(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)
	req := &Request{Method: http.MethodGet, Path: "/readyz"}

	// Ready → 200.
	w1, _ := newTestWriter()
	_ = h.ServeHTTP(context.Background(), req, w1)
	if w1.Status() != http.StatusOK {
		t.Fatalf("before drain: /readyz = %d, want 200", w1.Status())
	}

	// Drain start → 503.
	hs.SetNotReady()
	w2, _ := newTestWriter()
	_ = h.ServeHTTP(context.Background(), req, w2)
	if w2.Status() != http.StatusServiceUnavailable {
		t.Fatalf("after drain: /readyz = %d, want 503", w2.Status())
	}
}

// ---------------------------------------------------------------------------
// Unknown path
// ---------------------------------------------------------------------------

func TestHealthHandler_UnknownPath_404(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)

	w, _ := newTestWriter()
	req := &Request{Method: http.MethodGet, Path: "/other"}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != http.StatusNotFound {
		t.Fatalf("/other status = %d, want 404", w.Status())
	}
}

// ---------------------------------------------------------------------------
// Path with query string is matched on the path component only.
// ---------------------------------------------------------------------------

func TestHealthHandler_PathWithQuery(t *testing.T) {
	hs := NewHealthState()
	h := HealthHandler(hs)

	w, _ := newTestWriter()
	req := &Request{Method: http.MethodGet, Path: "/readyz?verbose=1"}
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != http.StatusOK {
		t.Fatalf("/readyz?verbose=1 status = %d, want 200", w.Status())
	}
}

// ---------------------------------------------------------------------------
// Shutdown drain wiring — readiness flips to NOT-ready at start of drain.
// ---------------------------------------------------------------------------

func TestServer_Shutdown_FlipsReadinessNotReady(t *testing.T) {
	hs := NewHealthState()
	called := make(chan struct{}, 1)

	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, _ ResponseWriter) error {
			return nil
		}),
		OnDrainStart: func() {
			hs.SetNotReady()
			select {
			case called <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if !hs.Ready() {
		t.Fatal("expected ready before shutdown")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled so Shutdown returns promptly with no conns
	_ = srv.Shutdown(ctx)

	if hs.Ready() {
		t.Fatal("expected NOT ready after Shutdown (drain start)")
	}
	select {
	case <-called:
	default:
		t.Fatal("OnDrainStart hook was not called")
	}
}
