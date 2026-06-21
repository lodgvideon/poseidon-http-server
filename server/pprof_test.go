package server

import (
	"bytes"
	"context"
	"testing"
)

// TestPprofHandler_Index verifies that a GET to /debug/pprof/ via the
// opt-in pprof handler returns 200 and the pprof index body.
func TestPprofHandler_Index(t *testing.T) {
	h := PprofHandler()
	if h == nil {
		t.Fatal("PprofHandler() returned nil")
	}

	w, sw := newTestWriter()
	req := &Request{
		Method: "GET",
		Path:   "/debug/pprof/",
		Scheme: "http",
	}

	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if w.Status() != 200 {
		t.Fatalf("status = %d, want 200", w.Status())
	}

	var body bytes.Buffer
	for _, chunk := range sw.dataSent {
		body.Write(chunk)
	}
	if !bytes.Contains(body.Bytes(), []byte("pprof")) {
		t.Fatalf("body does not contain pprof index marker; got %q", body.String())
	}
}

// TestPprofHandler_Heap verifies the /debug/pprof/heap profile endpoint
// routes correctly and returns 200.
func TestPprofHandler_Heap(t *testing.T) {
	h := PprofHandler()

	w, sw := newTestWriter()
	req := &Request{
		Method: "GET",
		Path:   "/debug/pprof/heap?debug=1",
		Scheme: "http",
	}

	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != 200 {
		t.Fatalf("heap status = %d, want 200", w.Status())
	}
	_ = sw
}

// TestPprofHandler_Cmdline verifies the /debug/pprof/cmdline endpoint.
func TestPprofHandler_Cmdline(t *testing.T) {
	h := PprofHandler()

	w, _ := newTestWriter()
	req := &Request{
		Method: "GET",
		Path:   "/debug/pprof/cmdline",
		Scheme: "http",
	}

	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != 200 {
		t.Fatalf("cmdline status = %d, want 200", w.Status())
	}
}
