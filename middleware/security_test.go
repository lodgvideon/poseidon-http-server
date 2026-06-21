package middleware

import (
	"context"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// okHandler is a trivial handler that writes a 200 with a small body via the
// native write path.
func okHandler() server.Handler {
	return server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		if err := w.WriteHeaders(200, nil); err != nil {
			return err
		}
		return w.WriteData([]byte("ok"))
	})
}

func TestSecurityHeaders_DefaultsOnNativePath(t *testing.T) {
	t.Parallel()

	rw := newFakeRW()
	mw := SecurityHeaders(DefaultSecurityHeadersConfig())
	h := mw(okHandler())

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if rw.nativeStatus != 200 {
		t.Fatalf("status = %d, want 200", rw.nativeStatus)
	}

	want := map[string]string{
		"x-content-type-options":    "nosniff",
		"x-frame-options":           "DENY",
		"referrer-policy":           "no-referrer",
		"strict-transport-security": "max-age=31536000; includeSubDomains",
	}
	for name, val := range want {
		if !hasField(rw.nativeHeaders, name, val) {
			t.Errorf("missing header %s: %s\n got: %v", name, val, rw.nativeHeaders)
		}
	}

	// CSP is empty by default -> must NOT be present.
	for _, h := range rw.nativeHeaders {
		if string(h.Name) == "content-security-policy" {
			t.Errorf("content-security-policy should be absent by default, got %q", h.Value)
		}
	}
}

func TestSecurityHeaders_CustomCSPAndReferrer(t *testing.T) {
	t.Parallel()

	cfg := DefaultSecurityHeadersConfig()
	cfg.ContentSecurityPolicy = "default-src 'self'"
	cfg.ReferrerPolicy = "strict-origin-when-cross-origin"

	rw := newFakeRW()
	h := SecurityHeaders(cfg)(okHandler())

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if !hasField(rw.nativeHeaders, "content-security-policy", "default-src 'self'") {
		t.Errorf("missing CSP header, got: %v", rw.nativeHeaders)
	}
	if !hasField(rw.nativeHeaders, "referrer-policy", "strict-origin-when-cross-origin") {
		t.Errorf("referrer-policy not overridden, got: %v", rw.nativeHeaders)
	}
}

func TestSecurityHeaders_HSTSDisabled(t *testing.T) {
	t.Parallel()

	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTSMaxAge = 0 // disable HSTS

	rw := newFakeRW()
	h := SecurityHeaders(cfg)(okHandler())

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	for _, hf := range rw.nativeHeaders {
		if string(hf.Name) == "strict-transport-security" {
			t.Errorf("HSTS should be absent when HSTSMaxAge=0, got %q", hf.Value)
		}
	}
	// Other headers still present.
	if !hasField(rw.nativeHeaders, "x-content-type-options", "nosniff") {
		t.Errorf("x-content-type-options missing, got: %v", rw.nativeHeaders)
	}
}

func TestSecurityHeaders_HSTSPreload(t *testing.T) {
	t.Parallel()

	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTSPreload = true

	rw := newFakeRW()
	h := SecurityHeaders(cfg)(okHandler())

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if !hasField(rw.nativeHeaders, "strict-transport-security",
		"max-age=31536000; includeSubDomains; preload") {
		t.Errorf("HSTS preload directive missing, got: %v", rw.nativeHeaders)
	}
}

func TestSecurityHeaders_DoesNotDuplicateExisting(t *testing.T) {
	t.Parallel()

	// Handler that already sets X-Frame-Options itself.
	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("x-frame-options"), Value: []byte("SAMEORIGIN")},
		})
	})

	rw := newFakeRW()
	h := SecurityHeaders(DefaultSecurityHeadersConfig())(handler)

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	var count int
	for _, hf := range rw.nativeHeaders {
		if string(hf.Name) == "x-frame-options" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("x-frame-options appears %d times, want 1 (handler value preserved): %v", count, rw.nativeHeaders)
	}
	if !hasField(rw.nativeHeaders, "x-frame-options", "SAMEORIGIN") {
		t.Errorf("handler's x-frame-options value should win, got: %v", rw.nativeHeaders)
	}
}

func TestSecurityHeaders_HTTPPath(t *testing.T) {
	t.Parallel()

	// Handler that uses the stdlib WriteHeader/Write path.
	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		w.WriteHeader(200)
		_, err := w.Write([]byte("ok"))
		return err
	})

	rw := newFakeRW()
	h := SecurityHeaders(DefaultSecurityHeadersConfig())(handler)

	req := &server.Request{Method: "GET", Path: "/", Scheme: "https"}
	if err := h.ServeHTTP(context.Background(), req, rw); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if rw.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("x-content-type-options not set on http path: %v", rw.header)
	}
	if rw.header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("x-frame-options not set on http path: %v", rw.header)
	}
}
