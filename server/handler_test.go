package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// contextKey avoids revive context-keys-type warning.
type contextKey string

// ---------------------------------------------------------------------------
// ResponseWriter tests
// ---------------------------------------------------------------------------

func TestResponseWriter_WriteHeaders(t *testing.T) {
	w := NewResponseWriter()
	if err := w.WriteHeaders(201, []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("text/plain")},
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if w.StatusCode() != 201 {
		t.Errorf("StatusCode = %d, want 201", w.StatusCode())
	}
	if ct := w.Header().Get("content-type"); ct != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	if !w.wroteHead {
		t.Error("wroteHead should be true after WriteHeaders")
	}
}

func TestResponseWriter_WriteData_Auto200(t *testing.T) {
	w := NewResponseWriter()
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if w.StatusCode() != 200 {
		t.Errorf("StatusCode = %d, want auto 200", w.StatusCode())
	}
	if string(w.Body()) != "hello" {
		t.Errorf("Body = %q, want hello", w.Body())
	}
}

func TestResponseWriter_WriteTrailers(t *testing.T) {
	w := NewResponseWriter()
	trailers := []hpack.HeaderField{
		{Name: []byte("grpc-status"), Value: []byte("0")},
	}
	if err := w.WriteTrailers(trailers); err != nil {
		t.Fatalf("WriteTrailers: %v", err)
	}
	if len(w.Trailers()) != 1 {
		t.Fatalf("Trailers len = %d, want 1", len(w.Trailers()))
	}
	if string(w.Trailers()[0].Value) != "0" {
		t.Errorf("trailer value = %q, want 0", w.Trailers()[0].Value)
	}
}

func TestResponseWriter_httpResponseWriter_Interface(t *testing.T) {
	// Compile-time check is in handler.go (var _ http.ResponseWriter).
	// Runtime sanity check:
	w := NewResponseWriter()
	var _ http.ResponseWriter = w
	_ = w.Header()
	w.WriteHeader(404)
	if w.StatusCode() != 404 {
		t.Errorf("StatusCode = %d, want 404", w.StatusCode())
	}
}

// ---------------------------------------------------------------------------
// Request conversion tests
// ---------------------------------------------------------------------------

func TestNewHTTPRequest(t *testing.T) {
	req := &Request{
		Method:    "POST",
		Path:      "/api/v1/users",
		Scheme:    "https",
		Authority: "example.com",
		Headers: []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("application/json")},
		},
		Body: []byte(`{"name":"test"}`),
	}
	httpReq, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}
	if httpReq.Method != "POST" {
		t.Errorf("Method = %q, want POST", httpReq.Method)
	}
	if httpReq.URL.Path != "/api/v1/users" {
		t.Errorf("Path = %q, want /api/v1/users", httpReq.URL.Path)
	}
	if httpReq.URL.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", httpReq.URL.Scheme)
	}
	if httpReq.URL.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", httpReq.URL.Host)
	}
	if httpReq.ContentLength != 15 {
		t.Errorf("ContentLength = %d, want 15", httpReq.ContentLength)
	}
	ct := httpReq.Header.Get("content-type")
	if ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	// Read body
	body := make([]byte, len(req.Body))
	n, _ := httpReq.Body.Read(body)
	if string(body[:n]) != `{"name":"test"}` {
		t.Errorf("Body = %q, want json", string(body[:n]))
	}
}

func TestNewHTTPRequest_Defaults(t *testing.T) {
	req := &Request{Method: "GET", Path: "/"}
	httpReq, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}
	if httpReq.URL.Scheme != "http" {
		t.Errorf("default Scheme = %q, want http", httpReq.URL.Scheme)
	}
	if httpReq.URL.Host != "localhost" {
		t.Errorf("default Host = %q, want localhost", httpReq.URL.Host)
	}
}

func TestHTTPRequestToRequest(t *testing.T) {
	httpReq := httptest.NewRequest("DELETE", "http://api.example.com/items/42", nil)
	httpReq.Header.Set("x-request-id", "abc123")
	req := HTTPRequestToRequest(httpReq)
	if req.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", req.Method)
	}
	if req.Path != "/items/42" {
		t.Errorf("Path = %q, want /items/42", req.Path)
	}
	found := false
	for _, h := range req.Headers {
		if string(h.Name) == "X-Request-Id" && string(h.Value) == "abc123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("x-request-id header not found in converted request")
	}
}

// ---------------------------------------------------------------------------
// Adapter tests
// ---------------------------------------------------------------------------

func TestFromHTTPHandler_ChiStyle(t *testing.T) {
	// Simulate a chi-style handler.
	stdHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello from chi"))
	})

	handler := FromHTTPHandler(stdHandler)

	req := &Request{
		Method:    "GET",
		Path:      "/hello",
		Scheme:    "http",
		Authority: "localhost",
	}
	w := NewResponseWriter()

	if err := handler.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.StatusCode() != 200 {
		t.Errorf("StatusCode = %d, want 200", w.StatusCode())
	}
	if string(w.Body()) != "hello from chi" {
		t.Errorf("Body = %q, want hello from chi", w.Body())
	}
}

func TestFromHTTPHandler_UsesContext(t *testing.T) {
	stdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxVal := r.Context().Value(contextKey("testkey"))
		if ctxVal != nil {
			_, _ = w.Write([]byte(ctxVal.(string)))
		} else {
			_, _ = w.Write([]byte("no-ctx"))
		}
	})

	handler := FromHTTPHandler(stdHandler)
	ctx := context.WithValue(context.Background(), contextKey("testkey"), "ctx-works")

	req := &Request{Method: "GET", Path: "/ctx"}
	w := NewResponseWriter()

	if err := handler.ServeHTTP(ctx, req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if string(w.Body()) != "ctx-works" {
		t.Errorf("Body = %q, want ctx-works", w.Body())
	}
}

func TestToHTTPHandler_Roundtrip(t *testing.T) {
	poseidonHandler := HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
		_ = w.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("x-custom"), Value: []byte("yes")},
		})
		_, _ = w.Write([]byte("poseidon-response"))
		return nil
	})

	httpHandler := ToHTTPHandler(poseidonHandler)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)

	httpHandler.ServeHTTP(rec, httpReq)

	if rec.Code != 200 {
		t.Errorf("Status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "poseidon-response" {
		t.Errorf("Body = %q, want poseidon-response", rec.Body.String())
	}
	if rec.Header().Get("x-custom") != "yes" {
		t.Errorf("x-custom = %q, want yes", rec.Header().Get("x-custom"))
	}
}

func TestToHTTPHandler_ErrorReturns500(t *testing.T) {
	poseidonHandler := HandlerFunc(func(_ context.Context, _ *Request, _ *ResponseWriter) error {
		return context.DeadlineExceeded
	})

	httpHandler := ToHTTPHandler(poseidonHandler)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/err", nil)

	httpHandler.ServeHTTP(rec, httpReq)

	if rec.Code != 500 {
		t.Errorf("Status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// HandlerFunc adapter
// ---------------------------------------------------------------------------

func TestHandlerFunc_ServeHTTP(t *testing.T) {
	called := false
	h := HandlerFunc(func(_ context.Context, _ *Request, _ *ResponseWriter) error {
		called = true
		return nil
	})
	w := NewResponseWriter()
	if err := h.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

// ---------------------------------------------------------------------------
// Full chi drop-in integration
// ---------------------------------------------------------------------------

func TestChiStyleRouter_DropIn(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("pong"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("msg")))
	})

	handler := FromHTTPHandler(mux)

	// Test /ping
	w := NewResponseWriter()
	if err := handler.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/ping"}, w); err != nil {
		t.Fatalf("/ping: %v", err)
	}
	if string(w.Body()) != "pong" {
		t.Errorf("/ping Body = %q, want pong", w.Body())
	}

	// Test /echo
	w2 := NewResponseWriter()
	if err := handler.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/echo?msg=hi"}, w2); err != nil {
		t.Fatalf("/echo: %v", err)
	}
	if string(w2.Body()) != "hi" {
		t.Errorf("/echo Body = %q, want hi", w2.Body())
	}
}
