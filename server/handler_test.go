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

// mockStreamWriter captures writes for test assertions.
type mockStreamWriter struct {
	headersSent [][]hpack.HeaderField
	dataSent    [][]byte
	trailers    [][]hpack.HeaderField
	endStream   []bool
	id          uint32
}

func (m *mockStreamWriter) sendHeaders(_ context.Context, headers []hpack.HeaderField, endStream bool) error {
	m.headersSent = append(m.headersSent, headers)
	m.endStream = append(m.endStream, endStream)
	if endStream {
		m.trailers = append(m.trailers, headers)
	}
	return nil
}

func (m *mockStreamWriter) sendData(_ context.Context, p []byte, endStream bool) error {
	m.dataSent = append(m.dataSent, p)
	m.endStream = append(m.endStream, endStream)
	return nil
}

func (m *mockStreamWriter) streamID() uint32 { return m.id }

func newTestWriter() (*ResponseWriter, *mockStreamWriter) {
	sw := &mockStreamWriter{id: 1}
	return newResponseWriterWithSW(sw), sw
}

// ---------------------------------------------------------------------------
// ResponseWriter tests
// ---------------------------------------------------------------------------

func TestResponseWriter_WriteHeaders(t *testing.T) {
	w, sw := newTestWriter()
	if err := w.WriteHeaders(201, []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("text/plain")},
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if w.Status() != 201 {
		t.Errorf("Status = %d, want 201", w.Status())
	}
	if !w.Written() {
		t.Error("Written should be true after WriteHeaders")
	}
	if len(sw.headersSent) != 1 {
		t.Fatalf("headersSent = %d calls, want 1", len(sw.headersSent))
	}
	h := sw.headersSent[0]
	// First header should be :status
	if string(h[0].Name) != ":status" || string(h[0].Value) != "201" {
		t.Errorf("first header = %q:%q, want :status:201", h[0].Name, h[0].Value)
	}
}

func TestResponseWriter_WriteHeaders_Idempotent(t *testing.T) {
	w, sw := newTestWriter()
	_ = w.WriteHeaders(200, nil)
	_ = w.WriteHeaders(500, nil) // should be no-op
	if len(sw.headersSent) != 1 {
		t.Errorf("headersSent = %d calls, want 1 (idempotent)", len(sw.headersSent))
	}
}

func TestResponseWriter_WriteData_Auto200(t *testing.T) {
	w, sw := newTestWriter()
	if err := w.WriteData([]byte("hello")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	if w.Status() != 200 {
		t.Errorf("Status = %d, want auto 200", w.Status())
	}
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "hello" {
		t.Errorf("dataSent = %v, want [hello]", sw.dataSent)
	}
}

func TestResponseWriter_WriteTrailers(t *testing.T) {
	w, sw := newTestWriter()
	_ = w.WriteHeaders(200, nil)
	trailers := []hpack.HeaderField{
		{Name: []byte("grpc-status"), Value: []byte("0")},
	}
	if err := w.WriteTrailers(trailers); err != nil {
		t.Fatalf("WriteTrailers: %v", err)
	}
	if len(sw.trailers) != 1 {
		t.Fatalf("trailers = %d, want 1", len(sw.trailers))
	}
}

func TestResponseWriter_httpResponseWriter_Interface(t *testing.T) {
	w, _ := newTestWriter()
	var _ http.ResponseWriter = w
	_ = w.Header()
	w.WriteHeader(404)
	if w.Status() != 404 {
		t.Errorf("Status = %d, want 404", w.Status())
	}
}

func TestResponseWriter_Write_SendsData(t *testing.T) {
	w, sw := newTestWriter()
	n, err := w.Write([]byte("abc"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 3 {
		t.Errorf("Write returned %d, want 3", n)
	}
	if w.Status() != 200 {
		t.Errorf("Status = %d, want auto 200", w.Status())
	}
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "abc" {
		t.Errorf("dataSent = %v, want [abc]", sw.dataSent)
	}
}

func TestResponseWriter_WriteHeader_SendsHPACK(t *testing.T) {
	w, sw := newTestWriter()
	w.Header().Set("content-type", "text/html")
	w.WriteHeader(200)
	if len(sw.headersSent) != 1 {
		t.Fatalf("headersSent = %d calls, want 1", len(sw.headersSent))
	}
	h := sw.headersSent[0]
	// Should contain :status + content-type
	foundCT := false
	for _, f := range h {
		if string(f.Name) == "Content-Type" && string(f.Value) == "text/html" {
			foundCT = true
		}
	}
	if !foundCT {
		t.Error("content-type header not found in sent headers")
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
	w, sw := newTestWriter()

	if err := handler.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Status() != 200 {
		t.Errorf("Status = %d, want 200", w.Status())
	}
	// Write(200) via WriteHeader should send :status, content-type
	if len(sw.headersSent) < 1 {
		t.Fatal("no headers sent")
	}
	// Write("hello from chi") should send data
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "hello from chi" {
		t.Errorf("dataSent = %v, want [hello from chi]", sw.dataSent)
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
	w, sw := newTestWriter()

	if err := handler.ServeHTTP(ctx, req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "ctx-works" {
		t.Errorf("dataSent = %v, want [ctx-works]", sw.dataSent)
	}
}

func TestToHTTPHandler_Roundtrip(t *testing.T) {
	poseidonHandler := HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
		w.Header().Set("x-custom", "yes")
		w.WriteHeader(200)
		return nil
	})

	httpHandler := ToHTTPHandler(poseidonHandler)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/test", nil)

	httpHandler.ServeHTTP(rec, httpReq)

	if rec.Code != 200 {
		t.Errorf("Status = %d, want 200", rec.Code)
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
	w, _ := newTestWriter()
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
	w, sw := newTestWriter()
	if err := handler.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/ping"}, w); err != nil {
		t.Fatalf("/ping: %v", err)
	}
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "pong" {
		t.Errorf("/ping dataSent = %v, want [pong]", sw.dataSent)
	}

	// Test /echo
	w2, sw2 := newTestWriter()
	if err := handler.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/echo?msg=hi"}, w2); err != nil {
		t.Fatalf("/echo: %v", err)
	}
	if len(sw2.dataSent) != 1 || string(sw2.dataSent[0]) != "hi" {
		t.Errorf("/echo dataSent = %v, want [hi]", sw2.dataSent)
	}
}
