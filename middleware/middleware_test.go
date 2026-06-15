package middleware

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Thread-safe test logger
// ---------------------------------------------------------------------------

type testLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (tl *testLogger) Printf(format string, args ...interface{}) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	fmt.Fprintf(&tl.buf, format+"\n", args...)
}

func (tl *testLogger) String() string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.buf.String()
}

// ---------------------------------------------------------------------------
// Server helpers
// ---------------------------------------------------------------------------

func startTestServer(t *testing.T, handler server.Handler) net.Listener {
	t.Helper()
	srv, err := server.NewServer(server.Options{Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		srv.Close()
		ln.Close()
	})
	time.Sleep(50 * time.Millisecond)
	return ln
}

func sendRequest(t *testing.T, addr string, extra ...hpack.HeaderField) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fr := frame.NewFramer(c, c)
	c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr.WriteSettings(frame.SettingsParams{N: 0})
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(buf)
	fr.WriteSettingsAck()

	enc := hpack.NewEncoder()
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/test")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	headers = append(headers, extra...)
	block := enc.EncodeBlock(nil, headers)
	fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	// Drain response.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(buf)
}

// ---------------------------------------------------------------------------
// Recovery tests
// ---------------------------------------------------------------------------

func TestRecovery_Panic(t *testing.T) {
	tl := &testLogger{}
	panicked := make(chan struct{})

	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		close(panicked)
		panic("boom")
	})

	mw := Recovery(tl)
	ln := startTestServer(t, mw(handler))

	sendRequest(t, ln.Addr().String())

	select {
	case <-panicked:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never panicked")
	}

	// Give recovery defer time to log.
	time.Sleep(50 * time.Millisecond)

	if !strings.Contains(tl.String(), "panic recovered") {
		t.Fatalf("log should contain 'panic recovered': %s", tl.String())
	}
}

func TestRecovery_NoPanic(t *testing.T) {
	done := make(chan struct{})
	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w *server.ResponseWriter) error {
		defer close(done)
		return w.WriteHeaders(200, nil)
	})

	mw := Recovery(nil)
	ln := startTestServer(t, mw(handler))

	sendRequest(t, ln.Addr().String())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler was not called")
	}
}

// ---------------------------------------------------------------------------
// RequestID tests
// ---------------------------------------------------------------------------

func TestRequestID_GeneratesID(t *testing.T) {
	result := make(chan string, 1)
	handler := server.HandlerFunc(func(ctx context.Context, _ *server.Request, w *server.ResponseWriter) error {
		result <- FromContext(ctx)
		return w.WriteHeaders(200, nil)
	})

	mw := RequestID()
	ln := startTestServer(t, mw(handler))

	sendRequest(t, ln.Addr().String())

	select {
	case id := <-result:
		if id == "" {
			t.Fatal("expected non-empty request ID")
		}
		if len(id) != 32 {
			t.Fatalf("request ID length = %d, want 32", len(id))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestRequestID_UsesClientID(t *testing.T) {
	result := make(chan string, 1)
	handler := server.HandlerFunc(func(ctx context.Context, _ *server.Request, w *server.ResponseWriter) error {
		result <- FromContext(ctx)
		return w.WriteHeaders(200, nil)
	})

	mw := RequestID()
	ln := startTestServer(t, mw(handler))

	sendRequest(t, ln.Addr().String(), hpack.HeaderField{
		Name: []byte("x-request-id"), Value: []byte("client-123"),
	})

	select {
	case id := <-result:
		if id != "client-123" {
			t.Fatalf("expected client-123, got %s", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

// ---------------------------------------------------------------------------
// AccessLog tests
// ---------------------------------------------------------------------------

func TestAccessLog_LogsRequest(t *testing.T) {
	tl := &testLogger{}
	done := make(chan struct{})

	handler := server.HandlerFunc(func(_ context.Context, _ *server.Request, w *server.ResponseWriter) error {
		defer close(done)
		return w.WriteHeaders(200, nil)
	})

	chain := server.Chain(RequestID(), AccessLog(tl))
	ln := startTestServer(t, chain(handler))

	sendRequest(t, ln.Addr().String())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timed out")
	}

	// AccessLog runs after handler — give it time.
	time.Sleep(100 * time.Millisecond)

	output := tl.String()
	if !strings.Contains(output, "GET") {
		t.Fatalf("log should contain 'GET': %s", output)
	}
	if !strings.Contains(output, "/test") {
		t.Fatalf("log should contain '/test': %s", output)
	}
	if !strings.Contains(output, "id=") {
		t.Fatalf("log should contain request ID: %s", output)
	}
}

// ---------------------------------------------------------------------------
// CORS tests
// ---------------------------------------------------------------------------

func TestDefaultCORSConfig(t *testing.T) {
	cfg := DefaultCORSConfig()
	if len(cfg.AllowOrigins) != 1 || cfg.AllowOrigins[0] != "*" {
		t.Errorf("AllowOrigins = %v, want [*]", cfg.AllowOrigins)
	}
	if cfg.MaxAge != 86400 {
		t.Errorf("MaxAge = %d, want 86400", cfg.MaxAge)
	}
}

func TestCORS_Preflight_ReturnsCORSHeaders(t *testing.T) {
	nextCalled := make(chan struct{}, 1)
	next := server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		select {
		case nextCalled <- struct{}{}:
		default:
		}
		return nil
	})

	mw := CORS(DefaultCORSConfig())
	h := mw(next)

	ln := startTestServer(t, h)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fr := frame.NewFramer(c, c)
	c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr.WriteSettings(frame.SettingsParams{N: 0})

	// Read server SETTINGS + ACK with timeout
	noop := &noopFrameHandler{}
	rctx, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	fr.ReadFrame(rctx, noop) // server SETTINGS
	fr.ReadFrame(rctx, noop) // server ACK
	cancel1()

	// Send SETTINGS ACK + OPTIONS request
	fr.WriteSettingsAck()
	enc := hpack.NewEncoder()
	hdrs := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("OPTIONS")},
		{Name: []byte(":path"), Value: []byte("/api")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	block := enc.EncodeBlock(nil, hdrs)
	fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	// Read response HEADERS
	hCollector := &headerCollector{}
	rctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	for range 6 {
		_, err := fr.ReadFrame(rctx2, hCollector)
		if err != nil || hCollector.gotHeaders {
			break
		}
	}

	select {
	case <-nextCalled:
		t.Error("next handler should not be called for OPTIONS preflight")
	default:
	}
	if !hCollector.gotHeaders {
		t.Fatal("did not receive response HEADERS frame")
	}
	if hCollector.status != 204 {
		t.Errorf("status = %d, want 204", hCollector.status)
	}
	found := false
	for _, h := range hCollector.fields {
		if string(h.Name) == "access-control-allow-origin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("access-control-allow-origin not in response headers: %v", hCollector.fields)
	}
}

type noopFrameHandler struct{}

func (h *noopFrameHandler) OnData(frame.FrameHeader, []byte, uint8) error                               { return nil }
func (h *noopFrameHandler) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error { return nil }
func (h *noopFrameHandler) OnPriority(frame.FrameHeader, frame.Priority) error                           { return nil }
func (h *noopFrameHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error                           { return nil }
func (h *noopFrameHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error                     { return nil }
func (h *noopFrameHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error      { return nil }
func (h *noopFrameHandler) OnPing(frame.FrameHeader, [8]byte) error                                      { return nil }
func (h *noopFrameHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error              { return nil }
func (h *noopFrameHandler) OnWindowUpdate(frame.FrameHeader, uint32) error                               { return nil }
func (h *noopFrameHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error                    { return nil }

func (h *noopFrameHandler) OnOrigin(frame.FrameHeader, []string) error { return nil }
func (h *noopFrameHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

// headerCollector decodes HEADERS frames and stores the result.
type headerCollector struct {
	fields     []hpack.HeaderField
	status     int
	gotHeaders bool
}

func (c *headerCollector) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (c *headerCollector) OnHeaders(_ frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	c.gotHeaders = true
	dec := hpack.NewDecoder()
	dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		c.fields = append(c.fields, f)
		if string(f.Name) == ":status" {
			fmt.Sscanf(string(f.Value), "%d", &c.status)
		}
		return nil
	})
	return nil
}
func (c *headerCollector) OnPriority(frame.FrameHeader, frame.Priority) error                      { return nil }
func (c *headerCollector) OnRSTStream(frame.FrameHeader, frame.ErrCode) error                       { return nil }
func (c *headerCollector) OnSettings(frame.FrameHeader, frame.SettingsParams) error                 { return nil }
func (c *headerCollector) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error  { return nil }
func (c *headerCollector) OnPing(frame.FrameHeader, [8]byte) error                                   { return nil }
func (c *headerCollector) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error          { return nil }
func (c *headerCollector) OnWindowUpdate(frame.FrameHeader, uint32) error                            { return nil }
func (c *headerCollector) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error                { return nil }

func (c *headerCollector) OnOrigin(frame.FrameHeader, []string) error { return nil }
func (c *headerCollector) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

func TestCORS_NonPreflight_PassesThrough(t *testing.T) {
	done := make(chan struct{}, 1)
	next := server.HandlerFunc(func(_ context.Context, _ *server.Request, w *server.ResponseWriter) error {
		select {
		case done <- struct{}{}:
		default:
		}
		return w.WriteHeaders(200, nil)
	})

	mw := CORS(DefaultCORSConfig())
	h := mw(next)

	ln := startTestServer(t, h)
	sendRequest(t, ln.Addr().String())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("next handler should be called for non-preflight request")
	}
}

func TestCORS_CustomOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET"},
		AllowHeaders: []string{"X-Custom"},
		MaxAge:       3600,
	}
	// Verify corsHeaders uses the custom origin directly.
	hdrs := corsHeaders(cfg, "https://example.com")
	found := false
	for _, h := range hdrs {
		if string(h.Name) == "access-control-allow-origin" && string(h.Value) == "https://example.com" {
			found = true
		}
	}
	if !found {
		t.Error("corsHeaders should include custom origin")
	}
}

func TestCorsHeaders_Defaults(t *testing.T) {
	// Empty config → default methods and headers.
	hdrs := corsHeaders(CORSConfig{}, "*")
	merged := ""
	for _, h := range hdrs {
		merged += string(h.Name) + ":" + string(h.Value) + " "
	}
	if !strings.Contains(merged, "GET, POST, PUT, DELETE, OPTIONS") {
		t.Errorf("default methods not found in: %s", merged)
	}
	if !strings.Contains(merged, "Content-Type, Authorization") {
		t.Errorf("default headers not found in: %s", merged)
	}
}
