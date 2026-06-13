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
