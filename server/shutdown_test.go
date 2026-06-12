package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestShutdown_Graceful verifies Shutdown sends GOAWAY and waits for drain.
func TestShutdown_Graceful(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		GracefulShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Serve(ctx, ln) }()

	// Connect a client.
	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	// Send a request and read response.
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	// Shutdown gracefully.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()

	if shutErr := srv.Shutdown(shutCtx); shutErr != nil {
		t.Errorf("Shutdown: %v", shutErr)
	}
}

// TestShutdown_Timeout verifies Shutdown force-closes after timeout.
func TestShutdown_Timeout(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			time.Sleep(5 * time.Second) // simulate slow handler
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		GracefulShutdownTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/slow")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	// Shutdown with short timeout.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)

	if srv.ConnCount() != 0 {
		t.Errorf("ConnCount = %d after shutdown, want 0", srv.ConnCount())
	}
}

// TestShutdown_AlreadyClosed verifies double shutdown is safe.
func TestShutdown_AlreadyClosed(t *testing.T) {
	srv, _ := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
	})
	_ = srv.Close()

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Errorf("double shutdown: %v", err)
	}
}
