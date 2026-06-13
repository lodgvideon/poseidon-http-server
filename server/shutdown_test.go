package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Graceful shutdown tests
// ---------------------------------------------------------------------------

func TestShutdown_NoActiveStreams(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// Give server time to start.
	time.Sleep(50 * time.Millisecond)

	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestShutdown_WaitsForStreams(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})

	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			close(started)
			<-block // block until test unblocks
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// Open a stream via raw HTTP/2 client.
	conn, cliFr, err := dialAndHandshake(t, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	openStream(t, cliFr)

	// Wait for handler to start.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}

	// Shutdown should block while stream is active.
	done := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		done <- srv.Shutdown(sctx)
	}()

	// Give Shutdown time to reach the WaitGroup.
	time.Sleep(100 * time.Millisecond)

	// Unblock the handler.
	close(block)

	// Shutdown should now complete.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown timed out waiting for streams")
	}
}

func TestShutdown_ContextCancelled(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})

	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			close(started)
			<-block
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	conn, cliFr, err := dialAndHandshake(t, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	openStream(t, cliFr)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}

	// Shutdown with very short timeout — should return context error.
	sctx, scancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer scancel()
	err = srv.Shutdown(sctx)
	if err == nil {
		t.Fatal("expected error from Shutdown with expired context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got: %v", err)
	}

	// Unblock handler.
	close(block)
}

func TestShutdown_DoubleShutdown(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	time.Sleep(50 * time.Millisecond)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := srv.Shutdown(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("second Shutdown: want ErrServerClosed, got: %v", err)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func dialAndHandshake(t *testing.T, addr string) (net.Conn, *frame.Framer, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	cliFr := frame.NewFramer(c, c)
	if err := performClientHandshake(c, cliFr); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, cliFr, nil
}

func openStream(t *testing.T, cliFr *frame.Framer) {
	t.Helper()
	enc := hpack.NewEncoder()
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	block := enc.EncodeBlock(nil, headers)
	if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     true, // complete request — handler will be called
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
}
