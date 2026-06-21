package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestIdleTimeout verifies that idle connections are closed after IdleTimeout.
func TestIdleTimeout(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
		IdleTimeout: 200 * time.Millisecond,
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
	defer srv.Close()

	// Dial and handshake.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cliFr := frame.NewFramer(conn, conn)
	if err := performClientHandshake(conn, cliFr); err != nil {
		t.Fatal(err)
	}

	// Don't send any streams — just wait for idle timeout.
	// The server should close the connection.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after idle timeout")
	}
}
