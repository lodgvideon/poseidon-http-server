package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestHandshakeTimeout_SlowPreface verifies that a client which connects but
// sends the HTTP/2 preface too slowly is dropped after HandshakeTimeout
// (Slowloris defense at the connection-establishment stage).
func TestHandshakeTimeout_SlowPreface(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	opts := ServerConnOptions{HandshakeTimeout: 150 * time.Millisecond}

	errCh := make(chan error, 1)
	go func() {
		_, err := NewServerConn(context.Background(), srv, opts)
		errCh <- err
	}()

	// Send only a partial preface, then stall — never finishing the handshake.
	go func() {
		_, _ = cli.Write([]byte("PRI * HTTP/2.0\r\n")) // partial
		// Then do nothing; the server should time out.
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected NewServerConn to fail on slow preface")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not time out; slow client was not dropped")
	}
}

// TestHandshakeTimeout_DefaultApplied verifies a sensible default is applied
// when HandshakeTimeout is zero (secure-by-default), and that the mitigation
// is disabled when negative.
func TestHandshakeTimeout_Resolved(t *testing.T) {
	t.Parallel()
	if got := (ServerConnOptions{}.defaulted()).HandshakeTimeout; got != defaultHandshakeTimeout {
		t.Errorf("default HandshakeTimeout = %v, want %v", got, defaultHandshakeTimeout)
	}
	// Negative means disabled — left as-is so handshakeDeadline can detect it.
	if got := (ServerConnOptions{HandshakeTimeout: -1}.defaulted()).HandshakeTimeout; got != -1 {
		t.Errorf("negative HandshakeTimeout = %v, want -1 (disabled)", got)
	}
	if got := (ServerConnOptions{HandshakeTimeout: 5 * time.Second}.defaulted()).HandshakeTimeout; got != 5*time.Second {
		t.Errorf("explicit HandshakeTimeout = %v, want 5s", got)
	}
}

// TestHandshakeTimeout_NormalClientUnaffected verifies a well-behaved client
// completing the handshake promptly is NOT dropped.
func TestHandshakeTimeout_NormalClientUnaffected(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	opts := ServerConnOptions{HandshakeTimeout: 500 * time.Millisecond}.defaulted()

	go pipeClient(t, cli, func(_ *frame.Framer) {
		time.Sleep(100 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, opts)
	if err != nil {
		t.Fatalf("NewServerConn for prompt client: %v", err)
	}
	_ = sc.Close()
}
