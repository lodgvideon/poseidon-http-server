package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// TestSlowloris_IncompletePrefaceDropped verifies a client that connects and
// sends an incomplete/slow preface is disconnected after the handshake timeout.
func TestSlowloris_IncompletePrefaceDropped(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
		ConnOpts: connHandshakeTimeoutOpts(150 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Send only part of the preface, then stall.
	_, _ = c.Write([]byte("PRI * HTTP/2.0\r\n"))

	// The server should close our connection once the handshake times out.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if _, rerr := c.Read(buf); rerr == nil {
		t.Fatal("expected connection to be closed after handshake timeout")
	}
}

// TestSlowloris_KeepaliveIdleThenActive verifies that a normal client running
// multiple sequential streams with idle gaps between them is NOT disconnected
// (the handshake timeout must not behave like a blanket connection read
// deadline, which would break HTTP/2 keep-alive).
func TestSlowloris_KeepaliveIdleThenActive(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
		// Generous idle timeout, small handshake timeout. Idle gaps below
		// must survive even though they exceed the handshake timeout.
		IdleTimeout: 2 * time.Second,
		ConnOpts:    connHandshakeTimeoutOpts(100 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	enc := hpack.NewEncoder()
	// Three sequential streams with idle gaps that exceed the handshake
	// timeout. A correct implementation keeps the connection alive.
	for i, sid := range []uint32{1, 3, 5} {
		if i > 0 {
			time.Sleep(250 * time.Millisecond) // idle gap > handshake timeout
		}
		block := enc.EncodeBlock(nil, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":path"), Value: []byte("/ka")},
			{Name: []byte(":scheme"), Value: []byte("http")},
			{Name: []byte(":authority"), Value: []byte("localhost")},
		})
		if werr := fr.WriteHeaders(frame.WriteHeadersParams{
			StreamID: sid, BlockFragment: block, EndHeaders: true, EndStream: true,
		}); werr != nil {
			t.Fatalf("stream %d WriteHeaders: %v", sid, werr)
		}
		// The server emits a HEADERS (with :status) followed by an empty
		// trailers HEADERS; read frames until we observe the :status.
		var status string
		for status == "" {
			respHeaders, herr := readResponseHeaders(fr)
			if herr != nil {
				t.Fatalf("stream %d read response: %v", sid, herr)
			}
			status = statusValue(respHeaders)
		}
		if status != "200" {
			t.Fatalf("stream %d status = %q, want 200 (keep-alive broken)", sid, status)
		}
	}
}

// TestIdleTimeout_DefaultApplied verifies NewServer applies a secure default
// IdleTimeout when none is set, and that a negative value disables it.
func TestIdleTimeout_DefaultApplied(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv.opts.IdleTimeout != defaultIdleTimeout {
		t.Errorf("default IdleTimeout = %v, want %v", srv.opts.IdleTimeout, defaultIdleTimeout)
	}

	srv2, err := NewServer(Options{
		Handler:     HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error { return w.WriteHeaders(200, nil) }),
		IdleTimeout: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv2.idleTimeout() != 0 {
		t.Errorf("negative IdleTimeout should disable (idleTimeout()=0), got %v", srv2.idleTimeout())
	}
}

// connHandshakeTimeoutOpts is a tiny helper to build ServerConnOptions with a
// handshake timeout for tests.
func connHandshakeTimeoutOpts(d time.Duration) conn.ServerConnOptions {
	return conn.ServerConnOptions{HandshakeTimeout: d}
}
