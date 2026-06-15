package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// pipeClient drives the client side of a net.Pipe for server tests.
// It sends the HTTP/2 client preface magic, SETTINGS, and reads
// server SETTINGS + ACKs.
func pipeClient(t *testing.T, cli net.Conn, after func(cliFr *frame.Framer)) {
	t.Helper()
	defer cli.Close()

	// 1. Write client preface magic.
	if _, err := cli.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Logf("client preface write: %v", err)
		return
	}
	cliFr := frame.NewFramer(cli, cli)

	// 2. Write client SETTINGS (empty — use defaults).
	writeDone := make(chan error, 1)
	go func() { writeDone <- cliFr.WriteSettings(frame.SettingsParams{}) }()

	// 3. Read server SETTINGS.
	if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
		t.Logf("client read server settings: %v", err)
		return
	}
	if err := <-writeDone; err != nil {
		t.Logf("client write settings: %v", err)
		return
	}

	// 4. Send SETTINGS ACK for server's SETTINGS.
	go func() { writeDone <- cliFr.WriteSettingsAck() }()

	// 5. Read server's SETTINGS ACK.
	if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
		t.Logf("client read server ack: %v", err)
		return
	}
	if err := <-writeDone; err != nil {
		t.Logf("client write ack: %v", err)
		return
	}

	if after != nil {
		after(cliFr)
	}
}

// TestServerConn_Handshake verifies the server-side HTTP/2 handshake:
// read client preface → send SETTINGS → receive client SETTINGS → send ACK →
// receive client ACK.
func TestServerConn_Handshake(t *testing.T) {
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	_ = sc.Close()
	<-done
}

// TestServerConn_Handshake_BadPreface verifies that an invalid client
// preface causes NewServerConn to return an error.
func TestServerConn_Handshake_BadPreface(t *testing.T) {
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Send garbage instead of preface magic.
		_, _ = cli.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		_ = cli.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err == nil {
		t.Fatal("expected error for bad preface, got nil")
	}
	<-done
}

// TestServerConn_Close_IsIdempotent verifies that closing a ServerConn
// multiple times does not error.
func TestServerConn_Close_IsIdempotent(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}
}

// TestServerConn_AcceptStream_ReturnsErrAfterClose verifies that
// AcceptStream returns ErrConnClosed after the connection is closed.
func TestServerConn_AcceptStream_ReturnsErrAfterClose(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	_ = sc.Close()

	_, err = sc.AcceptStream(ctx)
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("AcceptStream after Close: err = %v, want ErrConnClosed", err)
	}
}

// TestServerConn_Stats verifies that Stats returns non-zero sent counters
// after handshake (SETTINGS + ACK are sent synchronously).
// Received counters are only updated in the reader loop, which may not
// have processed handshake frames yet, so we only assert on sent.
func TestServerConn_Stats(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stats := sc.Stats()
	if stats.FramesSent == 0 {
		t.Fatal("Stats.FramesSent = 0, expected at least SETTINGS frame")
	}
}

// TestServerConn_AcceptStream_ReceivesClientHeaders verifies that
// AcceptStream returns a ServerStream with initial headers when the
// client sends a HEADERS frame.
func TestServerConn_AcceptStream_ReceivesClientHeaders(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Client sends HEADERS on stream 1.
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":authority"), Value: []byte("example.com")},
			{Name: []byte(":path"), Value: []byte("/")},
		})
		writeDone := make(chan error, 1)
		go func() {
			writeDone <- cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block,
				EndHeaders:    true,
				EndStream:     true,
			})
		}()
		<-writeDone

		// Keep client alive so server can process.
		time.Sleep(500 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if stream.ID() != 1 {
		t.Fatalf("stream.ID() = %d, want 1", stream.ID())
	}

	// First event should be headers.
	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("event type = %v, want EventHeaders", ev.Type)
	}
	if !ev.EndStream {
		t.Fatal("EndStream = false, want true")
	}

	// Verify we got the :method header.
	found := false
	for _, h := range ev.Headers {
		if string(h.Name) == ":method" && string(h.Value) == "GET" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("headers did not contain :method GET")
	}
}

// --- helpers ---

// nilHandler discards all frames.
type nilHandler struct{}

func (nilHandler) OnData(frame.FrameHeader, []byte, uint8) error       { return nil }
func (nilHandler) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (nilHandler) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (nilHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (nilHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (nilHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (nilHandler) OnPing(frame.FrameHeader, [8]byte) error                         { return nil }
func (nilHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (nilHandler) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (nilHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (nilHandler) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (nilHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

