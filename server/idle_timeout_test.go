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

	// Don't send any streams — just wait for the idle timeout. The server must
	// announce the shutdown with GOAWAY and then close the socket.
	//
	// Reading once is not enough, and used to hide the bug this test exists for:
	// before the server closed anything, the single Read simply sat until its own
	// 3s deadline and the resulting i/o timeout was indistinguishable from a
	// close. Draining until the read fails is the only assertion that can tell
	// "the peer went away" from "we gave up waiting".
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sawGoAway := false
	deadline := time.Now().Add(3 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("connection still open 3s after the 200ms idle timeout")
		}
		fh, rerr := cliFr.ReadFrame(context.Background(), &idleFrameSink{saw: &sawGoAway})
		if rerr != nil {
			break // the server closed the transport, which is the point
		}
		_ = fh
	}
	if !sawGoAway {
		t.Error("no GOAWAY before the close; RFC 9113 §6.8 asks a server ending a " +
			"connection to say so, and Options.IdleTimeout documents a clean shutdown")
	}
}

// idleFrameSink records whether a GOAWAY arrived and ignores everything else.
type idleFrameSink struct{ saw *bool }

func (s *idleFrameSink) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	*s.saw = true
	return nil
}
func (s *idleFrameSink) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (s *idleFrameSink) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (s *idleFrameSink) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (s *idleFrameSink) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (s *idleFrameSink) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (s *idleFrameSink) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (s *idleFrameSink) OnPing(frame.FrameHeader, [8]byte) error                   { return nil }
func (s *idleFrameSink) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (s *idleFrameSink) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (s *idleFrameSink) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (s *idleFrameSink) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }
