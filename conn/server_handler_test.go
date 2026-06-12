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

// TestServerConn_OnPriority verifies that PRIORITY frames are silently ignored.
func TestServerConn_OnPriority(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Send PRIORITY frame — server should silently ignore.
			if err := cliFr.WritePriority(1, frame.Priority{
				Exclusive: false,
				StreamDep: 0,
				Weight:    16,
			}); err != nil {
				t.Logf("WritePriority: %v", err)
				return
			}
			// Then open a real stream to verify connection is still alive.
			sendReq(t, cliFr, 3, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/priority-test")},
			}, true)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream after PRIORITY: %v", err)
	}
	stream.Close()
	<-done
}

// TestServerConn_OnPushPromise_HandlerLevel verifies that PUSH_PROMISE from
// a client returns a connection-level protocol error (RFC 7540 §8.2).
func TestServerConn_OnPushPromise_HandlerLevel(t *testing.T) {
	mock := &mockConnOps{
		streams: make(map[uint32]*ServerStream),
	}
	h := newServerConnHandler(mock, hpack.NewDecoder())

	err := h.OnPushPromise(frame.FrameHeader{StreamID: 1}, 3, nil, 0)
	if err == nil {
		t.Fatal("OnPushPromise should return connection error")
	}
	var ce connError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want connError", err)
	}
	if ce.code != frame.ErrCodeProtocolError {
		t.Fatalf("error code = %v, want ErrCodeProtocolError", ce.code)
	}
}

// TestServerConn_OnGoAway_FromClient verifies server handles GOAWAY from client.
func TestServerConn_OnGoAway_FromClient(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Client sends GOAWAY(NO_ERROR, last-stream-id=0).
			if err := cliFr.WriteGoAway(0, frame.ErrCodeNoError, nil); err != nil {
				t.Logf("WriteGoAway: %v", err)
				return
			}
			// Keep pipe open briefly for server to process.
			time.Sleep(200 * time.Millisecond)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}

	// After GOAWAY, AcceptStream should fail.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	_, err = sc.AcceptStream(ctx2)
	if err == nil {
		t.Fatal("AcceptStream should fail after client GOAWAY")
	}
	<-done
}

// --- mock for direct handler tests ---

type mockConnOps struct {
	streams           map[uint32]*ServerStream
	settingsAckCalled bool
	pingAckCalled     bool
}

func (m *mockConnOps) lookupStream(id uint32) *ServerStream                { return m.streams[id] }
func (m *mockConnOps) registerStream(id uint32, s *ServerStream)           { m.streams[id] = s }
func (m *mockConnOps) markStreamDone(id uint32)                            { delete(m.streams, id) }
func (m *mockConnOps) writeSettingsAck() error                             { m.settingsAckCalled = true; return nil }
func (m *mockConnOps) writePingAck(_ [8]byte) error                      { m.pingAckCalled = true; return nil }
func (m *mockConnOps) deliverPingAck(_ [8]byte)                          {}
func (m *mockConnOps) applyPeerSettings(_ frame.SettingsParams) error    { return nil }
func (m *mockConnOps) onWindowUpdate(_, _ uint32) error                   { return nil }
func (m *mockConnOps) onDataReceived(_ *ServerStream, _ uint32) error    { return nil }
