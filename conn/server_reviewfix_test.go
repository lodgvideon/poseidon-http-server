package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestServerConn_Handshake_BadInitialSettings_Rejected verifies that the
// client's INITIAL SETTINGS are validated during the handshake, not just on
// later SETTINGS frames. A first SETTINGS with INITIAL_WINDOW_SIZE > 2^31-1
// would otherwise be applied and make every stream's send window negative.
func TestServerConn_Handshake_BadInitialSettings_Rejected(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	go func() {
		defer cli.Close()
		if _, err := cli.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
			return
		}
		cliFr := frame.NewFramer(cli, cli)
		writeDone := make(chan error, 1)
		// Client SETTINGS with an illegal INITIAL_WINDOW_SIZE.
		go func() { writeDone <- cliFr.WriteSettings(oneSetting(frame.SettingInitialWindowSize, 0x80000000)) }()
		if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
			return
		}
		<-writeDone
		go func() { writeDone <- cliFr.WriteSettingsAck() }()
		if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
			return
		}
		<-writeDone
		// Drain whatever the server sends after rejecting (GOAWAY, then close).
		for {
			if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err == nil {
		t.Fatal("NewServerConn accepted a handshake with INITIAL_WINDOW_SIZE > 2^31-1")
	}
	var ce connError
	if !errors.As(err, &ce) || ce.code != frame.ErrCodeFlowControlError {
		t.Fatalf("NewServerConn error = %v, want connError FLOW_CONTROL_ERROR", err)
	}
}

// TestServerStream_Recv_PrefersBufferedEventOverCancel verifies that Recv
// returns a buffered event even when the context is already cancelled — so a
// final DATA/EOF delivered in the same step that cancels the stream context
// (markStreamDone) is not lost as context.Canceled.
func TestServerStream_Recv_PrefersBufferedEventOverCancel(t *testing.T) {
	ss := newServerStream(1, 8, nil, 65535)
	ctx, cancel := context.WithCancel(context.Background())
	ss.ctx, ss.cancel = ctx, cancel

	ss.push(StreamEvent{Type: EventData, Data: []byte("final"), EndStream: true})
	cancel() // cancel BEFORE Recv — the buffered event must still win

	ev, err := ss.Recv(ss.Context())
	if err != nil {
		t.Fatalf("Recv returned %v, want the buffered final event", err)
	}
	if ev.Type != EventData || string(ev.Data) != "final" || !ev.EndStream {
		t.Fatalf("Recv returned %+v, want buffered EventData(\"final\", END_STREAM)", ev)
	}
}
