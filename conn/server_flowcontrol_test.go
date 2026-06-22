package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestServerConn_FlowControl_ConnWindowOverflow_EmitsGoAway verifies that a
// WINDOW_UPDATE overflowing the connection-level send window past 2^31-1 makes
// the server emit GOAWAY(FLOW_CONTROL_ERROR) before tearing the connection
// down, rather than dropping the socket silently with no RFC error code
// (RFC 9113 §6.9.1). Regression guard for the connError-vs-fmt.Errorf fix.
func TestServerConn_FlowControl_ConnWindowOverflow_EmitsGoAway(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	gotGoAway := make(chan goAwayCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			gc := &goAwayCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), gc); err != nil {
						return
					}
					if gc.code != 0 {
						select {
						case gotGoAway <- *gc:
						default:
						}
						return
					}
				}
			}()

			// Open a stream, then send a WINDOW_UPDATE that overflows the
			// connection send window (initial 65535 + 2^31-1 > 2^31-1).
			sendReq(t, cliFr, 1, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/")},
			}, true)
			go func() { _ = cliFr.WriteWindowUpdate(0, 0x7FFFFFFF) }()

			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case gc := <-gotGoAway:
		if gc.code != frame.ErrCodeFlowControlError {
			t.Fatalf("GOAWAY code = %v, want FLOW_CONTROL_ERROR (0x3)", gc.code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server did not emit GOAWAY(FLOW_CONTROL_ERROR) on connection-window overflow")
	}
	<-done
}

// TestServerConn_FlowControl_StreamWindowOverflow_RSTsStream verifies RFC 9113
// §6.9.1: a WINDOW_UPDATE overflowing a STREAM (not connection) send window is a
// stream error — RST_STREAM(FLOW_CONTROL_ERROR) on that stream — and must NOT
// tear down the whole connection. (Regression guard for the review fix that
// stopped GOAWAYing the connection for a single stream's overflow.)
func TestServerConn_FlowControl_StreamWindowOverflow_RSTsStream(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	gotRST := make(chan frame.ErrCode, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			rc := &rstCapture{}
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), rc); err != nil {
						return
					}
					if rc.code != 0 {
						select {
						case gotRST <- rc.code:
						default:
						}
						return
					}
				}
			}()

			// Open stream 1 (kept open), then overflow ITS send window only.
			sendReq(t, cliFr, 1, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/")},
			}, false)
			go func() { _ = cliFr.WriteWindowUpdate(1, 0x7FFFFFFF) }()

			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case code := <-gotRST:
		// rstCapture only records RST_STREAM (OnGoAway is a no-op), so reaching
		// here proves the server chose a stream reset over a connection GOAWAY.
		if code != frame.ErrCodeFlowControlError {
			t.Fatalf("RST code = %v, want FLOW_CONTROL_ERROR (0x3)", code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server did not RST_STREAM(FLOW_CONTROL_ERROR) on stream-window overflow")
	}
	<-done
}
