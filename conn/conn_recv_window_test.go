package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

func connRecvWindowValue(sc *ServerConn) int32 {
	sc.fcMu.Lock()
	defer sc.fcMu.Unlock()
	return sc.connRecvWindow
}

// With ConnRecvWindow set above the 64 KiB protocol default, the server emits a
// single connection-level WINDOW_UPDATE right after the handshake to advertise
// the larger window, so large uploads aren't throttled into many round-trips.
func TestServerConn_ConnRecvWindow_EmitsStartupWindowUpdate(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	got := make(chan uint32, 1)
	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// The enlargement WINDOW_UPDATE is the next frame after the handshake.
			wu := &windowUpdateCapture{}
			if _, err := cliFr.ReadFrame(context.Background(), wu); err != nil {
				got <- 0
				return
			}
			got <- wu.increment
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const target = 1 << 20 // 1 MiB
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{ConnRecvWindow: target}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	if inc, want := <-got, uint32(target-connInitialRecvWindow); inc != want {
		t.Fatalf("startup connection WINDOW_UPDATE increment = %d, want %d", inc, want)
	}
	if w := connRecvWindowValue(sc); w != target {
		t.Fatalf("connRecvWindow = %d, want %d", w, target)
	}
}

// By default (ConnRecvWindow unset) the server keeps the 64 KiB protocol window
// and emits NO unsolicited WINDOW_UPDATE — asserted by the window value and,
// implicitly, by every other net.Pipe test (which would deadlock on an unread
// frame if one were sent).
func TestServerConn_ConnRecvWindow_DefaultKeeps64KiB(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	if w := connRecvWindowValue(sc); w != connInitialRecvWindow {
		t.Fatalf("default connRecvWindow = %d, want %d (no enlargement)", w, connInitialRecvWindow)
	}
}

// A ConnRecvWindow at or below the 64 KiB default is a no-op: no enlargement and
// no startup WINDOW_UPDATE (so this net.Pipe test does not deadlock on an unread
// frame).
func TestServerConn_ConnRecvWindow_BelowDefaultIsNoOp(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{ConnRecvWindow: 1024}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	if w := connRecvWindowValue(sc); w != connInitialRecvWindow {
		t.Fatalf("connRecvWindow = %d for a sub-default ConnRecvWindow, want %d", w, connInitialRecvWindow)
	}
}
