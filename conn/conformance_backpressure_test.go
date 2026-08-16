package conn

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestConformance_RFC9113_Sec521_WindowBoundsUnconsumedData pins the point of
// flow control, which the server had opted out of.
//
//	§5.2.1 — "The sender of a flow-controlled frame MUST NOT
//	send more than the receiver allows."
//
// A receiver that returns credit the moment a DATA frame ARRIVES, rather than
// when the application takes delivery of it, always allows more — so the
// advertised window bounds nothing and the real limit becomes whatever internal
// buffer happens to sit behind it. Here that was an 8-slot event channel: a
// 1 MiB upload to a handler lagging by a few milliseconds overran it and the
// stream was killed with RST_STREAM(INTERNAL_ERROR) mid-request.
//
// This is the test the CI failure on PR #60 should have had. The failure was
// only visible at all because the overflow reset changed from REFUSED_STREAM —
// which a Go client silently retries, hiding the bug — to INTERNAL_ERROR.
func TestConformance_RFC9113_Sec521_WindowBoundsUnconsumedData(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := newCreditTracker()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), seen); err != nil {
						return
					}
				}
			}()
			sendReq(t, cliFr, 1, goodHeaders("/sink"), false)
			// 1 MiB in 16 KiB frames — what the loadgen feature test uploads — sent
			// the way a conformant client does: only within the credit the server
			// has granted. That is the whole point. If the window is bounding
			// anything, this blocks and resumes; if it is not, the server's internal
			// buffer overruns and the stream dies.
			const frames, size = 64, 16384
			deadline := time.Now().Add(6 * time.Second)
			for i := range frames {
				for !seen.take(size) {
					if time.Now().After(deadline) {
						t.Errorf("upload stalled after %d/%d frames: the server stopped "+
							"granting credit for data its handler had already read", i, frames)
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
				if _, err := cli.Write(rawFrame(frame.FrameData, 0, 1, make([]byte, size))); err != nil {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	// A handler that lags behind the wire, as any real one does under load.
	go func() {
		for {
			if _, rerr := stream.Recv(ctx); rerr != nil {
				return
			}
			time.Sleep(8 * time.Millisecond)
		}
	}()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("probe did not finish")
	}
	if seen.sawRST {
		t.Errorf("RST_STREAM(%v) for an upload to a slow handler: the peer was given more "+
			"credit than the server could absorb, so its own window never throttled it",
			seen.rstCode)
	}
	if seen.sawGoAway {
		t.Errorf("GOAWAY(%v) for an ordinary upload", seen.goAwayCode)
	}
}

// creditTracker is a minimally conformant sender: it spends only the
// flow-control credit the server has actually granted, on both levels.
type creditTracker struct {
	fieldRSTCapture
	mu     sync.Mutex
	stream int64
	conn   int64
}

func newCreditTracker() *creditTracker {
	// Both windows start at the protocol default (RFC 9113 §6.9.2).
	return &creditTracker{stream: connInitialRecvWindow, conn: connInitialRecvWindow}
}

func (c *creditTracker) OnWindowUpdate(fh frame.FrameHeader, inc uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fh.StreamID == 0 {
		c.conn += int64(inc)
	} else {
		c.stream += int64(inc)
	}
	return nil
}

// take reserves n octets of credit, reporting false when the server has not
// granted enough yet.
func (c *creditTracker) take(n int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream < n || c.conn < n {
		return false
	}
	c.stream -= n
	c.conn -= n
	return true
}
