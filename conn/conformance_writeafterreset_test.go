package conn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// frameOrderLog records the type of every frame the server sends, in order, so
// a test can assert not just what went out but what went out AFTER what.
type frameOrderLog struct {
	nilHandler
	mu    sync.Mutex
	types []frame.FrameType
}

func (l *frameOrderLog) note(t frame.FrameType) {
	l.mu.Lock()
	l.types = append(l.types, t)
	l.mu.Unlock()
}

func (l *frameOrderLog) seen() []frame.FrameType {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]frame.FrameType(nil), l.types...)
}

func (l *frameOrderLog) OnData(frame.FrameHeader, []byte, uint8) error {
	l.note(frame.FrameData)
	return nil
}

func (l *frameOrderLog) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	l.note(frame.FrameHeaders)
	return nil
}

func (l *frameOrderLog) OnRSTStream(frame.FrameHeader, frame.ErrCode) error {
	l.note(frame.FrameRSTStream)
	return nil
}

// TestConformance_RFC9113_Sec51_NothingFollowsTheResetOnTheWire pins
// rfc9113.txt:1082 — "An endpoint MUST NOT send frames other than PRIORITY on a
// closed stream" — against the window between deciding to write and writing.
//
// SendHeaders and SendData check the stream's state on entry, but the write
// itself happens later: a DATA write waits in acquireSendCredits for as long as
// the peer withholds window, and a HEADERS write encodes first. A reset landing
// in that window produced this interleaving —
//
//	reset path: record the reset · take wmu · write RST_STREAM · release wmu
//	writer:     (already past its entry check)   ·   take wmu · write DATA
//
// — and the client saw DATA arrive after RST_STREAM, on a stream it had been
// told was closed.
//
// The test drives the two write helpers directly, which is exactly the state a
// writer that is past its entry check is in; entering through SendData instead
// would let the entry check answer and prove nothing about the write.
func TestConformance_RFC9113_Sec51_NothingFollowsTheResetOnTheWire(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := &frameOrderLog{}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			for {
				if _, err := cliFr.ReadFrame(context.Background(), seen); err != nil {
					return
				}
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

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// The reset reaches the wire first. Everything after this point is a writer
	// that made its decision before the reset existed.
	if rerr := sc.writeServerRSTStream(stream, frame.ErrCodeCancel); rerr != nil {
		t.Fatalf("writeServerRSTStream: %v", rerr)
	}

	if derr := sc.writeServerData(context.Background(), stream, []byte("late body"), false); !errors.Is(derr, ErrStreamClosed) {
		t.Errorf("writeServerData after the reset = %v, want ErrStreamClosed", derr)
	}
	if derr := sc.writeServerData(context.Background(), stream, nil, true); !errors.Is(derr, ErrStreamClosed) {
		t.Errorf("empty END_STREAM DATA after the reset = %v, want ErrStreamClosed", derr)
	}
	if herr := sc.writeServerHeaders(context.Background(), stream, []hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}}, false, nil); !errors.Is(herr, ErrStreamClosed) {
		t.Errorf("writeServerHeaders after the reset = %v, want ErrStreamClosed", herr)
	}

	_ = sc.Close()
	<-clientDone

	// The wire is the real assertion: whatever the helpers returned, nothing may
	// have followed the RST_STREAM on this stream.
	types := seen.seen()
	rst := -1
	for i, ft := range types {
		if ft == frame.FrameRSTStream {
			rst = i
			break
		}
	}
	if rst < 0 {
		t.Fatalf("no RST_STREAM observed; frames were %v", types)
	}
	for _, ft := range types[rst+1:] {
		if ft == frame.FrameData || ft == frame.FrameHeaders {
			t.Fatalf("%v reached the wire after RST_STREAM (frames: %v); §5.1 (rfc9113.txt:1082) "+
				"forbids sending anything but PRIORITY on a closed stream", ft, types)
		}
	}
}

// TestRegression_RefusedWriteReturnsItsFlowControlCredit pins the cost of the
// gate above.
//
// writeServerDataChunks debits both flow-control windows in acquireSendCredits
// and only then takes the write lock, so a refusal there throws away credit for
// octets that never left. RFC 9113 §6.9.1 replenishes a window only through the
// peer's WINDOW_UPDATE, and the peer sends those for octets it has RECEIVED, so
// the loss is permanent — and the connection-level window belongs to every
// stream, not just the reset one.
//
// Left unrefunded, a handful of mid-body cancellations on one connection drain
// it to zero and every later response stalls in acquireSendCredits until its own
// context expires, with no error reported anywhere. A client can do it on
// purpose: request a large body, reset the stream, repeat.
func TestRegression_RefusedWriteReturnsItsFlowControlCredit(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			for i := range 4 {
				sendReq(t, cliFr, uint32(2*i+1), goodHeaders("/"), false) //nolint:gosec // G115: i < 4
			}
			for {
				if _, err := cliFr.ReadFrame(context.Background(), &frameOrderLog{}); err != nil {
					return
				}
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

	connWindow := func() int32 {
		sc.fcOutMu.Lock()
		defer sc.fcOutMu.Unlock()
		return sc.peerConnSendWindow
	}
	before := connWindow()

	// A body large enough that a few refusals would exhaust the default 64 KiB
	// connection window if the credit were kept.
	body := make([]byte, 20*1024)
	for i := range 4 {
		stream, aerr := sc.AcceptStream(ctx)
		if aerr != nil {
			t.Fatalf("AcceptStream #%d: %v", i, aerr)
		}
		if rerr := sc.writeServerRSTStream(stream, frame.ErrCodeCancel); rerr != nil {
			t.Fatalf("writeServerRSTStream #%d: %v", i, rerr)
		}
		if derr := sc.writeServerData(context.Background(), stream, body, false); !errors.Is(derr, ErrStreamClosed) {
			t.Fatalf("writeServerData #%d = %v, want ErrStreamClosed", i, derr)
		}
		if got := connWindow(); got != before {
			t.Fatalf("connection send window = %d after %d refused write(s), want %d: the "+
				"refusal kept credit for octets it never sent, and only the peer can give "+
				"it back — %d octets of the connection's window are gone for good, and they "+
				"belonged to every stream on it", got, i+1, before, before-got)
		}
	}
}

// TestRegression_CreditRefundSaturatesAtTheMaximum pins the arithmetic of that
// refund, which has a second way to wedge the same connection.
//
// onWindowUpdate bounds an incoming grant against the window as it stands — and
// that window is already net of octets debited by acquireSendCredits but not yet
// written. So a peer can legally bring the connection window to exactly 2^31-1
// while a chunk is outstanding: the check passes, no error is raised. Adding
// that chunk back on top then overflows int32 to roughly -2^31, avail stays ≤ 0
// for every stream on the connection, and no WINDOW_UPDATE a peer would ever
// send can lift it out — it credits only octets it actually received.
//
// The result is the exact failure the refund was added to prevent, reached from
// the other direction.
func TestRegression_CreditRefundSaturatesAtTheMaximum(t *testing.T) {
	const maxWindow = int32(1<<31 - 1)

	cli, srv := net.Pipe()
	defer cli.Close()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			for {
				if _, rerr := cliFr.ReadFrame(context.Background(), &frameOrderLog{}); rerr != nil {
					return
				}
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

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Both windows at the maximum, as a peer may legally leave them.
	sc.fcOutMu.Lock()
	sc.peerConnSendWindow = maxWindow
	sc.fcOutMu.Unlock()
	stream.mu.Lock()
	stream.sendWindow = maxWindow
	stream.mu.Unlock()

	sc.releaseSendCredits(stream, 16384)

	sc.fcOutMu.Lock()
	gotConn := sc.peerConnSendWindow
	sc.fcOutMu.Unlock()
	stream.mu.Lock()
	gotStream := stream.sendWindow
	stream.mu.Unlock()

	if gotConn != maxWindow {
		t.Errorf("connection send window = %d after refunding into a full window, want %d "+
			"(2^31-1): a negative window starves every stream on the connection in "+
			"acquireSendCredits, and no WINDOW_UPDATE can lift it out", gotConn, maxWindow)
	}
	if gotStream != maxWindow {
		t.Errorf("stream send window = %d, want %d (2^31-1)", gotStream, maxWindow)
	}
}
