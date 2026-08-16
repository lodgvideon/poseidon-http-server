package conn

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// acceptQueueProbe is a client-side frame.Handler that records every
// RST_STREAM the server sends, keyed by stream, and signals PING ACKs.
//
// The PING ACK is the synchronisation barrier both tests below rely on: the
// server processes frames in receipt order on its single reader goroutine, so
// an ACK for a PING written after N HEADERS proves all N have already been
// through registerStream — and that any RST_STREAM they provoked is already
// recorded here, since the server wrote it first.
type acceptQueueProbe struct {
	mu      sync.Mutex
	rsts    map[uint32]frame.ErrCode
	pingAck chan struct{}
}

func newAcceptQueueProbe() *acceptQueueProbe {
	return &acceptQueueProbe{
		rsts:    make(map[uint32]frame.ErrCode),
		pingAck: make(chan struct{}, 8),
	}
}

func (p *acceptQueueProbe) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	p.mu.Lock()
	p.rsts[fh.StreamID] = code
	p.mu.Unlock()
	return nil
}

func (p *acceptQueueProbe) OnPing(fh frame.FrameHeader, _ [8]byte) error {
	if fh.Flags&frame.FlagPingAck != 0 {
		select {
		case p.pingAck <- struct{}{}:
		default:
		}
	}
	return nil
}

func (p *acceptQueueProbe) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (p *acceptQueueProbe) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (p *acceptQueueProbe) OnPriority(frame.FrameHeader, frame.Priority) error { return nil }
func (p *acceptQueueProbe) OnSettings(frame.FrameHeader, frame.SettingsParams) error {
	return nil
}
func (p *acceptQueueProbe) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (p *acceptQueueProbe) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}
func (p *acceptQueueProbe) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (p *acceptQueueProbe) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (p *acceptQueueProbe) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (p *acceptQueueProbe) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }

// snapshot copies the recorded resets.
func (p *acceptQueueProbe) snapshot() map[uint32]frame.ErrCode {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[uint32]frame.ErrCode, len(p.rsts))
	for id, code := range p.rsts {
		out[id] = code
	}
	return out
}

// barrier writes a PING and waits for its ACK, so everything written before it
// has demonstrably been processed by the server's reader goroutine.
func (p *acceptQueueProbe) barrier(t *testing.T, cliFr *frame.Framer) bool {
	t.Helper()
	if err := cliFr.WritePing(false, [8]byte{'a', 'q', 'b'}); err != nil {
		t.Errorf("client WritePing: %v", err)
		return false
	}
	select {
	case <-p.pingAck:
		return true
	case <-time.After(5 * time.Second):
		t.Error("no PING ACK: server reader never drained the frames written before the barrier")
		return false
	}
}

// openClientStream writes a HEADERS frame with no END_STREAM, so the stream
// stays open and counts toward SETTINGS_MAX_CONCURRENT_STREAMS.
func openClientStream(t *testing.T, cliFr *frame.Framer, enc *hpack.Encoder, id uint32) bool {
	t.Helper()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
	})
	if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      id,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     false,
	}); err != nil {
		t.Errorf("client WriteHeaders(%d): %v", id, err)
		return false
	}
	return true
}

// TestServerConn_AcceptQueue_DeliversAdvertisedMaxConcurrentStreams pins the
// promise the server makes in its SETTINGS frame: a client that opens exactly
// SETTINGS_MAX_CONCURRENT_STREAMS streams (RFC 9113 §5.1.2 — "the maximum
// number of concurrent streams that the sender will allow") must have every one
// of them delivered, even when the application has not drained a single one
// yet. The accept queue is a delivery buffer, not a second, lower concurrency
// limit.
//
// Regression for #119: acceptCh was make(chan *ServerStream, 64) against an
// advertised MaxConcurrentStreams of 100, so streams 65..100 were dropped.
func TestServerConn_AcceptQueue_DeliversAdvertisedMaxConcurrentStreams(t *testing.T) {
	// The advertised default, read from the code under test rather than
	// restated, so the two can never disagree here either.
	want := int(AdvertisedSettings{}.defaulted().MaxConcurrentStreams)
	if want < 2 {
		t.Fatalf("default MaxConcurrentStreams = %d, test needs > 1", want)
	}

	cli, srv := net.Pipe()
	defer cli.Close()

	probe := newAcceptQueueProbe()
	allOpen := make(chan struct{})
	drained := make(chan struct{})
	clientDone := make(chan struct{})

	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), probe); err != nil {
						return
					}
				}
			}()
			enc := hpack.NewEncoder()
			for i := range want {
				if !openClientStream(t, cliFr, enc, uint32(2*i+1)) { //nolint:gosec // G115: bounded by want
					return
				}
			}
			if !probe.barrier(t, cliFr) {
				return
			}
			close(allOpen)
			// Hold the pipe open until the server has finished draining.
			<-drained
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case <-allOpen:
	case <-time.After(15 * time.Second):
		close(drained)
		t.Fatal("client never finished opening streams")
	}

	seen := make(map[uint32]bool, want)
	for i := range want {
		actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
		ss, aerr := sc.AcceptStream(actx)
		acancel()
		if aerr != nil {
			close(drained)
			t.Fatalf("AcceptStream #%d of %d: %v (delivered %d; resets seen: %v)",
				i+1, want, aerr, len(seen), probe.snapshot())
		}
		seen[ss.ID()] = true
	}
	close(drained)

	if len(seen) != want {
		t.Fatalf("delivered %d distinct streams, want %d", len(seen), want)
	}
	// The error-code half of the same defect: nothing may be reset at all here,
	// and least of all with CANCEL, which tells the client the request WAS
	// processed and must not be retried.
	if rsts := probe.snapshot(); len(rsts) != 0 {
		t.Fatalf("server reset %d streams while at or below its advertised limit of %d: %v",
			len(rsts), want, rsts)
	}
	<-clientDone
}

// TestServerConn_AcceptQueue_OverflowRefusesRatherThanCancels covers the other
// half of #119: the error code on a genuine accept-queue overflow.
//
// Sizing the queue from MaxConcurrentStreams does not make overflow impossible,
// so the branch is load-bearing and must be RFC-correct. A stream leaves the
// stream table when the client resets it (OnRSTStream -> markStreamDone) but
// keeps its slot in the accept queue until the application takes delivery. So a
// client can free every table entry while the queue stays full, and the next
// stream is admitted by the table and then finds nowhere to be delivered — with
// the connection nowhere near its advertised limit.
//
// RFC 9113 §8.7: "The REFUSED_STREAM error code can be included in a RST_STREAM
// frame to indicate that the stream is being closed prior to any processing
// having occurred. Any request that was sent on the reset stream can be safely
// retried." CANCEL carries no such guarantee.
func TestServerConn_AcceptQueue_OverflowRefusesRatherThanCancels(t *testing.T) {
	const limit = 4
	const overflowID = uint32(2*limit + 1) // 9

	cli, srv := net.Pipe()
	defer cli.Close()

	probe := newAcceptQueueProbe()
	phaseDone := make(chan struct{})
	release := make(chan struct{})
	clientDone := make(chan struct{})

	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), probe); err != nil {
						return
					}
				}
			}()
			enc := hpack.NewEncoder()

			// Phase 1: fill both the stream table and the accept queue.
			for i := range limit {
				if !openClientStream(t, cliFr, enc, uint32(2*i+1)) { //nolint:gosec // G115: bounded by limit
					return
				}
			}
			if !probe.barrier(t, cliFr) {
				return
			}

			// Phase 2: reset all of them. Each leaves the table, freeing the
			// concurrency budget; none leaves the accept queue.
			for i := range limit {
				if err := cliFr.WriteRSTStream(uint32(2*i+1), frame.ErrCodeCancel); err != nil { //nolint:gosec // G115: bounded by limit
					t.Errorf("client WriteRSTStream: %v", err)
					return
				}
			}
			if !probe.barrier(t, cliFr) {
				return
			}

			// Phase 3: one more stream. The table admits it (0 of 4 in use); the
			// accept queue is still full.
			if !openClientStream(t, cliFr, enc, overflowID) {
				return
			}
			if !probe.barrier(t, cliFr) {
				return
			}
			close(phaseDone)
			<-release
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: limit},
	})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case <-phaseDone:
	case <-time.After(15 * time.Second):
		close(release)
		t.Fatal("client never completed the overflow sequence")
	}
	close(release)

	rsts := probe.snapshot()
	code, ok := rsts[overflowID]
	if !ok {
		t.Fatalf("stream %d was neither delivered nor refused — silently dropped; resets seen: %v",
			overflowID, rsts)
	}
	if code == frame.ErrCodeCancel {
		t.Fatalf("stream %d refused with CANCEL: RFC 9113 §8.7 reserves REFUSED_STREAM (0x7) for a stream closed "+
			"before any processing, and only REFUSED_STREAM makes the request safe to retry", overflowID)
	}
	if code != frame.ErrCodeRefusedStream {
		t.Fatalf("stream %d reset with %v, want REFUSED_STREAM (0x7)", overflowID, code)
	}
	<-clientDone
}
