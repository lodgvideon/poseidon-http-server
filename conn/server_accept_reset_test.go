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

// stageResetBeforeAccept drives the client half shared by both tests below:
// open every id in order, barrier, reset every id in resetIDs, barrier. When it
// returns the server's reader goroutine has demonstrably processed all of it —
// the PING ACK proves the frames written before it were handled, since the
// server reads frames in receipt order on one goroutine — and the application
// has not called AcceptStream even once.
//
// staged is closed when the sequence is complete; the client then holds the pipe
// open until release is closed, so AcceptStream's readerDone arm cannot fire and
// mask the behaviour under test.
func stageResetBeforeAccept(t *testing.T, cli net.Conn, probe *acceptQueueProbe, open []uint32, resetIDs []uint32, staged, release, clientDone chan struct{}) {
	t.Helper()
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
			for _, id := range open {
				if !openClientStream(t, cliFr, enc, id) {
					return
				}
			}
			if !probe.barrier(t, cliFr) {
				return
			}
			for _, id := range resetIDs {
				if err := cliFr.WriteRSTStream(id, frame.ErrCodeCancel); err != nil {
					t.Errorf("client WriteRSTStream(%d): %v", id, err)
					return
				}
			}
			if !probe.barrier(t, cliFr) {
				return
			}
			close(staged)
			<-release
		})
	}()
}

// TestServerConn_AcceptStream_SkipsStreamResetBeforeDelivery is the delivery
// half of the accept-queue mechanism #119 fixed the overflow half of.
//
// A stream leaves the stream table the moment the client resets it
// (serverConnHandler.OnRSTStream -> markStreamDone -> streamTable.release, which
// also cancels its context) but it does NOT leave sc.acceptCh: the pointer sits
// in the channel buffer until the application takes delivery. Before the fix for
// #133, AcceptStream returned whatever came off that channel with no state
// check, so the application was handed a *ServerStream already carrying stReset,
// already deregistered, and with a cancelled context — and ran a handler for it.
//
// RFC 9113 §5.1: "A stream also enters the 'closed' state after an endpoint
// either sends or receives a RST_STREAM frame", and "An endpoint MUST NOT send
// frames other than PRIORITY on a closed stream". Everything the handler
// produces for such a stream is work whose only possible outcome is to be
// refused by authorizeSend.
//
// The queue is FIFO, so resetting the FIRST of two opened streams puts the dead
// one at the head: a correct AcceptStream must skip it and return the second.
func TestServerConn_AcceptStream_SkipsStreamResetBeforeDelivery(t *testing.T) {
	const deadID = uint32(1)
	const liveID = uint32(3)

	cli, srv := net.Pipe()
	defer cli.Close()

	probe := newAcceptQueueProbe()
	staged := make(chan struct{})
	release := make(chan struct{})
	clientDone := make(chan struct{})
	stageResetBeforeAccept(t, cli, probe, []uint32{deadID, liveID}, []uint32{deadID}, staged, release, clientDone)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{})
	if err != nil {
		close(release)
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case <-staged:
	case <-time.After(15 * time.Second):
		close(release)
		t.Fatal("client never finished staging the reset")
	}

	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	ss, aerr := sc.AcceptStream(actx)
	acancel()
	if aerr != nil {
		close(release)
		t.Fatalf("AcceptStream: %v", aerr)
	}
	if ss == nil {
		close(release)
		t.Fatal("AcceptStream returned a nil stream and a nil error")
	}
	if ss.ID() == deadID {
		close(release)
		t.Fatalf("AcceptStream delivered stream %d, which the client reset before the application accepted it "+
			"(state bits %#04x, terminal=%v, ctx.Err=%v); the handler would run and write to a stream the peer abandoned",
			ss.ID(), uint32(ss.state()), ss.state().Terminal(), ss.Context().Err())
	}
	if ss.ID() != liveID {
		close(release)
		t.Fatalf("AcceptStream delivered stream %d, want the live stream %d", ss.ID(), liveID)
	}
	if st := ss.state(); st.Terminal() {
		close(release)
		t.Fatalf("delivered stream %d is already terminal (state bits %#04x)", ss.ID(), uint32(st))
	}
	if cerr := ss.Context().Err(); cerr != nil {
		close(release)
		t.Fatalf("delivered stream %d arrived with a cancelled context: %v", ss.ID(), cerr)
	}

	// The dead stream must have been CONSUMED, not stepped over and left to be
	// handed out by the next call. A channel cannot be peeked, so this pins the
	// difference between skipping and merely reordering.
	actx2, acancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	extra, aerr2 := sc.AcceptStream(actx2)
	acancel2()
	close(release)
	if aerr2 == nil {
		t.Fatalf("a second AcceptStream delivered stream %d; only %d was live", extra.ID(), liveID)
	}
	if !errors.Is(aerr2, context.DeadlineExceeded) {
		t.Fatalf("second AcceptStream: got %v, want context.DeadlineExceeded", aerr2)
	}
	<-clientDone
}

// TestServerConn_AcceptStream_QueueOfOnlyResetStreamsDoesNotDeliver pins the
// drain behaviour of the same fix: when everything left in the accept queue is
// dead, AcceptStream must go back to waiting rather than deliver a corpse — and
// it must not return a nil stream with a nil error, which a caller
// (server.acceptLoop -> spawnStream) would dereference.
//
// It must also not spin: the queue is drained with a non-blocking receive, and
// once it is empty the call parks in the blocking select on acceptCh /
// readerDone / ctx.Done. Each loop iteration therefore consumes one queued
// stream, so the skip loop is bounded by the queue depth.
func TestServerConn_AcceptStream_QueueOfOnlyResetStreamsDoesNotDeliver(t *testing.T) {
	const onlyID = uint32(1)

	cli, srv := net.Pipe()
	defer cli.Close()

	probe := newAcceptQueueProbe()
	staged := make(chan struct{})
	release := make(chan struct{})
	clientDone := make(chan struct{})
	stageResetBeforeAccept(t, cli, probe, []uint32{onlyID}, []uint32{onlyID}, staged, release, clientDone)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{})
	if err != nil {
		close(release)
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case <-staged:
	case <-time.After(15 * time.Second):
		close(release)
		t.Fatal("client never finished staging the reset")
	}

	actx, acancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	ss, aerr := sc.AcceptStream(actx)
	acancel()
	close(release)

	if aerr == nil {
		t.Fatalf("AcceptStream delivered stream %d from a queue containing nothing but reset streams "+
			"(state bits %#04x, ctx.Err=%v)", ss.ID(), uint32(ss.state()), ss.Context().Err())
	}
	if ss != nil {
		t.Fatalf("AcceptStream returned both an error (%v) and a non-nil stream %d", aerr, ss.ID())
	}
	if !errors.Is(aerr, context.DeadlineExceeded) {
		t.Fatalf("AcceptStream: got %v, want context.DeadlineExceeded", aerr)
	}
	<-clientDone
}
