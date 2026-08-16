package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestServerConn_StreamsAccepted_ExcludesStreamsSkippedAtDelivery is the metric
// half of the accept-queue mechanism whose delivery half is
// TestServerConn_AcceptStream_QueueOfOnlyResetStreamsDoesNotDeliver.
//
// registerStream counted a stream the moment the non-blocking send into acceptCh
// succeeded, on the reasoning that delivery was then certain. That was true
// while AcceptStream returned everything it dequeued, and stopped being true
// when it began skipping streams that died in the queue (deliverable, #133): the
// stream here is opened, queued, counted, reset by the client, and then skipped
// at dequeue, so it is counted and never served.
//
// ConnStats.StreamsAccepted is the number an operator reconciles against
// requests actually served. A client that opens and cancels aggressively drives
// it above the number of handlers that ran with nothing else reporting the gap,
// and under a rapid-reset flood the two diverge completely — the counter tracks
// the attack rate while zero handlers run (issue #147).
//
// Deterministic, not timing-dependent: stageResetBeforeAccept's PING-ACK barrier
// proves the server's reader goroutine has processed both the HEADERS and the
// RST_STREAM before the application calls AcceptStream at all.
func TestServerConn_StreamsAccepted_ExcludesStreamsSkippedAtDelivery(t *testing.T) {
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

	// The stream is queued and dead. AcceptStream must skip it, and must not have
	// counted it.
	actx, acancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	ss, aerr := sc.AcceptStream(actx)
	acancel()

	if aerr == nil {
		close(release)
		t.Fatalf("AcceptStream delivered stream %d from a queue holding only a reset stream", ss.ID())
	}
	if !errors.Is(aerr, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("AcceptStream: got %v, want context.DeadlineExceeded", aerr)
	}

	stats := sc.Stats()
	close(release)
	if stats.StreamsAccepted != 0 {
		t.Fatalf("StreamsAccepted = %d, want 0: stream %d was queued and then reset before the "+
			"application accepted it, so AcceptStream skipped it and no handler ever ran for it; "+
			"counting it puts the metric an operator reconciles against served requests above the "+
			"number of requests actually served", stats.StreamsAccepted, onlyID)
	}
	<-clientDone
}

// TestServerConn_StreamsAccepted_CountsDeliveredStream is the other side of the
// same assertion, and the control for it: a stream that IS delivered must still
// be counted. Without this, deleting the increment outright passes the test
// above.
func TestServerConn_StreamsAccepted_CountsDeliveredStream(t *testing.T) {
	const liveID = uint32(1)

	cli, srv := net.Pipe()
	defer cli.Close()

	probe := newAcceptQueueProbe()
	staged := make(chan struct{})
	release := make(chan struct{})
	clientDone := make(chan struct{})
	// Same staging, no resets: the stream is opened and left alive.
	stageResetBeforeAccept(t, cli, probe, []uint32{liveID}, nil, staged, release, clientDone)

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
		t.Fatal("client never finished staging")
	}

	// Before delivery the stream is queued but not yet handed over, so it must not
	// be counted yet either. This is what pins the counter to the dequeue rather
	// than to the enqueue.
	if before := sc.Stats().StreamsAccepted; before != 0 {
		close(release)
		t.Fatalf("StreamsAccepted = %d before AcceptStream was called, want 0: the stream is "+
			"queued, not delivered", before)
	}

	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	ss, aerr := sc.AcceptStream(actx)
	acancel()
	if aerr != nil {
		close(release)
		t.Fatalf("AcceptStream: %v", aerr)
	}
	if ss.ID() != liveID {
		close(release)
		t.Fatalf("AcceptStream delivered stream %d, want %d", ss.ID(), liveID)
	}

	stats := sc.Stats()
	close(release)
	if stats.StreamsAccepted != 1 {
		t.Fatalf("StreamsAccepted = %d after one delivered stream, want 1", stats.StreamsAccepted)
	}
	<-clientDone
}

// TestRegisterStream_RefusedStreamsDoNotLeakContexts pins the accounting duty
// that binding the per-stream context BEFORE admission hands to registerStream's
// two refusal branches (issue #156).
//
// The context is bound ahead of both publications — the stream table and
// acceptCh — so that no goroutine can ever find a half-built stream. That
// ordering makes the refusal paths owe a cancellation they did not owe before:
//
//   - refused at the concurrency limit, the stream never enters the table at
//     all, so writeServerRSTStream's markStreamDone finds nothing to release and
//     cancels nothing. Nothing else will ever cancel it either.
//   - refused at a full accept queue, the stream IS in the table and
//     markStreamDone does cancel it — but the branch cancels for itself rather
//     than depending on that, since CancelFunc is idempotent.
//
// A leaked child stays in connCtx's children map for the life of the connection,
// and the refusal branch is one an unauthenticated peer drives at will simply by
// opening more streams than the limit it was given — so the leak rate is the
// peer's to choose. That is strictly worse than the unreachable publication
// window the reorder closes, which is why the two arrive together.
func TestRegisterStream_RefusedStreamsDoNotLeakContexts(t *testing.T) {
	const limit = 2

	cli, srv := net.Pipe()
	defer cli.Close()

	release := make(chan struct{})
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Drain whatever the server writes (the RST_STREAMs below) so no write
			// blocks on the unbuffered pipe.
			go func() {
				probe := newAcceptQueueProbe()
				for {
					if _, err := cliFr.ReadFrame(context.Background(), probe); err != nil {
						return
					}
				}
			}()
			<-release
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: limit},
	}.defaulted())
	if err != nil {
		close(release)
		t.Fatalf("NewServerConn: %v", err)
	}
	defer func() { close(release); sc.Close(); <-clientDone }()

	// acceptQueueDepth tracks the advertised limit, so filling the table fills the
	// queue with it.
	admitted := make([]*ServerStream, 0, limit)
	for i := range uint32(limit) {
		id := 1 + 2*i
		s := newServerStream(id, 8, sc, int32(connInitialRecvWindow))
		if !sc.registerStream(id, s) {
			t.Fatalf("registerStream(%d) refused a stream within the advertised limit of %d", id, limit)
		}
		admitted = append(admitted, s)
	}
	// Control: an ADMITTED stream must not be cancelled. Without this, cancelling
	// unconditionally at the top of registerStream would satisfy every assertion
	// below.
	for _, s := range admitted {
		if err := s.Context().Err(); err != nil {
			t.Fatalf("admitted stream %d arrived with a cancelled context: %v", s.ID(), err)
		}
	}

	// Branch 1: over the concurrency limit. The table is full, so admitClient
	// refuses and the stream is never published anywhere.
	overLimit := newServerStream(5, 8, sc, int32(connInitialRecvWindow))
	if sc.registerStream(5, overLimit) {
		t.Fatalf("registerStream(5) admitted a %drd stream against an advertised limit of %d", limit+1, limit)
	}
	if err := overLimit.Context().Err(); err == nil {
		t.Fatalf("stream 5 was refused over MaxConcurrentStreams but its context is still live " +
			"(Err=nil): it never entered the stream table, so markStreamDone released nothing and " +
			"cancelled nothing, and the context child stays in connCtx for the life of the " +
			"connection — at a rate the peer chooses")
	}

	// Branch 2: full accept queue with an EMPTY table. Releasing the admitted
	// streams takes them out of the table but not out of acceptCh, which has no
	// removal — exactly the state registerStream's queue branch documents.
	for _, s := range admitted {
		sc.markStreamDone(s.ID())
	}
	if live := sc.ActiveStreams(); live != 0 {
		t.Fatalf("ActiveStreams = %d after releasing every admitted stream, want 0", live)
	}
	queueFull := newServerStream(7, 8, sc, int32(connInitialRecvWindow))
	if sc.registerStream(7, queueFull) {
		t.Fatal("registerStream(7) succeeded, but the accept queue should still hold the two " +
			"released streams: a channel has no removal, so releasing them from the table does " +
			"not free their queue slots")
	}
	if err := queueFull.Context().Err(); err == nil {
		t.Fatal("stream 7 was refused on a full accept queue but its context is still live (Err=nil)")
	}
}
