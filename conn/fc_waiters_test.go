package conn

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the targeted outbound flow-control wakeups in conn/fc_waiters.go.
//
// Replacing a Broadcast with anything narrower trades a cost for a risk: a
// writer that is never woken. That failure is silent — the stream simply stops,
// and nothing logs it — so these tests are built around the negative case, not
// the positive one. Every case asserts BOTH that the writers a grant releases do
// proceed AND that the writers it does not release stay parked, because a fix
// that just broadcasts everywhere would pass the first half of that alone.

// fcParkSettleTime is how long a test waits before concluding that a writer has
// not been woken. It bounds a scheduling delay, not a computation: the wakeups
// under test are a channel send away, so anything not delivered within this is
// not coming.
const fcParkSettleTime = 150 * time.Millisecond

// fcParkWant is the octet count every parked test writer asks for. One value
// throughout, so an assertion on what a released writer took is a comparison
// against a constant rather than against a number threaded through the call.
const fcParkWant = 100

// fcTestConn builds a ServerConn with nStreams admitted client streams and a
// transport that silently swallows whatever is written to it, so Close can run
// its real GOAWAY path. No reader goroutine exists, so readerDone is closed
// up front — Close waits on it.
func fcTestConn(t *testing.T, nStreams int) (*ServerConn, []*ServerStream) {
	t.Helper()

	cli, srv := net.Pipe()
	sc := &ServerConn{
		transport:          srv,
		peerConnSendWindow: 0,
		readerDone:         make(chan struct{}),
	}
	close(sc.readerDone)
	sc.tbl = newStreamTable(func() uint32 { return 0 }) // streams start with no send credit
	sc.fr = newCountingFramer(srv, sc, 16384)

	drained := make(chan struct{})
	go func() { defer close(drained); _, _ = io.Copy(io.Discard, cli) }()
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
		<-drained
	})

	streams := make([]*ServerStream, 0, nStreams)
	for i := range nStreams {
		id := uint32(2*i + 1) //nolint:gosec // G115: small loop bound
		ss := newServerStream(id, 8, sc, 0)
		if !sc.tbl.admitClient(id, ss, 0) {
			t.Fatalf("admitClient(%d) refused", id)
		}
		streams = append(streams, ss)
	}
	return sc, streams
}

// fcWriter is one goroutine parked in acquireSendCredits, plus the bookkeeping
// needed to ask whether it has come back.
type fcWriter struct {
	ss     *ServerStream
	got    atomic.Int64
	err    atomic.Pointer[error]
	done   atomic.Bool
	cancel context.CancelFunc
}

func (w *fcWriter) released() bool { return w.done.Load() }

// fcPark starts a writer on ss and blocks until it is demonstrably inside
// acquireSendCredits — established by reading the connection's own waiter list
// under the lock that guards it, not by sleeping and hoping.
func fcParkWriter(ctx context.Context, t *testing.T, sc *ServerConn, ss *ServerStream, wg *sync.WaitGroup) *fcWriter {
	t.Helper()
	w := &fcWriter{ss: ss}
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := sc.acquireSendCredits(ctx, ss, fcParkWant)
		w.got.Store(int64(n))
		if err != nil {
			w.err.Store(&err)
		}
		w.done.Store(true)
	}()
	fcWaitParked(t, sc, ss)
	return w
}

// fcWaitParked blocks until at least one writer is linked into ss's waiter list.
func fcWaitParked(t *testing.T, sc *ServerConn, ss *ServerStream) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc.fcOutMu.Lock()
		parked := ss.fcHead != nil
		sc.fcOutMu.Unlock()
		if parked {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("writer on stream %d never parked", ss.id)
}

// fcAwaitReleased waits for w to leave acquireSendCredits.
func fcAwaitReleased(t *testing.T, w *fcWriter, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.released() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s: writer on stream %d was never woken — missed wakeup", what, w.ss.id)
}

// fcAssertStillParked gives w every chance to wake and asserts it did not.
func fcAssertStillParked(t *testing.T, w *fcWriter, what string) {
	t.Helper()
	time.Sleep(fcParkSettleTime)
	if w.released() {
		t.Fatalf("%s: writer on stream %d woke for a grant that cannot release it", what, w.ss.id)
	}
}

// grantStreamCredit hands n octets to one stream through the real inbound
// WINDOW_UPDATE path.
func grantStreamCredit(t *testing.T, sc *ServerConn, ss *ServerStream, n uint32) {
	t.Helper()
	if err := sc.onWindowUpdate(ss.id, n); err != nil {
		t.Fatalf("onWindowUpdate(stream %d): %v", ss.id, err)
	}
}

// grantConnCredit hands n octets to the connection window through the real
// inbound WINDOW_UPDATE path.
func grantConnCredit(t *testing.T, sc *ServerConn, n uint32) {
	t.Helper()
	if err := sc.onWindowUpdate(0, n); err != nil {
		t.Fatalf("onWindowUpdate(conn): %v", err)
	}
}

// ---------------------------------------------------------------------------
// A per-stream grant must reach its own stream and no other
// ---------------------------------------------------------------------------

// TestFCWaiters_StreamGrantWakesOnlyThatStream is the case the waiter list
// exists for. Under the old sync.Cond every one of these writers woke on every
// WINDOW_UPDATE; the assertion that the untargeted ones stay parked is what
// distinguishes a targeted wakeup from a broadcast that happens to be correct.
func TestFCWaiters_StreamGrantWakesOnlyThatStream(t *testing.T) {
	sc, streams := fcTestConn(t, 4)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		// Release anyone still parked so the test cannot hang on cleanup.
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	ctx := context.Background()
	writers := make([]*fcWriter, len(streams))
	for i, ss := range streams {
		writers[i] = fcParkWriter(ctx, t, sc, ss, &wg)
	}

	// The connection window is the other half of min(stream, conn): give it
	// credit so the stream window is the only thing binding.
	grantConnCredit(t, sc, 1<<20)
	for _, w := range writers {
		fcAssertStillParked(t, w, "connection grant with every stream window empty")
	}

	// Now credit exactly one stream.
	grantStreamCredit(t, sc, streams[2], fcParkWant)
	fcAwaitReleased(t, writers[2], "per-stream WINDOW_UPDATE")
	if got := writers[2].got.Load(); got != fcParkWant {
		t.Fatalf("released writer took %d octets, want %d", got, fcParkWant)
	}
	for i, w := range writers {
		if i == 2 {
			continue
		}
		fcAssertStillParked(t, w, "per-stream WINDOW_UPDATE naming a different stream")
	}
}

// ---------------------------------------------------------------------------
// A connection grant must reach writers holding stream credit, and only those
// ---------------------------------------------------------------------------

// TestFCWaiters_ConnGrantWakesOnlyStreamCreditHolders pins the fcWakeConn
// predicate. A writer whose own stream window is empty cannot be released by
// connection credit — its send is min(stream, conn) and the stream side is the
// zero — so waking it is the waste this change removes. Getting the predicate
// backwards would strand the writer that CAN proceed, which the first half
// catches.
func TestFCWaiters_ConnGrantWakesOnlyStreamCreditHolders(t *testing.T) {
	sc, streams := fcTestConn(t, 2)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	ctx := context.Background()

	// streams[0] holds stream credit and lacks connection credit.
	streams[0].mu.Lock()
	streams[0].sendWindow = 5 * fcParkWant
	streams[0].mu.Unlock()
	hasStreamCredit := fcParkWriter(ctx, t, sc, streams[0], &wg)

	// streams[1] has neither.
	noStreamCredit := fcParkWriter(ctx, t, sc, streams[1], &wg)

	sc.fcOutMu.Lock()
	blocked := sc.fcConnBlocked
	sc.fcOutMu.Unlock()
	if blocked != 1 {
		t.Fatalf("fcConnBlocked = %d, want 1 (only the stream-credit holder waits on the connection)", blocked)
	}

	grantConnCredit(t, sc, fcParkWant)
	fcAwaitReleased(t, hasStreamCredit, "connection WINDOW_UPDATE")
	fcAssertStillParked(t, noStreamCredit, "connection WINDOW_UPDATE with an empty stream window")

	// And the counter unwound when the released writer left.
	sc.fcOutMu.Lock()
	blocked = sc.fcConnBlocked
	sc.fcOutMu.Unlock()
	if blocked != 0 {
		t.Fatalf("fcConnBlocked = %d after the waiter left, want 0", blocked)
	}
}

// ---------------------------------------------------------------------------
// The injection arm: prove these tests can see a missed wakeup at all
// ---------------------------------------------------------------------------

// TestFCWaiters_InjectedMissedWakeupIsDetected is the control for every
// assertion above. It grows a window WITHOUT notifying anyone — which is exactly
// the shape of a missed wakeup, credit sitting available with nobody told — and
// requires that the writer stays parked. If it woke anyway, then "released"
// in the other tests would be proving nothing: the writer would be polling, or
// waking spuriously, and a real missed wakeup would slip through green.
//
// Each injection is then repaired through the real notifier and the writer must
// come back, so the test also shows the parked writer was genuinely wakeable the
// whole time and the silence was caused by the missing notification alone.
func TestFCWaiters_InjectedMissedWakeupIsDetected(t *testing.T) {
	const injections = 8

	sc, streams := fcTestConn(t, injections)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	ctx := context.Background()
	grantConnCredit(t, sc, 1<<20) // connection side never binds here

	injected, detected := 0, 0
	for i := range injections {
		ss := streams[i]
		w := fcParkWriter(ctx, t, sc, ss, &wg)

		// INJECT: credit the stream window behind the notifier's back.
		ss.mu.Lock()
		ss.sendWindow += 100
		ss.mu.Unlock()
		injected++

		time.Sleep(fcParkSettleTime)
		if w.released() {
			t.Fatalf("injection %d: writer woke with no notification issued — "+
				"these tests cannot distinguish a wakeup from a spurious one", i)
		}
		detected++

		// REPAIR: the same credit, announced properly this time.
		sc.fcOutMu.Lock()
		sc.fcWakeStream(ss)
		sc.fcOutMu.Unlock()
		fcAwaitReleased(t, w, "repaired wakeup after injection")
	}

	if injected != injections || detected != injections {
		t.Fatalf("injected=%d detected=%d, want %d each", injected, detected, injections)
	}
	t.Logf("missed-wakeup injections performed=%d detected=%d (control arm: every "+
		"repaired grant released its writer)", injected, detected)
}

// ---------------------------------------------------------------------------
// Context cancellation — the path that no longer has a watchdog goroutine
// ---------------------------------------------------------------------------

// TestFCWaiters_ContextCancelReleasesOnlyThatWriter covers what
// acquireSendCreditsSlow used to do with a goroutine per park. The parked writer
// now selects on ctx.Done() itself, so a cancellation must release exactly the
// writer that owns that context and leave its neighbours alone.
func TestFCWaiters_ContextCancelReleasesOnlyThatWriter(t *testing.T) {
	sc, streams := fcTestConn(t, 3)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	cancelCtx, cancel := context.WithCancel(context.Background())
	doomed := fcParkWriter(cancelCtx, t, sc, streams[0], &wg)
	doomed.cancel = cancel

	bystanders := []*fcWriter{
		fcParkWriter(context.Background(), t, sc, streams[1], &wg),
		fcParkWriter(context.Background(), t, sc, streams[2], &wg),
	}

	cancel()
	fcAwaitReleased(t, doomed, "context cancellation")
	gotErr := doomed.err.Load()
	if gotErr == nil || !errors.Is(*gotErr, context.Canceled) {
		t.Fatalf("cancelled writer returned err=%v, want context.Canceled", gotErr)
	}
	for _, w := range bystanders {
		fcAssertStillParked(t, w, "another writer's context cancellation")
	}

	// The cancelled writer must also have unlinked itself: a waiter left in the
	// lists after its frame returns is walked and woken forever.
	sc.fcOutMu.Lock()
	stillListed := streams[0].fcHead != nil
	sc.fcOutMu.Unlock()
	if stillListed {
		t.Fatal("cancelled writer stayed linked in its stream's waiter list")
	}
}

// ---------------------------------------------------------------------------
// Close, SETTINGS and refund — the three grants that must reach everyone
// ---------------------------------------------------------------------------

// TestFCWaiters_CloseReleasesEveryParkedWriter checks the one place a broadcast
// is still the right answer. Narrowing this one would hang every parked writer
// on connection teardown.
func TestFCWaiters_CloseReleasesEveryParkedWriter(t *testing.T) {
	sc, streams := fcTestConn(t, 16)
	var wg sync.WaitGroup

	writers := make([]*fcWriter, len(streams))
	for i, ss := range streams {
		writers[i] = fcParkWriter(context.Background(), t, sc, ss, &wg)
	}

	_ = sc.Close()
	for _, w := range writers {
		fcAwaitReleased(t, w, "connection Close")
		gotErr := w.err.Load()
		if gotErr == nil || !errors.Is(*gotErr, ErrConnClosed) {
			t.Fatalf("writer on stream %d returned err=%v, want ErrConnClosed", w.ss.id, gotErr)
		}
	}
	wg.Wait()

	sc.fcOutMu.Lock()
	leftover := sc.fcHead
	blocked := sc.fcConnBlocked
	sc.fcOutMu.Unlock()
	if leftover != nil {
		t.Fatal("waiters remained linked after every writer returned")
	}
	if blocked != 0 {
		t.Fatalf("fcConnBlocked = %d after teardown, want 0", blocked)
	}
}

// TestFCWaiters_ReleaseSendCreditsWakesTheRefundedStream covers the refund path
// and, specifically, its ordering. The sync.Cond version notified while holding
// fcOutMu and only afterwards took ss.mu to restore the STREAM window, so a
// writer could wake, read a window that had not been refunded yet, and park
// again with nothing further owed to it.
func TestFCWaiters_ReleaseSendCreditsWakesTheRefundedStream(t *testing.T) {
	sc, streams := fcTestConn(t, 2)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	refunded := fcParkWriter(context.Background(), t, sc, streams[0], &wg)
	other := fcParkWriter(context.Background(), t, sc, streams[1], &wg)

	sc.releaseSendCredits(streams[0], fcParkWant)

	fcAwaitReleased(t, refunded, "releaseSendCredits on this writer's stream")
	fcAssertStillParked(t, other, "releaseSendCredits on a different stream")
}

// TestFCWaiters_InitialWindowIncreaseWakesEveryone covers RFC 9113 §6.9.2: a
// SETTINGS_INITIAL_WINDOW_SIZE increase applies retroactively to every open
// stream, so it is the second event that genuinely needs the whole population.
func TestFCWaiters_InitialWindowIncreaseWakesEveryone(t *testing.T) {
	sc, streams := fcTestConn(t, 8)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() {
		sc.closed.Store(true)
		sc.fcOutMu.Lock()
		sc.fcWakeAll()
		sc.fcOutMu.Unlock()
	}()

	grantConnCredit(t, sc, 1<<20)
	writers := make([]*fcWriter, len(streams))
	for i, ss := range streams {
		writers[i] = fcParkWriter(context.Background(), t, sc, ss, &wg)
	}

	// Raise every stream's send window through applyInitialWindow, the way
	// onSettings does, and wake as onSettings does.
	if err := sc.tbl.applyInitialWindow(
		func() (uint32, uint32) { return 0, 4096 },
		func(st *ServerStream, delta int64) error {
			st.mu.Lock()
			st.sendWindow = int32(int64(st.sendWindow) + delta) //nolint:gosec // G115: bounded by the test
			st.mu.Unlock()
			return nil
		}); err != nil {
		t.Fatalf("applyInitialWindow: %v", err)
	}
	sc.fcOutMu.Lock()
	sc.fcWakeAll()
	sc.fcOutMu.Unlock()

	for _, w := range writers {
		fcAwaitReleased(t, w, "SETTINGS_INITIAL_WINDOW_SIZE increase")
	}
}

// ---------------------------------------------------------------------------
// Churn: nothing may be stranded, ever
// ---------------------------------------------------------------------------

// TestFCWaiters_NoStrandedWriterUnderChurn is the whole-system statement the
// per-event tests above cannot make: run many writers against many streams while
// grants of both kinds arrive concurrently, and require that every writer
// finishes. A wakeup rule that is narrow in the wrong place shows up here as a
// hang, not as a wrong value, which is why the assertion is a deadline.
//
// This is the -race target: the waiter lists, fcConnBlocked and both windows are
// all touched from the granting goroutines and the parked ones at once.
func TestFCWaiters_NoStrandedWriterUnderChurn(t *testing.T) {
	const (
		nStreams        = 24
		writesPerStream = 12
		chunk           = 64
	)

	sc, streams := fcTestConn(t, nStreams)

	var completed atomic.Int64
	var wg sync.WaitGroup
	for _, ss := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range writesPerStream {
				n, err := sc.acquireSendCredits(context.Background(), ss, chunk)
				if err != nil {
					t.Errorf("stream %d: acquireSendCredits: %v", ss.id, err)
					return
				}
				if n <= 0 || n > chunk {
					t.Errorf("stream %d: acquireSendCredits returned %d, want 1..%d", ss.id, n, chunk)
					return
				}
				completed.Add(1)
			}
		}()
	}

	// Feed credit from a separate goroutine, alternating the two grant kinds so
	// both wake predicates are exercised against a moving waiter population.
	granter := make(chan struct{})
	go func() {
		defer close(granter)
		for range writesPerStream {
			grantConnCredit(t, sc, chunk*nStreams)
			for _, ss := range streams {
				if err := sc.onWindowUpdate(ss.id, chunk); err != nil {
					t.Errorf("onWindowUpdate(stream %d): %v", ss.id, err)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		sc.fcOutMu.Lock()
		parked := 0
		for w := sc.fcHead; w != nil; w = w.connNext {
			parked++
		}
		sc.fcOutMu.Unlock()
		t.Fatalf("stranded: %d/%d writes completed, %d writers still parked",
			completed.Load(), nStreams*writesPerStream, parked)
	}
	<-granter

	if got, want := completed.Load(), int64(nStreams*writesPerStream); got != want {
		t.Fatalf("%d writes completed, want %d", got, want)
	}

	sc.fcOutMu.Lock()
	leftover := sc.fcHead
	blocked := sc.fcConnBlocked
	sc.fcOutMu.Unlock()
	if leftover != nil {
		t.Fatal("waiters remained linked after every writer finished")
	}
	if blocked != 0 {
		t.Fatalf("fcConnBlocked = %d after every writer finished, want 0", blocked)
	}
}
