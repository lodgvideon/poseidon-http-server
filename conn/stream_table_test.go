package conn

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// The table exists to answer, once, the questions 56 call sites used to compose
// out of a map, a mutex and two counters. These tests pin the answers — and the
// three defect shapes that composition produced.

func TestStreamTable_IdleIsParityAware(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	// Nothing opened: every identifier is idle.
	for _, id := range []uint32{1, 2, 3, 4, 99} {
		if !tbl.idle(id) {
			t.Errorf("id %d should be idle on a fresh connection", id)
		}
	}

	tbl.admitClient(3, &ServerStream{id: 3}, 0)
	// Odd identifiers up to the highest admitted are no longer idle...
	for _, id := range []uint32{1, 3} {
		if tbl.idle(id) {
			t.Errorf("odd id %d should not be idle after admitting 3", id)
		}
	}
	if !tbl.idle(5) {
		t.Error("odd id 5 should still be idle")
	}
	// ...and the even space is untouched by a client stream. Answering both
	// parities from one counter — which the handler mock did — makes every push
	// identifier look used the moment a client stream arrives.
	if !tbl.idle(2) {
		t.Error("even id 2 should still be idle: a client stream does not consume the push space")
	}
}

// TestStreamTable_LastPeerIDIsNeverAServerStream pins RFC 9113 §6.8 with
// §5.1.1. This is the shipped defect: the answer used to come from a scan that
// omitted the parity filter its two neighbours applied.
func TestStreamTable_LastPeerIDIsNeverAServerStream(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	tbl.admitClient(1, &ServerStream{id: 1}, 0)
	for range 5 {
		if _, ok := tbl.reservePush(&ServerStream{}, noStreamLimit); !ok {
			t.Fatal("push refused with no limit")
		}
	}
	if got := tbl.lastPeerID(); got != 1 {
		t.Errorf("lastPeerID = %d, want 1: push streams are server-initiated and can "+
			"never be the last stream the PEER opened", got)
	}
}

// TestStreamTable_RefusalStillConsumesTheIdentifier pins §5.1.1 — an identifier
// may not be reused whether or not the stream was accepted.
func TestStreamTable_RefusalStillConsumesTheIdentifier(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	tbl.admitClient(1, &ServerStream{id: 1}, 1)
	if ok := tbl.admitClient(3, &ServerStream{id: 3}, 1); ok {
		t.Fatal("second client stream admitted over a limit of 1")
	}
	if tbl.idle(3) {
		t.Error("identifier 3 is idle after being refused; §5.1.1 forbids reusing it")
	}
	if err := tbl.validateClientID(3); err == nil {
		t.Error("identifier 3 accepted again after a refusal")
	}
}

// TestStreamTable_CountsAreByParity pins what the two O(n) scans used to do,
// and why they were counted apart: the limit this server advertises governs the
// client, and the peer's limit governs this server's pushes.
func TestStreamTable_CountsAreByParity(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	tbl.admitClient(1, &ServerStream{id: 1}, 2)
	pushed, _ := tbl.reservePush(&ServerStream{}, noStreamLimit)

	// A push must not consume the client's allowance...
	if ok := tbl.admitClient(3, &ServerStream{id: 3}, 2); !ok {
		t.Error("a client stream was refused because a push stream was counted against its limit")
	}
	// ...nor the other way round.
	if _, ok := tbl.reservePush(&ServerStream{}, 2); !ok {
		t.Error("a push was refused because client streams were counted against the peer's limit")
	}
	if got := tbl.live(); got != 4 {
		t.Errorf("live = %d, want 4", got)
	}
	if s := tbl.release(pushed); s == nil {
		t.Error("release of a live push stream returned nil")
	}
	if got := tbl.live(); got != 3 {
		t.Errorf("live after release = %d, want 3", got)
	}
	if s := tbl.release(pushed); s != nil {
		t.Error("releasing an already-released identifier returned a stream")
	}
}

// TestStreamTable_WindowSeedingIsAtomicWithTheRetroactiveDelta pins the reason
// admission reads the peer's window under the table lock and applyInitialWindow
// publishes under the same one.
//
// Seeding and the §6.9.2 walk as two separate steps leave a gap: a stream
// admitted after the new value is visible but before the walk gets the delta
// twice, so the server believes it may send more than the peer allowed — which
// §6.9.1 obliges the peer to answer with a connection error. The mirror gap
// loses the delta entirely and pins the stream at the stale window.
//
// Every stream here must end at exactly the new initial window, however the
// admissions and the change interleave.
func TestStreamTable_WindowSeedingIsAtomicWithTheRetroactiveDelta(t *testing.T) {
	t.Parallel()

	const (
		oldWin = 65535
		newWin = 1 << 20
		n      = 64
	)
	for range 200 {
		var mu sync.Mutex
		current := uint32(oldWin)
		tbl := newStreamTable(func() uint32 {
			mu.Lock()
			defer mu.Unlock()
			return current
		})

		streams := make([]*ServerStream, n)
		for i := range streams {
			streams[i] = &ServerStream{id: uint32(2*i + 1)} //nolint:gosec // G115: i < n
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i, s := range streams {
				tbl.admitClient(uint32(2*i+1), s, 0) //nolint:gosec // G115: i < n
			}
		}()
		go func() {
			defer wg.Done()
			_ = tbl.applyInitialWindow(
				func() (uint32, uint32) {
					mu.Lock()
					defer mu.Unlock()
					old := current
					current = newWin
					return old, newWin
				},
				func(s *ServerStream, delta int64) error {
					s.mu.Lock()
					defer s.mu.Unlock()
					s.sendWindow += int32(delta) //nolint:gosec // G115: bounded by the test's values
					return nil
				})
		}()
		wg.Wait()

		for i, s := range streams {
			s.mu.Lock()
			got := s.sendWindow
			s.mu.Unlock()
			if got != newWin {
				t.Fatalf("stream %d send window = %d, want %d: seeding and the retroactive "+
					"delta interleaved, so the window was %s", i, got, newWin,
					map[bool]string{true: "double-credited", false: "left stale"}[got > newWin])
			}
		}
	}
}

// failWritesConn lets a test break the write side of a connection without
// breaking the read side, so the reader goroutine stays alive and the failure
// stays scoped to the one frame under test.
type failWritesConn struct {
	net.Conn
	fail atomic.Bool
}

func (c *failWritesConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("write refused by the test")
	}
	return c.Conn.Write(p)
}

// TestStreamTable_FailedPushWriteReturnsTheReservation pins the cost of moving
// registration ahead of the frame write.
//
// reservePush registers and counts the stream before PUSH_PROMISE reaches the
// wire, so a write that then fails must give the reservation back. Leaving it
// behind kept ActiveStreams above zero for the life of the connection — the
// exact predicate IdleTimeout uses to decide a connection is busy, so it could
// never be reaped — and permanently spent one of the peer's
// SETTINGS_MAX_CONCURRENT_STREAMS slots.
func TestStreamTable_FailedPushWriteReturnsTheReservation(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	failing := &failWritesConn{Conn: srv}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
						return
					}
				}
			}()
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			time.Sleep(2 * time.Second)
		})
	}()

	sc, err := NewServerConn(ctx, failing, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	before := sc.ActiveStreams()

	// From here every frame this server writes fails; the connection is otherwise
	// untouched and the reader goroutine keeps running.
	failing.fail.Store(true)

	for i := range 5 {
		if _, perr := stream.Push(ctx, goodHeaders("/asset.css")); perr == nil {
			t.Fatalf("push #%d succeeded although every write fails", i+1)
		}
	}

	if got := sc.ActiveStreams(); got != before {
		t.Errorf("ActiveStreams = %d after 5 failed pushes, want %d: each failure left its "+
			"reservation in the table, so the connection can never be reaped and the "+
			"peer's push allowance is spent", got, before)
	}
}
