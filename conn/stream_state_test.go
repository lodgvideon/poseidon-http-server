package conn

import (
	"sync"
	"testing"
)

// The state exists so that the questions callers used to compose out of five
// booleans have one answer each. These tests pin the answers, and the two
// properties the composition could not give: that a transition reports its own
// edge, and that concurrent transitions elect exactly one winner.

func TestStreamState_ClosedIsClosedWhicheverWay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		bits     streamState
		terminal bool
		writable bool
	}{
		// RFC 9113 §5.1: a client-initiated stream is admitted "open".
		{"open", 0, false, true},
		{"open, request received", stRecvFields, false, true},
		// §5.1 half-closed (remote): the peer is done, this endpoint is not.
		{"half-closed (remote)", stRecvFields | stRecvEnded, false, true},
		// §5.1 half-closed (local): this endpoint is done, the peer is not. Not
		// writable — §5.1 (rfc9113.txt:1069) allows only WINDOW_UPDATE, PRIORITY
		// and RST_STREAM after END_STREAM, none of which go through SendData.
		{"half-closed (local)", stSentFields | stSentEnded, false, false},
		// §5.1 closed, the ordinary way: both halves ended.
		{"closed, both halves ended", stRecvEnded | stSentEnded, true, false},
		// §5.1 closed, the other way. A reset closes BOTH halves however little
		// has crossed — this is the case the old `closed || localEnded` had to
		// spell out at every call site, and the case each of the three shipped
		// defects got wrong in a different place.
		{"closed by reset, nothing sent", stReset, true, false},
		{"closed by reset mid-response", stRecvFields | stSentFields | stReset, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.bits.Terminal(); got != tc.terminal {
				t.Errorf("Terminal() = %v, want %v", got, tc.terminal)
			}
			if got := tc.bits.Writable(); got != tc.writable {
				t.Errorf("Writable() = %v, want %v", got, tc.writable)
			}
		})
	}
}

// TestStreamState_AdvanceReportsTheEdge pins what every caller actually asks:
// not "is the stream reset" but "was this the reset that closed it". Close and
// the event-overflow path both send RST_STREAM only on the first transition,
// because §5.4.2 (rfc9113.txt:1201) says an endpoint "SHOULD NOT send more than
// one RST_STREAM frame for any stream".
func TestStreamState_AdvanceReportsTheEdge(t *testing.T) {
	t.Parallel()

	ss := &ServerStream{}
	if before := ss.advance(stReset); before.WasReset() {
		t.Error("the first reset reported the stream as already reset")
	}
	if before := ss.advance(stReset); !before.WasReset() {
		t.Error("the second reset reported itself as the first; a duplicate RST_STREAM follows")
	}
	if !ss.state().Terminal() {
		t.Error("a reset stream is not terminal")
	}
}

// TestStreamState_ExactlyOneHalfCloserSeesTheClose pins the invariant that
// makes markStreamDone safe to call from whichever half finishes last.
//
// The two halves end from different goroutines — the reader records END_STREAM
// received, a handler records END_STREAM sent — and each returns "the stream is
// now fully closed" so its caller can release it. Both returning true releases
// the stream twice; both returning false leaks it, and a leaked stream keeps
// ActiveStreams above zero for the life of the connection, so IdleTimeout can
// never reap it.
func TestStreamState_ExactlyOneHalfCloserSeesTheClose(t *testing.T) {
	t.Parallel()

	for range 2000 {
		ss := &ServerStream{}
		var remote, local bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); remote = ss.markRemoteEnd() }()
		go func() { defer wg.Done(); local = ss.markLocalEnd() }()
		wg.Wait()

		if remote == local {
			t.Fatalf("markRemoteEnd = %v, markLocalEnd = %v: the stream was %s", remote, local,
				map[bool]string{true: "released twice", false: "never released"}[remote])
		}
		if !ss.state().Terminal() {
			t.Fatal("both halves ended but the stream is not terminal")
		}
	}
}
