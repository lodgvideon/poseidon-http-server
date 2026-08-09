package conn

import "testing"

// The push identifier space moved from a standalone counter into streamTable,
// which allocates the identifier and registers the stream under one lock. These
// tests follow it there: the property under test — even, ascending, never
// duplicated under concurrency — is unchanged, and RFC 9113 §5.1.1 is where it
// comes from.

func newPushTable() *streamTable {
	return newStreamTable(func() uint32 { return connInitialRecvWindow })
}

func TestStreamTable_PushIDsAreEvenAndAscending(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	want := []uint32{2, 4, 6, 8, 10}
	for i, w := range want {
		got, ok := tbl.reservePush(&ServerStream{}, noStreamLimit)
		if !ok {
			t.Fatalf("reservePush #%d refused with no limit set", i)
		}
		if got != w {
			t.Fatalf("ids[%d] = %d, want %d", i, got, w)
		}
	}
}

func TestStreamTable_PushIDsConcurrentSafe(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	done := make(chan uint32, 100)
	for range 100 {
		go func() {
			id, ok := tbl.reservePush(&ServerStream{}, noStreamLimit)
			if !ok {
				id = 1 // odd: fails the parity assertion below
			}
			done <- id
		}()
	}

	seen := make(map[uint32]bool)
	for range 100 {
		id := <-done
		if id%2 != 0 {
			t.Fatalf("got odd ID %d", id)
		}
		if seen[id] {
			t.Fatalf("duplicate ID %d", id)
		}
		seen[id] = true
	}
}

// TestStreamTable_PushRefusalDoesNotBurnAnIdentifier pins the reason allocation
// and registration are one step. Allocating first and registering afterwards
// consumed an identifier even when the push was then refused, which makes
// isIdle report a never-reserved stream as non-idle — and §5.1 turns on exactly
// that distinction.
func TestStreamTable_PushRefusalDoesNotBurnAnIdentifier(t *testing.T) {
	t.Parallel()

	tbl := newPushTable()
	if _, ok := tbl.reservePush(&ServerStream{}, 1); !ok {
		t.Fatal("first push refused under a limit of 1")
	}
	if _, ok := tbl.reservePush(&ServerStream{}, 1); ok {
		t.Fatal("second push admitted over a limit of 1")
	}
	// Identifier 4 must still be idle: the refused push never reserved it.
	if !tbl.idle(4) {
		t.Error("identifier 4 is not idle after a refused push; the refusal consumed it")
	}
}
