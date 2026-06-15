package conn

import "testing"

func TestPushIDCounter_GeneratesEvenIDs(t *testing.T) {
	t.Parallel()

	c := newPushIDCounter()

	want := []uint32{2, 4, 6, 8, 10}
	for i, w := range want {
		got := c.next()
		if got != w {
			t.Fatalf("ids[%d] = %d, want %d", i, got, w)
		}
	}
}

func TestPushIDCounter_ConcurrentSafe(t *testing.T) {
	t.Parallel()

	c := newPushIDCounter()

	done := make(chan uint32, 100)
	for range 100 {
		go func() {
			done <- c.next()
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

func TestPushIDCounter_StartsAtTwo(t *testing.T) {
	t.Parallel()

	c := newPushIDCounter()
	if got := c.next(); got != 2 {
		t.Fatalf("first push ID = %d, want 2", got)
	}
}

func TestErrPushDisabled(t *testing.T) {
	t.Parallel()
	if ErrPushDisabled == nil {
		t.Fatal("ErrPushDisabled is nil")
	}
	if ErrPushDisabled.Error() == "" {
		t.Fatal("ErrPushDisabled has empty message")
	}
}

func TestErrPushAfterResponse(t *testing.T) {
	t.Parallel()
	if ErrPushAfterResponse == nil {
		t.Fatal("ErrPushAfterResponse is nil")
	}
	if ErrPushAfterResponse.Error() == "" {
		t.Fatal("ErrPushAfterResponse has empty message")
	}
}
