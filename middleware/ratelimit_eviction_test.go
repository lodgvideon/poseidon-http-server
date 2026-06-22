package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newTestLimiter builds a keyedLimiter directly (white-box) so eviction can be
// driven deterministically via an injected clock. rate/burst are fixed; the
// refill-to-full time (burst/rate) is small so any ttl >= it leaves an idle
// bucket full.
func newTestLimiter(maxBuckets int, ttl time.Duration, sweepEvery uint64, clock func() time.Time) *keyedLimiter {
	return &keyedLimiter{
		rate:       100,
		burst:      10,
		now:        clock,
		maxBuckets: maxBuckets,
		ttl:        ttl,
		sweepEvery: sweepEvery,
		buckets:    make(map[string]*tokenBucket),
	}
}

func (l *keyedLimiter) hasKey(k string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.buckets[k]
	return ok
}

// The hard cap must evict the oldest-inserted bucket so the map size never
// exceeds maxBuckets, even under an unbounded stream of distinct keys.
func TestKeyedLimiter_HardCapEvictsOldest(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(4, 0, 0, clock) // cap 4, idle sweep disabled

	for _, k := range []string{"k0", "k1", "k2", "k3"} {
		lim.allow(k)
		now = now.Add(time.Millisecond)
	}
	if got := lim.bucketCount(); got != 4 {
		t.Fatalf("after 4 inserts: bucketCount = %d, want 4", got)
	}

	lim.allow("k4") // exceeds the cap -> evict the oldest (k0)
	if got := lim.bucketCount(); got != 4 {
		t.Fatalf("after cap-exceeding insert: bucketCount = %d, want 4 (capped)", got)
	}
	if lim.hasKey("k0") {
		t.Error("oldest key k0 should have been evicted at the cap")
	}
	if !lim.hasKey("k4") {
		t.Error("newest key k4 should be present")
	}
}

// Under a sustained flood the cap must hold for every insert, never letting the
// map grow past maxBuckets.
func TestKeyedLimiter_HardCapHoldsUnderFlood(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(16, 0, 0, clock)

	for i := range 10_000 {
		lim.allow(fmt.Sprintf("flood-%d", i))
		now = now.Add(time.Microsecond)
		if got := lim.bucketCount(); got > 16 {
			t.Fatalf("insert %d: bucketCount = %d exceeded cap 16", i, got)
		}
	}
	if got := lim.bucketCount(); got != 16 {
		t.Fatalf("final bucketCount = %d, want 16", got)
	}
}

// Buckets untouched past the TTL are reclaimed by the opportunistic sweep.
func TestKeyedLimiter_IdleSweepReclaims(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(0, time.Second, 1, clock) // unbounded cap, 1s TTL, sweep every insert

	for _, k := range []string{"a", "b", "c"} {
		lim.allow(k)
	}
	if got := lim.bucketCount(); got != 3 {
		t.Fatalf("after 3 inserts: bucketCount = %d, want 3", got)
	}

	now = now.Add(2 * time.Second) // a, b, c are now idle past the TTL
	lim.allow("trigger")           // a cold insert runs the sweep
	if got := lim.bucketCount(); got != 1 {
		t.Fatalf("after idle sweep: bucketCount = %d, want 1 (only 'trigger')", got)
	}
	if lim.hasKey("a") || lim.hasKey("b") || lim.hasKey("c") {
		t.Error("idle buckets a/b/c should have been swept")
	}
	if !lim.hasKey("trigger") {
		t.Error("'trigger' must remain")
	}
}

// A key touched within the TTL must survive a sweep even though other keys
// inserted at the same time are evicted — proves recency (not insert time)
// governs the sweep.
func TestKeyedLimiter_ActiveKeyNotSwept(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(0, time.Second, 1, clock)

	lim.allow("hot")
	lim.allow("cold")

	now = now.Add(600 * time.Millisecond)
	lim.allow("hot") // refresh hot's recency (a hit; does not insert/sweep)

	now = now.Add(600 * time.Millisecond) // t=1.2s: hot idle 0.6s (<ttl), cold idle 1.2s (>ttl)
	lim.allow("trigger")                  // cold insert -> sweep

	if !lim.hasKey("hot") {
		t.Error("active key 'hot' must NOT be swept (recent lastSeen)")
	}
	if lim.hasKey("cold") {
		t.Error("idle key 'cold' should have been swept")
	}
}

// The intrusive FIFO list must stay consistent with the map across a long mix of
// inserts, hits, cap evictions, and idle sweeps: every list node is in the map,
// the list length equals the map size, and head/tail terminate cleanly.
func TestKeyedLimiter_ListIntegrity(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(8, time.Second, 4, clock)

	for i := range 200 {
		lim.allow(fmt.Sprintf("k%d", i))
		now = now.Add(50 * time.Millisecond)
		if i%3 == 0 {
			lim.allow(fmt.Sprintf("k%d", i)) // a hit on an existing key
		}
	}

	lim.mu.Lock()
	defer lim.mu.Unlock()

	seen := 0
	for p := lim.head; p != nil; p = p.next {
		seen++
		if _, ok := lim.buckets[p.key]; !ok {
			t.Fatalf("list node %q is not in the map", p.key)
		}
		if seen > len(lim.buckets)+1 {
			t.Fatal("list longer than map — cycle or leak")
		}
	}
	if seen != len(lim.buckets) {
		t.Fatalf("list length %d != map size %d", seen, len(lim.buckets))
	}
	if lim.head != nil && lim.head.prev != nil {
		t.Error("head.prev must be nil")
	}
	if lim.tail != nil && lim.tail.next != nil {
		t.Error("tail.next must be nil")
	}
	if len(lim.buckets) > 8 {
		t.Errorf("map size %d exceeds cap 8", len(lim.buckets))
	}
}

// With the cap disabled (<0 sentinel resolved to internal 0) and no TTL, the map
// grows without eviction — the documented legacy/opt-out behaviour.
func TestKeyedLimiter_Unbounded(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	lim := newTestLimiter(0, 0, 0, clock) // 0 maxBuckets here means unbounded internally

	for i := range 1000 {
		lim.allow(fmt.Sprintf("k%d", i))
	}
	if got := lim.bucketCount(); got != 1000 {
		t.Fatalf("unbounded limiter: bucketCount = %d, want 1000", got)
	}
}

// Concurrent inserts of many distinct keys against a small cap must keep the map
// bounded with no race/panic (run under -race on CI).
func TestRateLimit_EvictionConcurrent(t *testing.T) {
	lim := newTestLimiter(50, time.Second, 8, time.Now) // real clock, small cap

	var wg sync.WaitGroup
	for g := range 50 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 200 {
				lim.allow(fmt.Sprintf("g%d-k%d", g, i))
			}
		}(g)
	}
	wg.Wait()

	if got := lim.bucketCount(); got > 50 {
		t.Fatalf("bucketCount = %d, want <= maxBuckets 50", got)
	}
}

func TestResolveMaxBuckets(t *testing.T) {
	if got := resolveMaxBuckets(0); got != DefaultMaxBuckets {
		t.Errorf("resolveMaxBuckets(0) = %d, want DefaultMaxBuckets %d", got, DefaultMaxBuckets)
	}
	if got := resolveMaxBuckets(-1); got != 0 {
		t.Errorf("resolveMaxBuckets(-1) = %d, want 0 (unbounded)", got)
	}
	if got := resolveMaxBuckets(123); got != 123 {
		t.Errorf("resolveMaxBuckets(123) = %d, want 123", got)
	}
}

func TestResolveIdleTTL(t *testing.T) {
	// Negative disables idle sweeping.
	if got := resolveIdleTTL(-1, 100, 10); got != 0 {
		t.Errorf("resolveIdleTTL(<0) = %v, want 0 (disabled)", got)
	}
	// Zero -> default floor when refill-to-full (0.1s) is below it.
	if got := resolveIdleTTL(0, 100, 10); got != DefaultBucketIdleTTL {
		t.Errorf("resolveIdleTTL(0) = %v, want default %v", got, DefaultBucketIdleTTL)
	}
	// An explicit TTL below the refill-to-full time is raised to it, so an
	// evicted idle bucket is always full. rate=1, burst=100 -> refill = 100s.
	if got := resolveIdleTTL(time.Second, 1, 100); got != 100*time.Second {
		t.Errorf("resolveIdleTTL raised to refill-to-full = %v, want 100s", got)
	}
}
