package middleware

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// countingHandler records how many times it was invoked.
type countingHandler struct {
	calls atomic.Int64
}

func (c *countingHandler) ServeHTTP(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
	c.calls.Add(1)
	return w.WriteHeaders(200, nil)
}

// ---------------------------------------------------------------------------
// Token bucket (unit)
// ---------------------------------------------------------------------------

func TestTokenBucket_BurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	// rate 10/s, burst 3.
	tb := newTokenBucket(10, 3, clock)

	// Burst of 3 should all pass on a full bucket.
	for i := range 3 {
		if !tb.allow() {
			t.Fatalf("token %d of burst should be allowed", i+1)
		}
	}
	// 4th is denied — bucket empty, no time elapsed.
	if tb.allow() {
		t.Fatal("4th token must be denied (bucket exhausted)")
	}

	// Advance 100ms → at 10/s that refills exactly 1 token.
	now = now.Add(100 * time.Millisecond)
	if !tb.allow() {
		t.Fatal("after 100ms one token must be available")
	}
	if tb.allow() {
		t.Fatal("only one token should have refilled")
	}
}

func TestTokenBucket_CapAtBurst(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	tb := newTokenBucket(10, 2, clock)

	// Idle a long time — tokens must cap at burst (2), not accumulate unbounded.
	now = now.Add(10 * time.Second)
	for i := range 2 {
		if !tb.allow() {
			t.Fatalf("token %d should be available after long idle", i+1)
		}
	}
	if tb.allow() {
		t.Fatal("tokens must be capped at burst=2")
	}
}

// ---------------------------------------------------------------------------
// RateLimit middleware
// ---------------------------------------------------------------------------

func TestRateLimit_BurstBeyondLimitYields429(t *testing.T) {
	h := &countingHandler{}
	now := time.Unix(0, 0)
	mw := RateLimit(RateLimitConfig{
		Rate:  1,
		Burst: 2,
		now:   func() time.Time { return now },
	})
	handler := mw(h)

	statuses := make([]int, 0, 5)
	for i := range 5 {
		w := newFakeRW()
		if err := handler.ServeHTTP(context.Background(), &server.Request{}, w); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		statuses = append(statuses, w.nativeStatus)
	}

	// First 2 pass through (burst), remaining 3 short-circuit with 429.
	if h.calls.Load() != 2 {
		t.Fatalf("next handler should run twice (burst), ran %d times", h.calls.Load())
	}
	wantPass, want429 := 0, 0
	for _, s := range statuses {
		switch s {
		case 200:
			wantPass++
		case 429:
			want429++
		default:
			t.Fatalf("unexpected status %d", s)
		}
	}
	if wantPass != 2 || want429 != 3 {
		t.Fatalf("want 2x200 + 3x429, got %d pass, %d limited (statuses=%v)", wantPass, want429, statuses)
	}
}

func TestRateLimit_UnderLimitPassesThrough(t *testing.T) {
	h := &countingHandler{}
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	mw := RateLimit(RateLimitConfig{Rate: 100, Burst: 1, now: clock})
	handler := mw(h)

	// Each request spaced by >=10ms (rate 100/s ⇒ 1 token / 10ms), all under the limit.
	for i := range 5 {
		w := newFakeRW()
		if err := handler.ServeHTTP(context.Background(), &server.Request{}, w); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if w.nativeStatus != 200 {
			t.Fatalf("request %d: want 200, got %d", i, w.nativeStatus)
		}
		now = now.Add(11 * time.Millisecond)
	}
	if h.calls.Load() != 5 {
		t.Fatalf("all 5 requests should pass, handler ran %d times", h.calls.Load())
	}
}

func TestRateLimit_PerKeyBucketsAreIndependent(t *testing.T) {
	h := &countingHandler{}
	now := time.Unix(0, 0)
	keyOf := func(_ context.Context, req *server.Request) string { return req.Authority }
	mw := RateLimit(RateLimitConfig{
		Rate:  1,
		Burst: 1,
		Key:   keyOf,
		now:   func() time.Time { return now },
	})
	handler := mw(h)

	send := func(key string) int {
		w := newFakeRW()
		if err := handler.ServeHTTP(context.Background(), &server.Request{Authority: key}, w); err != nil {
			t.Fatalf("serve: %v", err)
		}
		return w.nativeStatus
	}

	// Each key has its own burst-1 bucket: first request per key passes.
	if got := send("a"); got != 200 {
		t.Fatalf("key a first request: want 200, got %d", got)
	}
	if got := send("b"); got != 200 {
		t.Fatalf("key b first request: want 200, got %d", got)
	}
	// Second request to a is limited; key b stays unaffected.
	if got := send("a"); got != 429 {
		t.Fatalf("key a second request: want 429, got %d", got)
	}
}

func TestRateLimit_KeyByClientIP(t *testing.T) {
	h := &countingHandler{}
	now := time.Unix(0, 0)
	mw := RateLimit(RateLimitConfig{
		Rate:  1,
		Burst: 1,
		Key:   KeyByClientIP(),
		now:   func() time.Time { return now },
	})
	handler := mw(h)

	// send drives a request whose context carries the client IP the RealIP
	// middleware would have resolved (realIPCtxKey is what RealIP injects and
	// what ClientIP — used by KeyByClientIP — reads back).
	send := func(clientIP string) int {
		ctx := context.WithValue(context.Background(), realIPCtxKey{}, clientIP)
		w := newFakeRW()
		if err := handler.ServeHTTP(ctx, &server.Request{}, w); err != nil {
			t.Fatalf("serve: %v", err)
		}
		return w.nativeStatus
	}

	// Each client IP gets its own burst-1 bucket.
	if got := send("1.1.1.1"); got != 200 {
		t.Fatalf("client 1.1.1.1 first request: want 200, got %d", got)
	}
	if got := send("2.2.2.2"); got != 200 {
		t.Fatalf("client 2.2.2.2 first request: want 200, got %d", got)
	}
	// Second request from 1.1.1.1 is limited; 2.2.2.2 stays unaffected.
	if got := send("1.1.1.1"); got != 429 {
		t.Fatalf("client 1.1.1.1 second request: want 429, got %d", got)
	}
}

func TestRateLimit_DefaultsAndGlobalBucket(t *testing.T) {
	h := &countingHandler{}
	// Rate 0 ⇒ defaulted; explicit Burst 1, default global key.
	mw := RateLimit(RateLimitConfig{Rate: 0, Burst: 1})
	handler := mw(h)

	w1 := newFakeRW()
	_ = handler.ServeHTTP(context.Background(), &server.Request{Authority: "x"}, w1)
	w2 := newFakeRW()
	_ = handler.ServeHTTP(context.Background(), &server.Request{Authority: "y"}, w2)

	// Single global bucket regardless of key ⇒ second is limited.
	if w1.nativeStatus != 200 {
		t.Fatalf("first request want 200, got %d", w1.nativeStatus)
	}
	if w2.nativeStatus != 429 {
		t.Fatalf("second request (different authority, global bucket) want 429, got %d", w2.nativeStatus)
	}
}

func TestRateLimit_ConcurrentSafe(t *testing.T) {
	h := &countingHandler{}
	mw := RateLimit(RateLimitConfig{Rate: 1000, Burst: 50})
	handler := mw(h)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := newFakeRW()
			_ = handler.ServeHTTP(context.Background(), &server.Request{}, w)
		}()
	}
	wg.Wait()
	// Just assert no panic/race and that some requests were admitted.
	if h.calls.Load() == 0 {
		t.Fatal("expected at least one admitted request")
	}
}
