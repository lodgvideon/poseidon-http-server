package middleware

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// noopHandler is the terminal handler used by the cardinality tests.
func noopHandler() server.Handler {
	return server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		return nil
	})
}

// seriesCounts returns the live entry count of each of the collector's four
// metric maps.
func seriesCounts(c *MetricsCollector) (counters, durations, histograms, reqBytes int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.counters), len(c.durations), len(c.histograms), len(c.reqBytes)
}

// drive sends n requests with distinct paths through the middleware.
func drive(h server.Handler, prefix string, n int) {
	ctx := context.Background()
	w := server.NewResponseWriter(nil)
	req := &server.Request{Method: "GET"}
	for i := range n {
		req.Path = prefix + strconv.Itoa(i)
		_ = h.ServeHTTP(ctx, req, w)
	}
}

// A flood of distinct attacker-chosen paths must settle at the configured bound
// instead of growing 1:1 with the request count. This is the regression test for
// issue #68: before the fix, 1e6 distinct paths produced 1e6 counter series,
// 1e6 duration series and 1e6 histograms (~400 MiB retained).
func TestMetricsCollector_SeriesCountSettlesAtBound(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector() // default bounds
	h := mc.Metrics()(noopHandler())

	const flood = 1_000_000
	drive(h, "/users/", flood)

	// MaxSeries real entries + the single overflow entry.
	const want = DefaultMaxSeries + 1

	counters, durations, histograms, reqBytes := seriesCounts(mc)
	for _, m := range []struct {
		name string
		got  int
	}{
		{"counters", counters},
		{"durations", durations},
		{"histograms", histograms},
	} {
		if m.got > want {
			t.Errorf("%s = %d series after %d distinct paths, want <= %d", m.name, m.got, flood, want)
		}
		if m.got < want {
			t.Errorf("%s = %d series, want the bound %d to be reached (test is not exercising overflow)", m.name, m.got, want)
		}
	}
	if reqBytes != 0 {
		t.Errorf("reqBytes = %d, want 0 (no bodies sent)", reqBytes)
	}
}

// Overflowing requests must be folded, never dropped: the overflow series
// carries every request past the cap and is visible in the exposition output
// under path="__other__".
func TestMetricsCollector_OverflowSeriesCountsFoldedRequests(t *testing.T) {
	t.Parallel()

	const cap0 = 8
	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     cap0,
		SeriesIdleTTL: -1, // isolate the cap: no idle reclamation
	})
	h := mc.Metrics()(noopHandler())

	const total = 100
	drive(h, "/p/", total)

	// The first cap0 distinct paths get their own series; the rest fold.
	wantFolded := int64(total - cap0)
	if got := mc.TotalRequests(OverflowLabel, OverflowLabel, 0); got != 0 {
		t.Fatalf("sanity: numeric-status overflow lookup returned %d, want 0", got)
	}

	mc.mu.RLock()
	ctr, ok := mc.counters[overflowCounterKey]
	mc.mu.RUnlock()
	if !ok {
		t.Fatalf("no overflow counter series after %d distinct paths with cap %d", total, cap0)
	}
	if got := ctr.Load(); got != wantFolded {
		t.Fatalf("overflow counter = %d, want %d (every request past the cap, none dropped)", got, wantFolded)
	}

	// Total accounting: no request may go unrecorded.
	var sum int64
	mc.mu.RLock()
	for _, c := range mc.counters {
		sum += c.Load()
	}
	mc.mu.RUnlock()
	if sum != total {
		t.Fatalf("counters sum to %d, want %d — requests were dropped, not folded", sum, total)
	}

	out := mc.WritePrometheus()
	if !strings.Contains(out, `path="`+OverflowLabel+`"`) {
		t.Fatalf("exposition output lacks the overflow series:\n%s", out)
	}
}

// The route-template hook must replace the concrete path, collapsing a flood of
// distinct paths onto one label so the cap is never approached.
func TestMetricsCollector_PathLabelHookCollapsesRoutes(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		PathLabel: func(req *server.Request) string {
			if strings.HasPrefix(req.Path, "/users/") {
				return "/users/{id}"
			}
			return req.Path
		},
	})
	h := mc.Metrics()(noopHandler())

	drive(h, "/users/", 50_000)

	counters, durations, histograms, _ := seriesCounts(mc)
	if counters != 1 || durations != 1 || histograms != 1 {
		t.Fatalf("counters=%d durations=%d histograms=%d, want 1 each (template collapses the label)",
			counters, durations, histograms)
	}
	if got := mc.TotalRequests("GET", "/users/{id}", 200); got != 50_000 {
		t.Fatalf("TotalRequests(/users/{id}) = %d, want 50000", got)
	}
	if got := mc.TotalRequests("GET", "/users/1", 200); got != 0 {
		t.Fatalf("concrete path still labelled: TotalRequests(/users/1) = %d, want 0", got)
	}
}

// An idle series must be reclaimed so its budget slot can be reused by a label
// first seen later — otherwise an early flood would hold the cap forever and
// every route deployed afterwards would be invisible.
func TestMetricsCollector_IdleSeriesEvictedAndSlotReused(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     4,
		SeriesIdleTTL: time.Minute,
		now:           clock,
	})
	h := mc.Metrics()(noopHandler())

	// Fill the budget exactly.
	drive(h, "/old/", 4)
	if counters, _, _, _ := seriesCounts(mc); counters != 4 {
		t.Fatalf("counters = %d after filling the budget, want 4", counters)
	}

	// Everything goes idle.
	advance(2 * time.Minute)

	// A newly-seen label must reclaim a slot rather than fold into overflow.
	drive(h, "/new/", 1)

	if got := mc.TotalRequests("GET", "/new/0", 200); got != 1 {
		t.Fatalf("TotalRequests(/new/0) = %d, want 1 — the new label folded into overflow instead of reusing an evicted slot", got)
	}
	if got := mc.TotalRequests("GET", "/old/0", 200); got != 0 {
		t.Fatalf("TotalRequests(/old/0) = %d, want 0 — the idle series was not evicted", got)
	}
	counters, durations, histograms, _ := seriesCounts(mc)
	if counters != 1 || durations != 1 || histograms != 1 {
		t.Fatalf("counters=%d durations=%d histograms=%d after the sweep, want 1 each", counters, durations, histograms)
	}
}

// A SUSTAINED flood is the case that freezes the label set: once the overflow
// series exists, every further unique path is answered without ever inserting,
// so a sweep gated on insertions would never fire again and the attacker's
// labels would hold the budget for the life of the process. The sweep must
// still come due on the fold path.
func TestMetricsCollector_SustainedFloodStillSweeps(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     2,
		SeriesIdleTTL: time.Minute,
		now:           clock,
	})
	h := mc.Metrics()(noopHandler())

	// Fill the budget AND materialise the overflow series, so the fold path is
	// fully warm and no further insertion would ever happen on its own.
	drive(h, "/attack/", 100)
	mc.mu.RLock()
	_, overflowExists := mc.counters[overflowCounterKey]
	mc.mu.RUnlock()
	if !overflowExists {
		t.Fatal("setup: overflow series was not materialised")
	}

	clockMu.Lock()
	now = now.Add(2 * time.Minute)
	clockMu.Unlock()

	// A real route deployed after the flood must become visible again.
	drive(h, "/legit/", 1)

	if got := mc.TotalRequests("GET", "/legit/0", 200); got != 1 {
		t.Fatalf("TotalRequests(/legit/0) = %d, want 1 — the label set froze: a sustained flood never inserts, so the sweep never came due", got)
	}
	if got := mc.TotalRequests("GET", "/attack/0", 200); got != 0 {
		t.Fatalf("TotalRequests(/attack/0) = %d, want 0 — the idle flood series survived the sweep", got)
	}
}

// With the TTL disabled the cap alone must still bound the maps — and a label
// first seen after the cap is reached must fold, not evict an existing one.
func TestMetricsCollector_CapAloneBoundsWithoutTTL(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollectorWithConfig(MetricsConfig{MaxSeries: 16, SeriesIdleTTL: -1})
	h := mc.Metrics()(noopHandler())

	drive(h, "/x/", 5000)

	counters, durations, histograms, _ := seriesCounts(mc)
	for name, got := range map[string]int{"counters": counters, "durations": durations, "histograms": histograms} {
		if got != 17 { // 16 + overflow
			t.Errorf("%s = %d, want 17 (MaxSeries 16 + overflow)", name, got)
		}
	}
	// The labels admitted first are retained.
	if got := mc.TotalRequests("GET", "/x/0", 200); got != 1 {
		t.Errorf("TotalRequests(/x/0) = %d, want 1 — an admitted series was evicted despite the TTL being disabled", got)
	}
}

// MaxSeries < 0 is the documented opt-out that restores the pre-fix unbounded
// behaviour for operators who need it.
func TestMetricsCollector_NegativeMaxSeriesIsUnbounded(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollectorWithConfig(MetricsConfig{MaxSeries: -1, SeriesIdleTTL: -1})
	h := mc.Metrics()(noopHandler())

	drive(h, "/u/", 5000)

	counters, durations, histograms, _ := seriesCounts(mc)
	if counters != 5000 || durations != 5000 || histograms != 5000 {
		t.Fatalf("counters=%d durations=%d histograms=%d, want 5000 each (MaxSeries<0 opts out of the cap)",
			counters, durations, histograms)
	}
}

// The bound must hold under concurrent floods, and the recency stamps the sweep
// reads must not race with the requests writing them. Run with -race.
func TestMetricsCollector_ConcurrentFloodStaysBounded(t *testing.T) {
	t.Parallel()

	const (
		maxSeries  = 64
		goroutines = 16
		perG       = 2000
	)
	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     maxSeries,
		SeriesIdleTTL: 50 * time.Microsecond, // force sweeps to run concurrently with hits
	})
	h := mc.Metrics()(noopHandler())

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			w := server.NewResponseWriter(nil)
			for i := range perG {
				req := &server.Request{
					Method: "GET",
					Path:   "/g" + strconv.Itoa(g) + "/" + strconv.Itoa(i),
					Body:   []byte("b"),
				}
				_ = h.ServeHTTP(ctx, req, w)
			}
		}(g)
	}
	wg.Wait()

	// Concurrent readers of the exposition path must also be race-free.
	_ = mc.WritePrometheus()

	counters, durations, histograms, reqBytes := seriesCounts(mc)
	for name, got := range map[string]int{
		"counters": counters, "durations": durations, "histograms": histograms, "reqBytes": reqBytes,
	} {
		if got > maxSeries+1 {
			t.Errorf("%s = %d after a concurrent flood, want <= %d", name, got, maxSeries+1)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — the metrics middleware sits on the per-request path, so it needs
// a RunParallel variant: a single-goroutine ns/op says nothing about the
// contention on MetricsCollector.mu.
// ---------------------------------------------------------------------------

func benchMetricsParallel(b *testing.B, distinctPaths int) {
	b.Helper()

	mc := NewMetricsCollector()
	h := mc.Metrics()(noopHandler())
	paths := make([]string, distinctPaths)
	for i := range paths {
		paths[i] = fmt.Sprintf("/bench/%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		w := server.NewResponseWriter(nil)
		req := &server.Request{Method: "GET"}
		i := 0
		for pb.Next() {
			req.Path = paths[i%distinctPaths]
			i++
			_ = h.ServeHTTP(ctx, req, w)
		}
	})
}

// Steady state: every label is already tracked, so the cap costs nothing beyond
// the recency stamp.
func BenchmarkMetricsMiddlewareParallel_Tracked(b *testing.B) {
	benchMetricsParallel(b, 16)
}

// Under attack: every path is new, so every request takes the cold path and
// folds into the overflow series.
func BenchmarkMetricsMiddlewareParallel_Overflow(b *testing.B) {
	mc := NewMetricsCollectorWithConfig(MetricsConfig{MaxSeries: 1, SeriesIdleTTL: -1})
	h := mc.Metrics()(noopHandler())

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		w := server.NewResponseWriter(nil)
		req := &server.Request{Method: "GET"}
		i := 0
		for pb.Next() {
			req.Path = "/flood/" + strconv.Itoa(i)
			i++
			_ = h.ServeHTTP(ctx, req, w)
		}
	})
}

func BenchmarkMetricsMiddleware_Tracked(b *testing.B) {
	mc := NewMetricsCollector()
	h := mc.Metrics()(noopHandler())
	ctx := context.Background()
	w := server.NewResponseWriter(nil)
	req := &server.Request{Method: "GET", Path: "/bench/0"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = h.ServeHTTP(ctx, req, w)
	}
}
