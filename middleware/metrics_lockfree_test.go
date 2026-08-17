package middleware

// Tests for the lock-free request path added in #120: the immutable views the
// request path reads instead of taking MetricsCollector.mu, and the coarse
// recency stamp that replaced an unconditional store per request.
//
// The performance claim itself lives in the benchmarks (bench_parallel_test.go,
// metrics_cardinality_test.go). What is pinned here is the correctness the views
// can silently lose: a view that outlives the live map it was cloned from hands
// out a detached counter, and every increment landing on it disappears from the
// exposition without any error, panic or race.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// fakeClock is a manually-advanced clock shared with a collector.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// totalCounted sums every counter series, i.e. how many requests the collector
// can still account for.
func totalCounted(c *MetricsCollector) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sum int64
	for _, ctr := range c.counters {
		sum += ctr.Load()
	}
	return sum
}

// A sweep deletes series from the live maps. Any view still in circulation that
// was cloned before the sweep keeps handing those deleted series out, and the
// increments landing on them are counted nowhere the exposition can see — the
// requests are silently dropped, which is precisely what the overflow series
// exists to prevent.
//
// The sequence below reaches the one place where the sweep runs and the caller
// then returns WITHOUT inserting anything, so republishing the views cannot be
// left to the insertion at the bottom of series():
//
//	MaxSeries 1, so the second distinct label materialises the overflow series;
//	the overflow series is kept fresh by folded traffic while the first label
//	goes idle; once the TTL elapses a folded request takes the locked path,
//	sweeps away the idle label, finds the store still full and the overflow
//	series still present, and returns it.
func TestMetricsCollector_SweepRepublishesViewsBeforeReturning(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     1,
		SeriesIdleTTL: time.Minute,
		now:           clk.Now,
	})
	h := mc.Metrics()(noopHandler())
	ctx := context.Background()
	w := server.NewResponseWriter(nil)

	send := func(path string) {
		_ = h.ServeHTTP(ctx, &server.Request{Method: "GET", Path: path}, w)
	}

	send("/a") // admitted: the single budgeted series
	send("/b") // folds: materialises the overflow series

	clk.advance(30 * time.Second)
	send("/b") // keeps the overflow series fresh while /a goes idle

	clk.advance(40 * time.Second) // now past the TTL: a sweep is due
	send("/b")                    // sweeps /a away, then returns the surviving overflow series

	// Everything before this point is accounted for or was deliberately
	// reclaimed by the sweep; only what happens after it is at stake.
	base := totalCounted(mc)

	// /a is gone from the live maps. A request for it must fold into the
	// overflow series, not land on the counter the sweep detached.
	const after = 2
	send("/a")
	send("/a")

	if got := totalCounted(mc); got != base+after {
		t.Fatalf("counters gained %d of the %d requests served after the sweep — a stale view kept handing out a series the sweep deleted, so those increments are invisible to every scrape", got-base, after)
	}
	if !strings.Contains(mc.WritePrometheus(), `path="`+OverflowLabel+`"`) {
		t.Fatalf("no overflow series in the exposition, so the folded requests were not counted:\n%s", mc.WritePrometheus())
	}
}

// The recency stamp is now written at a granularity rather than on every
// request, so the sweep must still see a continuously-served route as busy. A
// granularity that is not comfortably finer than the TTL would evict a route
// that never stopped receiving traffic — the metrics equivalent of losing a
// live connection to an idle timeout.
func TestMetricsCollector_BusySeriesSurvivesItsTTL(t *testing.T) {
	t.Parallel()

	const ttl = time.Minute
	clk := newFakeClock()
	mc := NewMetricsCollectorWithConfig(MetricsConfig{
		MaxSeries:     4,
		SeriesIdleTTL: ttl,
		now:           clk.Now,
	})
	h := mc.Metrics()(noopHandler())
	ctx := context.Background()
	w := server.NewResponseWriter(nil)

	// Serve /busy every second for five TTLs, and nothing else.
	const step = time.Second
	var sent int64
	for range int(5 * ttl / step) {
		_ = h.ServeHTTP(ctx, &server.Request{Method: "GET", Path: "/busy"}, w)
		sent++
		clk.advance(step)
	}

	// Force a sweep to run by introducing a new label after the TTL has elapsed
	// since the collector was created.
	_ = h.ServeHTTP(ctx, &server.Request{Method: "GET", Path: "/other"}, w)

	if got := mc.TotalRequests("GET", "/busy", 200); got != sent {
		t.Fatalf("TotalRequests(/busy) = %d, want %d — a route that was served every second was swept as idle, so its recency stamp is too coarse for the TTL", got, sent)
	}
}

// The lock-free path only exists if the views actually carry the labels a server
// is serving; a collector that never republishes them is still correct, just
// permanently back on the locked path, and no correctness test would notice.
func TestMetricsCollector_ViewsCarryTrackedLabels(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	h := mc.Metrics()(noopHandler())
	_ = h.ServeHTTP(context.Background(), &server.Request{
		Method: "POST", Path: "/v", Body: []byte("x"),
	}, server.NewResponseWriter(nil))

	v := mc.views.Load()
	dKey := durationKey("POST", "/v")
	for _, m := range []struct {
		name string
		ok   bool
	}{
		{"counters", contains(v.counters, counterKey("POST", "/v", 200))},
		{"durations", contains(v.durations, dKey)},
		{"reqBytes", contains(v.reqBytes, dKey)},
		{"histograms", containsHist(v.histograms, dKey)},
	} {
		if !m.ok {
			t.Errorf("%s view does not carry the label just served: the request path will take MetricsCollector.mu for every subsequent request", m.name)
		}
	}
}

func contains(m map[string]*seriesCounter, key string) bool { _, ok := m[key]; return ok }
func containsHist(m map[string]*histogram, key string) bool { _, ok := m[key]; return ok }

// The request path builds its keys in a fixed-size stack buffer. Request paths
// are attacker-chosen and unbounded in length, so a path that overruns the
// buffer must spill to the heap and keep the whole key — never be truncated into
// it. Truncation would make two distinct long paths share one series, which is a
// metrics-poisoning primitive handed to whoever picks the paths.
func TestMetricsCollector_LongPathsDoNotShareASeries(t *testing.T) {
	t.Parallel()

	prefix := "/" + strings.Repeat("a", 4*metricsKeyBufSize)
	mc := NewMetricsCollector()
	h := mc.Metrics()(noopHandler())
	ctx := context.Background()
	w := server.NewResponseWriter(nil)

	for i, p := range []string{prefix + "/one", prefix + "/two"} {
		for range i + 1 { // 1 request for the first path, 2 for the second
			_ = h.ServeHTTP(ctx, &server.Request{Method: "GET", Path: p}, w)
		}
	}

	if got := mc.TotalRequests("GET", prefix+"/one", 200); got != 1 {
		t.Errorf("TotalRequests(<long>/one) = %d, want 1 — the key was truncated into the scratch buffer, so two distinct paths collapsed onto one series", got)
	}
	if got := mc.TotalRequests("GET", prefix+"/two", 200); got != 2 {
		t.Errorf("TotalRequests(<long>/two) = %d, want 2", got)
	}
}

// Exposition must stay correct while the request path mutates the collector
// without holding its lock. Scraping concurrently with traffic must never lose a
// request, produce a malformed line, or race.
func TestMetricsCollector_ExpositionUnderConcurrentMutation(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 8
		perG       = 3000
		labels     = 32
	)
	mc := NewMetricsCollectorWithConfig(MetricsConfig{MaxSeries: 128, SeriesIdleTTL: -1})
	h := mc.Metrics()(noopHandler())

	stop := make(chan struct{})
	scrapes := make(chan int, 1)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				scrapes <- n
				return
			default:
			}
			out := mc.WritePrometheus()
			// Every line is either a comment or "name{labels} value"; a torn
			// build would show up as a line with no value.
			for _, line := range strings.Split(out, "\n") {
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if i := strings.LastIndexByte(line, ' '); i < 0 {
					t.Errorf("malformed exposition line under concurrent mutation: %q", line)
					return
				}
			}
			n++
		}
	}()

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			w := server.NewResponseWriter(nil)
			for i := range perG {
				_ = h.ServeHTTP(ctx, &server.Request{
					Method: "GET",
					Path:   "/c/" + strconv.Itoa((g*perG+i)%labels),
				}, w)
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	if n := <-scrapes; n == 0 {
		t.Fatal("the scraper never completed a scrape; the test did not exercise concurrency")
	}

	const want = goroutines * perG
	if got := totalCounted(mc); got != want {
		t.Fatalf("counters account for %d of %d requests served concurrently with scrapes", got, want)
	}
}
