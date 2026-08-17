package middleware

// Parallel benchmarks for MetricsCollector (issue #95).
//
// CLAUDE.md names MetricsCollector.mu as one of four sites to weigh against the
// "locks cost more than allocations" rule: "four map lookups per request". Every
// request that passes through the Metrics middleware takes c.mu three or four
// times — once per map — and in steady state each of those is an RLock hit, so
// the question is whether a shared RWMutex read path costs anything at 16 cores.
//
// Sweep with -cpu to see it:
//
//	go test -run='^$' -bench='Parallel' -benchmem \
//	        -benchtime=500ms -count=10 -cpu=1,2,4,8,16 ./middleware

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// benchParRW is a no-op server.ResponseWriter: the metrics middleware only reads
// StatusCode() off it, and a stub keeps the transport out of the measurement.
type benchParRW struct{ hdr http.Header }

func (w *benchParRW) Header() http.Header {
	if w.hdr == nil {
		w.hdr = make(http.Header)
	}
	return w.hdr
}
func (w *benchParRW) Write(p []byte) (int, error)                 { return len(p), nil }
func (w *benchParRW) WriteHeader(int)                             {}
func (w *benchParRW) WriteHeaders(int, []hpack.HeaderField) error { return nil }
func (w *benchParRW) WriteData([]byte) error                      { return nil }
func (w *benchParRW) WriteTrailers([]hpack.HeaderField) error     { return nil }
func (w *benchParRW) Status() int                                 { return http.StatusOK }
func (w *benchParRW) StatusCode() int                             { return http.StatusOK }
func (w *benchParRW) Written() bool                               { return true }

// BenchmarkMetricsMiddleware_Parallel drives the real Metrics middleware, which
// is the production path: counter, duration and histogram lookups under
// MetricsCollector.mu on every request.
//
// The keys are pre-created before the timed region, so this measures the steady
// state (all RLock fast-path hits), not first-sight map growth under the write
// lock.
func BenchmarkMetricsMiddleware_Parallel(b *testing.B) {
	c := NewMetricsCollector()
	next := server.HandlerFunc(func(context.Context, *server.Request, server.ResponseWriter) error {
		return nil
	})
	h := c.Metrics()(next)

	req := &server.Request{Method: http.MethodGet, Path: "/bench"}
	ctx := context.Background()

	// Warm the maps so the timed region never takes the write lock.
	_ = h.ServeHTTP(ctx, req, &benchParRW{})

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := &benchParRW{}
		for pb.Next() {
			if err := h.ServeHTTP(ctx, req, w); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkMetricsObserveDuration_Parallel isolates ONE of the four lookups, so
// the middleware number above can be attributed: if this scales and the
// middleware does not, the cost is the repetition, not the map.
func BenchmarkMetricsObserveDuration_Parallel(b *testing.B) {
	c := NewMetricsCollector()
	c.ObserveDuration(http.MethodGet, "/bench", time.Millisecond) // warm the map

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.ObserveDuration(http.MethodGet, "/bench", time.Millisecond)
		}
	})
}

// fullCollector returns a collector holding the maximum number of series the
// default bounds admit, which is the worst case for a scrape.
func fullCollector(b *testing.B) *MetricsCollector {
	b.Helper()
	c := NewMetricsCollector()
	h := c.Metrics()(server.HandlerFunc(func(context.Context, *server.Request, server.ResponseWriter) error {
		return nil
	}))
	ctx := context.Background()
	w := &benchParRW{}
	for i := range DefaultMaxSeries {
		_ = h.ServeHTTP(ctx, &server.Request{
			Method: http.MethodGet,
			Path:   "/route/" + strconv.Itoa(i),
			Body:   []byte("b"),
		}, w)
	}
	return c
}

// BenchmarkMetricsWritePrometheus_FullCollector is the measurement issue #109
// asked for and did not have: WritePrometheus holds the collector read lock for
// the entire exposition build, so this ns/op IS the lock hold, on the largest
// collector the default cardinality bound allows (DefaultMaxSeries series in
// each of four maps, ~14 exposition lines per histogram).
//
// What that hold blocks is the write lock — inserting a first-sight series and
// running the idle sweep. Weigh it against the scrape interval, not against a
// request: at a 15s interval a hold of h seconds delays insertions for h/15 of
// the time.
func BenchmarkMetricsWritePrometheus_FullCollector(b *testing.B) {
	c := fullCollector(b)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		sink = c.WritePrometheus()
	}
}

var sink string

// scrapeInBackground runs WritePrometheus in a loop until the returned stop
// function is called, which it waits for the scraper to observe.
func scrapeInBackground(c *MetricsCollector) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-quit:
				return
			default:
			}
			sink = c.WritePrometheus()
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}

// BenchmarkMetricsWriteLockDuringScrape times the ONE thing a scrape blocks:
// acquiring the write lock, which is what creating a first-sight series, running
// the idle sweep and republishing the lock-free views all have to do (issue
// #109). The collector is pre-filled to the default bound, so each background
// scrape is a full-size exposition build.
//
// Taking and immediately releasing the lock is the whole iteration on purpose:
// inserting real series instead would grow the collector without bound as the
// benchmark ran, which changes the cost of the very scrape being measured.
//
// Read it against BenchmarkMetricsWritePrometheus_FullCollector: if the
// exposition is built under the lock, every acquisition is a coin-flip on
// landing inside a ~10ms hold; if it is built from a snapshot, the wait is only
// the snapshot.
func BenchmarkMetricsWriteLockDuringScrape(b *testing.B) {
	c := fullCollector(b)
	stop := scrapeInBackground(c)
	defer stop()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		c.mu.Lock()
		//nolint:staticcheck // the empty critical section IS the measurement
		c.mu.Unlock()
	}
}

// BenchmarkMetricsMiddlewareParallel_TrackedDuringScrape is the other half of
// #109: the steady-state request path measured while a scraper hammers the
// exposition build in the background. Compared against
// BenchmarkMetricsMiddlewareParallel_Tracked it says whether a concurrent scrape
// is visible from the request path at all.
func BenchmarkMetricsMiddlewareParallel_TrackedDuringScrape(b *testing.B) {
	c := fullCollector(b)
	h := c.Metrics()(server.HandlerFunc(func(context.Context, *server.Request, server.ResponseWriter) error {
		return nil
	}))

	stop := scrapeInBackground(c)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		w := &benchParRW{}
		req := &server.Request{Method: http.MethodGet, Path: "/route/0"}
		for pb.Next() {
			_ = h.ServeHTTP(ctx, req, w)
		}
	})
	b.StopTimer()
	stop()
}
