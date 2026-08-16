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
