package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Metrics — Prometheus-style request counters and histograms
// ---------------------------------------------------------------------------

// MetricsCollector tracks request-level metrics in a thread-safe manner.
// The data can be exposed via Prometheus, OpenMetrics, or simple /metrics scraping.
type MetricsCollector struct {
	mu sync.RWMutex

	// requestCount tracks total requests by method+path+status.
	counters map[string]*atomic.Int64

	// requestDuration tracks total duration (nanoseconds) by method+path.
	durations map[string]*atomic.Int64

	// requestBytes tracks total request body bytes by method+path.
	reqBytes map[string]*atomic.Int64

	// responseBytes tracks total response body bytes by method+path.
	respBytes map[string]*atomic.Int64

	// activeRequests tracks in-flight requests.
	active atomic.Int64
}

// NewMetricsCollector creates an empty MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		counters:  make(map[string]*atomic.Int64),
		durations: make(map[string]*atomic.Int64),
		reqBytes:  make(map[string]*atomic.Int64),
		respBytes: make(map[string]*atomic.Int64),
	}
}

// counterKey returns the metrics key for a request.
func counterKey(method, path string, status int) string {
	return fmt.Sprintf("%s|%s|%d", method, path, status)
}

// durationKey returns the metrics key for duration tracking.
func durationKey(method, path string) string {
	return method + "|" + path
}

// getOrCreateCounter returns an existing counter or creates a new one.
func (c *MetricsCollector) getOrCreateCounter(key string) *atomic.Int64 {
	c.mu.RLock()
	if ctr, ok := c.counters[key]; ok {
		c.mu.RUnlock()
		return ctr
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check.
	if ctr, ok := c.counters[key]; ok {
		return ctr
	}
	ctr := &atomic.Int64{}
	c.counters[key] = ctr
	return ctr
}

// getOrCreateDuration returns an existing duration counter or creates one.
func (c *MetricsCollector) getOrCreateDuration(key string) *atomic.Int64 {
	c.mu.RLock()
	if ctr, ok := c.durations[key]; ok {
		c.mu.RUnlock()
		return ctr
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok := c.durations[key]; ok {
		return ctr
	}
	ctr := &atomic.Int64{}
	c.durations[key] = ctr
	return ctr
}

// getOrCreateBytes returns an existing bytes counter or creates one.
func (c *MetricsCollector) getOrCreateBytes(store map[string]*atomic.Int64, key string) *atomic.Int64 {
	c.mu.RLock()
	if ctr, ok := store[key]; ok {
		c.mu.RUnlock()
		return ctr
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok := store[key]; ok {
		return ctr
	}
	ctr := &atomic.Int64{}
	store[key] = ctr
	return ctr
}

// Metrics returns a middleware that collects request metrics.
func (c *MetricsCollector) Metrics() server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w *server.ResponseWriter) error {
			c.active.Add(1)
			defer c.active.Add(-1)

			start := time.Now()
			err := next.ServeHTTP(ctx, req, w)
			elapsed := time.Since(start)

			status := w.StatusCode()
			if status == 0 {
				status = 200
			}

			// Increment request counter.
			key := counterKey(req.Method, req.Path, status)
			c.getOrCreateCounter(key).Add(1)

			// Record duration.
			dKey := durationKey(req.Method, req.Path)
			c.getOrCreateDuration(dKey).Add(int64(elapsed))

			// Record request body size.
			if len(req.Body) > 0 {
				c.getOrCreateBytes(c.reqBytes, dKey).Add(int64(len(req.Body)))
			}

			return err
		})
	}
}

// ActiveRequests returns the number of in-flight requests.
func (c *MetricsCollector) ActiveRequests() int64 {
	return c.active.Load()
}

// TotalRequests returns total request count for a given method+path+status.
func (c *MetricsCollector) TotalRequests(method, path string, status int) int64 {
	key := counterKey(method, path, status)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if ctr, ok := c.counters[key]; ok {
		return ctr.Load()
	}
	return 0
}

// TotalDuration returns total accumulated duration for a method+path.
func (c *MetricsCollector) TotalDuration(method, path string) time.Duration {
	key := durationKey(method, path)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if ctr, ok := c.durations[key]; ok {
		return time.Duration(ctr.Load())
	}
	return 0
}

// WritePrometheus writes metrics in Prometheus text exposition format.
// This can be served directly at /metrics via an http.Handler.
func (c *MetricsCollector) WritePrometheus() string {
	var sb strings.Builder

	sb.WriteString("# HELP poseidon_requests_total Total HTTP requests by method, path, and status.\n")
	sb.WriteString("# TYPE poseidon_requests_total counter\n")

	c.mu.RLock()
	defer c.mu.RUnlock()

	for key, ctr := range c.counters {
		// Parse method|path|status from key.
		parts := strings.SplitN(key, "|", 3)
		if len(parts) != 3 {
			continue
		}
		fmt.Fprintf(&sb, "poseidon_requests_total{method=%q,path=%q,status=%q} %d\n",
			parts[0], parts[1], parts[2], ctr.Load())
	}

	sb.WriteString("\n# HELP poseidon_request_duration_seconds_total Total request duration.\n")
	sb.WriteString("# TYPE poseidon_request_duration_seconds_total counter\n")
	for key, ctr := range c.durations {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		seconds := float64(ctr.Load()) / float64(time.Second)
		fmt.Fprintf(&sb, "poseidon_request_duration_seconds_total{method=%q,path=%q} %.9f\n",
			parts[0], parts[1], seconds)
	}

	sb.WriteString("\n# HELP poseidon_active_requests Current in-flight requests.\n")
	sb.WriteString("# TYPE poseidon_active_requests gauge\n")
	fmt.Fprintf(&sb, "poseidon_active_requests %d\n", c.active.Load())

	return sb.String()
}

// MetricsHandler returns an http.Handler-compatible server.HandlerFunc
// that serves the Prometheus text exposition format at /metrics.
func (c *MetricsCollector) MetricsHandler() server.HandlerFunc {
	return server.HandlerFunc(func(_ context.Context, _ *server.Request, w *server.ResponseWriter) error {
		body := []byte(c.WritePrometheus())
		headers := []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("text/plain; version=0.0.4; charset=utf-8")},
		}
		if err := w.WriteHeaders(http.StatusOK, headers); err != nil {
			return err
		}
		return w.WriteData(body)
	})
}
