package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// defaultDurationBuckets are the upper bounds (in seconds) for the request
// duration histogram. They mirror Prometheus' client default buckets and span
// 5ms .. 10s. The implicit +Inf bucket is added at exposition time.
var defaultDurationBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// histogram holds per-bucket cumulative-eligible counts plus a running sum and
// total observation count. Buckets are NOT pre-accumulated; the cumulative
// values are computed at exposition time. counts[i] is the number of
// observations whose value is <= buckets[i] but > buckets[i-1] (i.e. the count
// for the narrowest bucket the observation falls into). count is the grand
// total (== +Inf bucket). sumNanos is the running sum in nanoseconds, kept as
// an integer to stay allocation- and precision-friendly on the hot path.
type histogram struct {
	buckets  []float64
	counts   []atomic.Int64 // len == len(buckets); index of the matching bucket
	infCount atomic.Int64   // observations exceeding the largest bucket bound
	sumNanos atomic.Int64
	count    atomic.Int64
}

func newHistogram(buckets []float64) *histogram {
	return &histogram{
		buckets: buckets,
		counts:  make([]atomic.Int64, len(buckets)),
	}
}

// observe records a single duration. It is allocation-free: the bucket index is
// found via binary search and all updates are atomic.
func (h *histogram) observe(d time.Duration) {
	seconds := d.Seconds()
	// sort.SearchFloat64s returns the smallest index i such that buckets[i] >= seconds.
	i := sort.SearchFloat64s(h.buckets, seconds)
	if i < len(h.buckets) {
		h.counts[i].Add(1)
	} else {
		h.infCount.Add(1)
	}
	h.sumNanos.Add(int64(d))
	h.count.Add(1)
}

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

	// histograms tracks request-duration distributions by method+path,
	// completing the RED method (Rate/Errors/Duration).
	histograms map[string]*histogram

	// activeRequests tracks in-flight requests.
	active atomic.Int64

	// transportSrc, when set via SetTransportSource, supplies HTTP/2 transport
	// counters (bytes/frames/streams, rapid-resets, GOAWAYs, active conns) for
	// exposition. Guarded by mu like the maps above.
	transportSrc func() server.TransportStats
}

// NewMetricsCollector creates an empty MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		counters:   make(map[string]*atomic.Int64),
		durations:  make(map[string]*atomic.Int64),
		reqBytes:   make(map[string]*atomic.Int64),
		histograms: make(map[string]*histogram),
	}
}

// SetTransportSource registers a provider of HTTP/2 transport counters (e.g.
// (*server.Server).TransportStats) so WritePrometheus can export connection,
// byte, frame, stream, rapid-reset, and GOAWAY metrics alongside the per-request
// ones. Pass nil to disable transport exposition. Safe for concurrent use.
func (c *MetricsCollector) SetTransportSource(src func() server.TransportStats) {
	c.mu.Lock()
	c.transportSrc = src
	c.mu.Unlock()
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

// getOrCreateHistogram returns an existing histogram or creates one.
func (c *MetricsCollector) getOrCreateHistogram(key string) *histogram {
	c.mu.RLock()
	if h, ok := c.histograms[key]; ok {
		c.mu.RUnlock()
		return h
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.histograms[key]; ok {
		return h
	}
	h := newHistogram(defaultDurationBuckets)
	c.histograms[key] = h
	return h
}

// ObserveDuration records a single request duration into the per-method+path
// latency histogram. It is allocation-light: the histogram lookup uses the
// shared RWMutex only on first sight of a key; the observation itself is
// atomic and lock-free.
func (c *MetricsCollector) ObserveDuration(method, path string, d time.Duration) {
	c.getOrCreateHistogram(durationKey(method, path)).observe(d)
}

// Metrics returns a middleware that collects request metrics.
func (c *MetricsCollector) Metrics() server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
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

			// Record duration (total) and latency histogram.
			dKey := durationKey(req.Method, req.Path)
			c.getOrCreateDuration(dKey).Add(int64(elapsed))
			c.getOrCreateHistogram(dKey).observe(elapsed)

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

	sb.WriteString("\n# HELP poseidon_request_bytes_total Total request body bytes by method and path.\n")
	sb.WriteString("# TYPE poseidon_request_bytes_total counter\n")
	for key, ctr := range c.reqBytes {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		fmt.Fprintf(&sb, "poseidon_request_bytes_total{method=%q,path=%q} %d\n",
			parts[0], parts[1], ctr.Load())
	}

	sb.WriteString("\n# HELP poseidon_request_duration_seconds Request latency distribution in seconds.\n")
	sb.WriteString("# TYPE poseidon_request_duration_seconds histogram\n")
	for key, h := range c.histograms {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		method, path := parts[0], parts[1]

		// Emit cumulative bucket counts in ascending le order.
		var cumulative int64
		for i, ub := range h.buckets {
			cumulative += h.counts[i].Load()
			fmt.Fprintf(&sb,
				"poseidon_request_duration_seconds_bucket{method=%q,path=%q,le=%q} %d\n",
				method, path, formatBucketBound(ub), cumulative)
		}
		// The +Inf bucket includes every observation.
		total := h.count.Load()
		fmt.Fprintf(&sb,
			"poseidon_request_duration_seconds_bucket{method=%q,path=%q,le=\"+Inf\"} %d\n",
			method, path, total)

		sumSeconds := float64(h.sumNanos.Load()) / float64(time.Second)
		fmt.Fprintf(&sb, "poseidon_request_duration_seconds_sum{method=%q,path=%q} %.9f\n",
			method, path, sumSeconds)
		fmt.Fprintf(&sb, "poseidon_request_duration_seconds_count{method=%q,path=%q} %d\n",
			method, path, total)
	}

	sb.WriteString("\n# HELP poseidon_active_requests Current in-flight requests.\n")
	sb.WriteString("# TYPE poseidon_active_requests gauge\n")
	fmt.Fprintf(&sb, "poseidon_active_requests %d\n", c.active.Load())

	c.writeTransport(&sb)

	return sb.String()
}

// writeTransport appends HTTP/2 transport metrics when a source is registered.
// Caller holds c.mu (read lock).
func (c *MetricsCollector) writeTransport(sb *strings.Builder) {
	if c.transportSrc == nil {
		return
	}
	t := c.transportSrc()

	sb.WriteString("\n# HELP poseidon_connections_active Current open HTTP/2 connections.\n")
	sb.WriteString("# TYPE poseidon_connections_active gauge\n")
	fmt.Fprintf(sb, "poseidon_connections_active %d\n", t.ActiveConns)

	// Monotonic transport counters.
	type counter struct {
		name, help string
		val        uint64
	}
	for _, m := range []counter{
		{"poseidon_bytes_sent_total", "Total bytes written to clients across all connections.", uint64(t.BytesSent)},
		{"poseidon_bytes_received_total", "Total bytes read from clients across all connections.", uint64(t.BytesReceived)},
		{"poseidon_frames_sent_total", "Total HTTP/2 frames written across all connections.", uint64(t.FramesSent)},
		{"poseidon_frames_received_total", "Total HTTP/2 frames read across all connections.", uint64(t.FramesReceived)},
		{"poseidon_streams_accepted_total", "Total HTTP/2 streams accepted across all connections.", t.StreamsAccepted},
		{"poseidon_rapid_resets_total", "Total client RST_STREAM frames charged against the Rapid Reset budget (CVE-2023-44487).", t.RapidResets},
		{"poseidon_goaways_sent_total", "Total connections on which the server emitted a GOAWAY.", t.GoAways},
	} {
		fmt.Fprintf(sb, "\n# HELP %s %s\n# TYPE %s counter\n%s %d\n", m.name, m.help, m.name, m.name, m.val)
	}
}

// formatBucketBound renders a histogram upper bound for the le label using the
// shortest representation that round-trips (e.g. 5 not 5.000000, 0.005 not
// 5e-03), matching Prometheus exposition conventions.
func formatBucketBound(ub float64) string {
	return strconv.FormatFloat(ub, 'f', -1, 64)
}

// MetricsHandler returns an http.Handler-compatible server.HandlerFunc
// that serves the Prometheus text exposition format at /metrics.
func (c *MetricsCollector) MetricsHandler() server.HandlerFunc {
	return server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
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
