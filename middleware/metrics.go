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

	// lastSeen is the UnixNano of the most recent touch, read only by the idle
	// sweep. See seriesCounter.lastSeen for why it is a lock-free atomic.
	lastSeen atomic.Int64
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

// OverflowLabel is the label value a request folds into once the collector has
// reached its series cap ([MetricsConfig.MaxSeries]). Overflowing requests are
// still counted — into one fixed series carrying this value for method, path
// and status — so traffic is never dropped from the metrics, only aggregated.
const OverflowLabel = "__other__"

// DefaultMaxSeries bounds the number of distinct label combinations each metric
// map holds when [MetricsConfig.MaxSeries] is unset. Request paths are
// attacker-chosen (the raw ":path", query string included — see server.Request),
// so without a ceiling a scanner walking /users/1, /users/2, … grows the heap
// until the process is OOM-killed. 1024 series keeps a scrape response readable
// (each series costs ~14 exposition lines) and the retained heap well under a
// megabyte, while comfortably covering a route-templated application.
const DefaultMaxSeries = 1024

// DefaultSeriesIdleTTL is how long an untouched series is retained before it
// becomes eligible for opportunistic eviction when [MetricsConfig.SeriesIdleTTL]
// is unset. The hard cap alone bounds memory; the TTL is what lets the label set
// *adapt* — without it, whichever labels arrived first (an attacker's, say)
// would hold the budget forever and every route deployed afterwards would fold
// into [OverflowLabel]. 15 minutes is far longer than any sane scrape interval,
// so a route touched even once between scrapes keeps its series.
const DefaultSeriesIdleTTL = 15 * time.Minute

// overflowCounterKey and overflowSeriesKey are the fixed keys every folded
// request lands on. They are package-level constants, not built per request, so
// the overflow path allocates nothing the normal path would not.
const (
	overflowCounterKey = OverflowLabel + "|" + OverflowLabel + "|" + OverflowLabel
	overflowSeriesKey  = OverflowLabel + "|" + OverflowLabel
)

// MetricsConfig configures a [MetricsCollector]. The zero value selects the
// documented safe defaults, which is what [NewMetricsCollector] uses.
type MetricsConfig struct {
	// MaxSeries caps the number of distinct label combinations held in each
	// metric map, bounding memory against an attacker who streams unbounded
	// distinct paths (or methods). Once a map is full, a request whose labels
	// are not already tracked is recorded under [OverflowLabel] instead, so each
	// map holds at most MaxSeries+1 entries.
	//
	//	0  => DefaultMaxSeries (the secure default)
	//	<0 => unbounded (no cap — the pre-v0.5 behaviour; not recommended for
	//	      any server reachable by untrusted traffic)
	//	>0 => explicit cap
	MaxSeries int

	// SeriesIdleTTL is how long an untouched series is retained before it
	// becomes eligible for opportunistic eviction. Eviction makes room for
	// newly-seen labels, so a burst of attacker paths cannot permanently
	// occupy the budget.
	//
	//	0  => DefaultSeriesIdleTTL
	//	<0 => idle eviction disabled (only the MaxSeries cap bounds memory)
	//	>0 => explicit TTL
	SeriesIdleTTL time.Duration

	// PathLabel maps a request to the value used for the "path" label. It is
	// the hook to label by route template rather than by concrete path —
	// collapse the path onto the template yourself:
	//
	//	PathLabel: func(req *server.Request) string {
	//		if strings.HasPrefix(req.Path, "/users/") {
	//			return "/users/{id}"
	//		}
	//		return req.Path
	//	}
	//
	// A router's own matched pattern is NOT reachable from here, and this
	// doc comment used to claim otherwise with a chi example that did not
	// compile. Two things stop it. [server.Request] has no Context method —
	// a [server.Handler] takes ctx as a separate parameter, so there is no
	// req.Context() to pass. And Metrics is a [server.Middleware], which
	// Options.resolvedHandler chains ON TOP OF FromHTTPHandler: this hook
	// runs before the router does, so even a reachable context would not
	// yet hold the route pattern chi fills in inside its own ServeHTTP.
	//
	// Returning a template collapses /users/1, /users/2, … onto /users/{id},
	// which keeps the label set small enough that the cap is never reached.
	// It also strips the query string, which the raw path carries.
	//
	// When nil, the raw request path is used. PathLabel is a refinement, not a
	// replacement, for MaxSeries: the cap still applies to whatever it returns.
	PathLabel func(req *server.Request) string

	// now is an injectable clock for deterministic testing. Nil uses time.Now.
	// Unexported so it is not part of the public API.
	now func() time.Time
}

// seriesCounter is a monotonic counter plus the recency stamp the idle sweep
// reads. lastSeen is the ONLY field eviction touches and is accessed solely via
// atomic Load/Store, so a sweep never needs a per-series lock and recording a
// hit never upgrades MetricsCollector.mu.
type seriesCounter struct {
	atomic.Int64
	lastSeen atomic.Int64
}

// MetricsCollector tracks request-level metrics in a thread-safe manner.
// The data can be exposed via Prometheus, OpenMetrics, or simple /metrics scraping.
//
// Label cardinality is bounded: see [MetricsConfig] and [DefaultMaxSeries].
type MetricsCollector struct {
	mu sync.RWMutex

	// requestCount tracks total requests by method+path+status.
	counters map[string]*seriesCounter

	// requestDuration tracks total duration (nanoseconds) by method+path.
	durations map[string]*seriesCounter

	// requestBytes tracks total request body bytes by method+path.
	reqBytes map[string]*seriesCounter

	// histograms tracks request-duration distributions by method+path,
	// completing the RED method (Rate/Errors/Duration).
	histograms map[string]*histogram

	// activeRequests tracks in-flight requests.
	active atomic.Int64

	// transportSrc, when set via SetTransportSource, supplies HTTP/2 transport
	// counters (bytes/frames/streams, rapid-resets, GOAWAYs, active conns) for
	// exposition. Guarded by mu like the maps above.
	transportSrc func() server.TransportStats

	// Cardinality bounds. Immutable after construction, so the hot path reads
	// them without synchronisation.
	maxSeries int           // 0 => unbounded
	seriesTTL time.Duration // 0 => idle sweeping disabled
	pathLabel func(req *server.Request) string
	now       func() time.Time

	// lastSweep is the UnixNano of the last idle sweep. Atomic, not mu-guarded,
	// so the fold path can pace sweeps with a single lock-free load.
	lastSweep atomic.Int64
}

// NewMetricsCollector creates an empty MetricsCollector with the default
// cardinality bounds ([DefaultMaxSeries], [DefaultSeriesIdleTTL]). Use
// [NewMetricsCollectorWithConfig] to change them or to label by route template.
func NewMetricsCollector() *MetricsCollector {
	return NewMetricsCollectorWithConfig(MetricsConfig{})
}

// NewMetricsCollectorWithConfig creates an empty MetricsCollector with explicit
// cardinality bounds. The zero MetricsConfig is identical to
// [NewMetricsCollector].
func NewMetricsCollectorWithConfig(cfg MetricsConfig) *MetricsCollector {
	clock := cfg.now
	if clock == nil {
		clock = time.Now
	}
	c := &MetricsCollector{
		counters:   make(map[string]*seriesCounter),
		durations:  make(map[string]*seriesCounter),
		reqBytes:   make(map[string]*seriesCounter),
		histograms: make(map[string]*histogram),
		maxSeries:  resolveMaxSeries(cfg.MaxSeries),
		seriesTTL:  resolveSeriesIdleTTL(cfg.SeriesIdleTTL),
		pathLabel:  cfg.PathLabel,
		now:        clock,
	}
	c.lastSweep.Store(clock().UnixNano())
	return c
}

// resolveMaxSeries maps the configured cap to the internal value, where 0 means
// "unbounded": cfg 0 => DefaultMaxSeries, cfg <0 => 0 (unbounded), cfg >0 => cfg.
func resolveMaxSeries(cfg int) int {
	switch {
	case cfg == 0:
		return DefaultMaxSeries
	case cfg < 0:
		return 0 // unbounded
	default:
		return cfg
	}
}

// resolveSeriesIdleTTL maps the configured TTL to the internal value, where 0
// means "no idle sweeping": cfg 0 => DefaultSeriesIdleTTL, cfg <0 => 0
// (disabled), cfg >0 => cfg.
func resolveSeriesIdleTTL(cfg time.Duration) time.Duration {
	switch {
	case cfg == 0:
		return DefaultSeriesIdleTTL
	case cfg < 0:
		return 0 // disabled
	default:
		return cfg
	}
}

// nowNanos reads the collector clock. The Metrics middleware reads the clock
// once per request and threads the result through, so this is only paid by
// direct API callers.
func (c *MetricsCollector) nowNanos() int64 { return c.now().UnixNano() }

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
func (c *MetricsCollector) getOrCreateCounter(key string) *seriesCounter {
	return c.series(c.counters, key, overflowCounterKey, c.nowNanos())
}

// getOrCreateDuration returns an existing duration counter or creates one.
func (c *MetricsCollector) getOrCreateDuration(key string) *seriesCounter {
	return c.series(c.durations, key, overflowSeriesKey, c.nowNanos())
}

// getOrCreateBytes returns an existing bytes counter or creates one.
func (c *MetricsCollector) getOrCreateBytes(store map[string]*seriesCounter, key string) *seriesCounter {
	return c.series(store, key, overflowSeriesKey, c.nowNanos())
}

// getOrCreateHistogram returns an existing histogram or creates one.
func (c *MetricsCollector) getOrCreateHistogram(key string) *histogram {
	return c.histogramSeries(key, c.nowNanos())
}

// series returns the counter for key in store, creating it if the store has
// room and otherwise folding the request into the single `overflow` series.
//
// Locking — this is the part that makes the bound safe rather than merely
// present. Two paths never take the write lock:
//
//   - an already-tracked label: one read-lock'd map lookup, then a lock-free
//     atomic for the recency stamp. Identical cost to before the cap existed.
//   - an untracked label while the store is full (i.e. every request of a
//     unique-path flood): the fold is resolved under the SAME read lock. If the
//     flood reached the write lock instead, capping the memory would simply
//     convert the memory DoS into a contention DoS — measured at 45s vs 1.3s
//     for 1e6 unique paths before this branch existed.
//
// The write lock is taken only to actually insert a series, or when an idle
// sweep has come due — both bounded by the cap and the TTL, neither driven by
// request rate.
func (c *MetricsCollector) series(store map[string]*seriesCounter, key, overflow string, nowNanos int64) *seriesCounter {
	c.mu.RLock()
	if ctr, ok := store[key]; ok {
		c.mu.RUnlock()
		ctr.lastSeen.Store(nowNanos)
		return ctr
	}
	if c.foldsLocked(store, nowNanos) {
		if ctr, ok := store[overflow]; ok {
			c.mu.RUnlock()
			ctr.lastSeen.Store(nowNanos)
			return ctr
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check.
	if ctr, ok := store[key]; ok {
		ctr.lastSeen.Store(nowNanos)
		return ctr
	}
	c.maybeSweepLocked(nowNanos)
	if c.maxSeries > 0 && len(store) >= c.maxSeries {
		key = overflow
	}
	// The overflow series usually already exists once folding has started.
	if ctr, ok := store[key]; ok {
		ctr.lastSeen.Store(nowNanos)
		return ctr
	}
	ctr := &seriesCounter{}
	ctr.lastSeen.Store(nowNanos)
	store[key] = ctr
	return ctr
}

// histogramSeries is series() for the histogram map, which holds a different
// value type. Same locking contract.
func (c *MetricsCollector) histogramSeries(key string, nowNanos int64) *histogram {
	c.mu.RLock()
	if h, ok := c.histograms[key]; ok {
		c.mu.RUnlock()
		h.lastSeen.Store(nowNanos)
		return h
	}
	if c.maxSeries > 0 && len(c.histograms) >= c.maxSeries && !c.sweepDue(nowNanos) {
		if h, ok := c.histograms[overflowSeriesKey]; ok {
			c.mu.RUnlock()
			h.lastSeen.Store(nowNanos)
			return h
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.histograms[key]; ok {
		h.lastSeen.Store(nowNanos)
		return h
	}
	c.maybeSweepLocked(nowNanos)
	if c.maxSeries > 0 && len(c.histograms) >= c.maxSeries {
		key = overflowSeriesKey
	}
	if h, ok := c.histograms[key]; ok {
		h.lastSeen.Store(nowNanos)
		return h
	}
	h := newHistogram(defaultDurationBuckets)
	h.lastSeen.Store(nowNanos)
	c.histograms[key] = h
	return h
}

// foldsLocked reports whether an untracked label must fold into the overflow
// series right now, without escalating to the write lock. A due sweep is the one
// reason to escalate: it may free a slot for this very label. Caller holds the
// read lock.
func (c *MetricsCollector) foldsLocked(store map[string]*seriesCounter, nowNanos int64) bool {
	return c.maxSeries > 0 && len(store) >= c.maxSeries && !c.sweepDue(nowNanos)
}

// sweepDue reports whether a full store should stop folding long enough to
// reclaim idle series. Checked with a single atomic load on the fold path.
//
// A sustained flood inserts nothing, so an insertion-gated sweep would never
// fire and the label set would freeze permanently at whatever the attacker put
// there first. Pacing on the TTL instead costs at most one sweep per TTL.
func (c *MetricsCollector) sweepDue(nowNanos int64) bool {
	return c.seriesTTL > 0 && nowNanos-c.lastSweep.Load() >= int64(c.seriesTTL)
}

// maybeSweepLocked runs the idle sweep if one has come due, recording that it
// ran so concurrent callers that also saw it due do not repeat the scan. Caller
// holds the write lock.
func (c *MetricsCollector) maybeSweepLocked(nowNanos int64) {
	if !c.sweepDue(nowNanos) {
		return
	}
	c.lastSweep.Store(nowNanos)
	c.sweepLocked(nowNanos)
}

// sweepLocked drops every series untouched for at least seriesTTL. All four maps
// are swept with one cutoff so a path's counter, duration, byte count and
// histogram are reclaimed together rather than drifting apart. Recency is read
// through the per-series lock-free atomic, so the sweep takes no per-series
// lock. Caller holds the write lock.
func (c *MetricsCollector) sweepLocked(nowNanos int64) {
	cutoff := nowNanos - int64(c.seriesTTL)
	for _, store := range [...]map[string]*seriesCounter{c.counters, c.durations, c.reqBytes} {
		for k, ctr := range store {
			if ctr.lastSeen.Load() < cutoff {
				delete(store, k)
			}
		}
	}
	for k, h := range c.histograms {
		if h.lastSeen.Load() < cutoff {
			delete(c.histograms, k)
		}
	}
}

// ObserveDuration records a single request duration into the per-method+path
// latency histogram. It is allocation-light: the histogram lookup uses the
// shared RWMutex only on first sight of a key; the observation itself is
// atomic and lock-free.
func (c *MetricsCollector) ObserveDuration(method, path string, d time.Duration) {
	c.getOrCreateHistogram(durationKey(method, path)).observe(d)
}

// Metrics returns a middleware that collects request metrics.
//
// The "path" label is [MetricsConfig.PathLabel] applied to the request, or the
// raw request path when that hook is nil. Either way the number of distinct
// label combinations is capped at [MetricsConfig.MaxSeries] per metric; requests
// beyond the cap are counted under [OverflowLabel] rather than dropped.
func (c *MetricsCollector) Metrics() server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			c.active.Add(1)
			defer c.active.Add(-1)

			start := c.now()
			err := next.ServeHTTP(ctx, req, w)
			end := c.now()
			elapsed := end.Sub(start)
			// One clock read serves every recency stamp below, so bounding the
			// cardinality costs no extra clock reads on the hot path.
			nowNanos := end.UnixNano()

			status := w.StatusCode()
			if status == 0 {
				status = 200
			}

			path := req.Path
			if c.pathLabel != nil {
				path = c.pathLabel(req)
			}

			// Increment request counter.
			key := counterKey(req.Method, path, status)
			c.series(c.counters, key, overflowCounterKey, nowNanos).Add(1)

			// Record duration (total) and latency histogram.
			dKey := durationKey(req.Method, path)
			c.series(c.durations, dKey, overflowSeriesKey, nowNanos).Add(int64(elapsed))
			c.histogramSeries(dKey, nowNanos).observe(elapsed)

			// Record request body size.
			if len(req.Body) > 0 {
				c.series(c.reqBytes, dKey, overflowSeriesKey, nowNanos).Add(int64(len(req.Body)))
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
