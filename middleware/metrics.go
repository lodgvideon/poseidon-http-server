package middleware

import (
	"context"
	"fmt"
	"maps"
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

// metricViews is an immutable copy of the four metric maps, published as one
// atomic pointer. It is what the request path reads.
//
// This is the answer to "what does the hot path do INSTEAD of taking a lock"
// (CLAUDE.md): a request resolves its series with a single atomic pointer LOAD
// plus a plain map lookup. A load leaves the cache line in the shared state on
// every core, so it costs nothing extra as cores are added — unlike
// [sync.RWMutex.RLock], which is a read-modify-write on one reader counter and
// therefore serialises 16 cores onto one cache line even though it never blocks
// (issue #120: 13.3% of all CPU at -cpu=16, 100% of it from RLock/RUnlock).
//
// A view is built under [MetricsCollector.mu] and never mutated afterwards, so
// concurrent readers need no synchronisation of their own. The maps it holds are
// clones: the *values* (the [seriesCounter] and [histogram] pointers) are shared
// with the live maps, so a counter incremented through a view is the same
// counter the exposition path reads.
type metricViews struct {
	counters   map[string]*seriesCounter
	durations  map[string]*seriesCounter
	reqBytes   map[string]*seriesCounter
	histograms map[string]*histogram

	// entries is the total live-map entry count at publication, used to pace
	// rebuilds. See maybePublishViewsLocked.
	entries int
}

// eagerViewEntries is the total live-entry count below which the views are
// rebuilt on every insertion, which keeps them exact. A rebuild is O(entries),
// so past this point rebuilds are paced to a doubling of the entry count, making
// the amortised cost per insertion constant; keys inserted between rebuilds are
// simply invisible to the fast path and fall through to the locked path, which
// is what every request did before this existed.
//
// Every *bounded* configuration stays in the eager regime: the default caps the
// four maps at 4*(DefaultMaxSeries+1) = 4100 entries. The paced branch exists
// only for MetricsConfig.MaxSeries < 0 (the documented unbounded opt-out), where
// an eager rebuild would be quadratic in the number of series — turning the
// memory DoS that MaxSeries<0 accepts into a CPU DoS as well.
const eagerViewEntries = 8192

// metricsKeyBufSize is the stack scratch space a request builds its two metric
// keys in. Both keys are looked up as map[string(buf)], which the compiler
// resolves without copying the bytes to the heap, so a request whose labels are
// already tracked allocates nothing at all. A path longer than this still works
// and is never truncated — append spills to the heap — it just costs one
// allocation, which is still fewer than the four this replaced.
const metricsKeyBufSize = 256

// MetricsCollector tracks request-level metrics in a thread-safe manner.
// The data can be exposed via Prometheus, OpenMetrics, or simple /metrics scraping.
//
// Label cardinality is bounded: see [MetricsConfig] and [DefaultMaxSeries].
type MetricsCollector struct {
	// mu guards the four live maps below and transportSrc. The request path does
	// NOT take it in steady state — it reads the immutable views instead (see
	// metricViews). It is taken to insert a series, to sweep, and to snapshot for
	// exposition; WritePrometheus formats outside it.
	mu sync.RWMutex

	// views is the lock-free read side of the four maps. Written only under mu.
	views atomic.Pointer[metricViews]

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
	c.publishViewsLocked(0) // nothing else can reach c yet
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

// touch refreshes a series' recency stamp for the idle sweep, and skips the
// write entirely when idle sweeping is off, since nothing will ever read it.
//
// It is a plain store, and that is a measured decision rather than an obvious
// one. Reading the stamp first and writing only when it had drifted by TTL/64
// looks like it should be cheaper — a shared-line load instead of an
// exclusive-line store — and it is NOT: lastSeen sits in the same cache line as
// the counter every request increments, so the line is already owned exclusively
// by whichever core last recorded a hit, and the "cheap" load pays the same
// coherence transfer plus a branch. Measured at -cpu=16, the conditional version
// was 11.4% slower on BenchmarkMetricsMiddleware_Parallel and 4.2% slower on
// BenchmarkMetricsMiddlewareParallel_Tracked (p=0.000, n=10 each). Do not
// reintroduce it without separating the stamp from the counter first.
//
// nowNanos is the caller's single clock read, threaded through so that bounding
// cardinality still costs no extra clock reads per request.
func (c *MetricsCollector) touch(lastSeen *atomic.Int64, nowNanos int64) {
	if c.seriesTTL <= 0 {
		return // idle sweeping is disabled; nothing reads the stamp
	}
	lastSeen.Store(nowNanos)
}

// publishViewsLocked rebuilds the immutable read views from the live maps and
// publishes them. Caller holds the write lock (or is the constructor, before the
// collector is reachable).
//
// The values are shared, not copied: a view holds the same *seriesCounter and
// *histogram pointers the live maps hold, so an increment through a view lands
// in the series the exposition path reads.
func (c *MetricsCollector) publishViewsLocked(entries int) {
	c.views.Store(&metricViews{
		counters:   maps.Clone(c.counters),
		durations:  maps.Clone(c.durations),
		reqBytes:   maps.Clone(c.reqBytes),
		histograms: maps.Clone(c.histograms),
		entries:    entries,
	})
}

// maybePublishViewsLocked republishes the views after an insertion, eagerly
// while the collector is small and on a doubling of the entry count once it is
// not. See eagerViewEntries. Caller holds the write lock.
func (c *MetricsCollector) maybePublishViewsLocked() {
	n := len(c.counters) + len(c.durations) + len(c.reqBytes) + len(c.histograms)
	if n <= eagerViewEntries || n >= 2*c.views.Load().entries {
		c.publishViewsLocked(n)
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

// counterKey returns the metrics key for a request. It builds the string by
// concatenation rather than with fmt.Sprintf (issue #107), which costs a
// format-string parse and an extra allocation for the same bytes. The request
// path does not call this at all — it uses appendCounterKey — so this is now
// only the lookup helper for TotalRequests and for direct API callers.
func counterKey(method, path string, status int) string {
	return method + "|" + path + "|" + strconv.Itoa(status)
}

// durationKey returns the metrics key for duration tracking.
func durationKey(method, path string) string {
	return method + "|" + path
}

// appendDurationKey writes durationKey(method, path) into dst. Given stack
// scratch space it produces the key without allocating; see metricsKeyBufSize.
func appendDurationKey(dst []byte, method, path string) []byte {
	dst = append(dst, method...)
	dst = append(dst, '|')
	return append(dst, path...)
}

// appendCounterKey extends a duration key already written by appendDurationKey
// into the counter key for status, which is the same bytes plus "|<status>".
// Sharing one buffer between the two keys is not a micro-optimisation for its
// own sake: it is what keeps a request to one scratch buffer, and the duration
// key stays valid because appending only ever writes past its length.
func appendCounterKey(durKey []byte, status int) []byte {
	return strconv.AppendInt(append(durKey, '|'), int64(status), 10)
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

// lookupSeries resolves key to its counter WITHOUT taking any lock, given the
// view of store published by the last insertion or sweep. key is a []byte so
// that the caller can build it in stack scratch space: `view[string(key)]` is
// the one map access the compiler resolves without copying the bytes to the
// heap, so a request whose labels are tracked allocates nothing.
//
// Two cases are answered from the view, and between them they are every request
// a running server serves:
//
//   - an already-tracked label — one atomic load, one map lookup;
//   - an untracked label while the store is full, i.e. every request of a
//     unique-path flood — the fold is resolved from the same view.
//
// Anything else (first sight of a label, or a label inserted since the last
// rebuild in the paced regime) falls through to series, which is the locked path
// this used to be.
func (c *MetricsCollector) lookupSeries(view, live map[string]*seriesCounter, key []byte, overflow string, nowNanos int64) *seriesCounter {
	if ctr, ok := view[string(key)]; ok {
		c.touch(&ctr.lastSeen, nowNanos)
		return ctr
	}
	if c.foldsView(len(view), nowNanos) {
		if ctr, ok := view[overflow]; ok {
			c.touch(&ctr.lastSeen, nowNanos)
			return ctr
		}
	}
	return c.series(live, string(key), overflow, nowNanos)
}

// lookupHistogram is lookupSeries for the histogram map.
func (c *MetricsCollector) lookupHistogram(view map[string]*histogram, key []byte, nowNanos int64) *histogram {
	if h, ok := view[string(key)]; ok {
		c.touch(&h.lastSeen, nowNanos)
		return h
	}
	if c.foldsView(len(view), nowNanos) {
		if h, ok := view[overflowSeriesKey]; ok {
			c.touch(&h.lastSeen, nowNanos)
			return h
		}
	}
	return c.histogramSeries(string(key), nowNanos)
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
//
// Since #120 both of those read-lock cases are normally answered one level up by
// lookupSeries, from an immutable view and with no lock at all; this remains the
// path for direct API callers ([MetricsCollector.ObserveDuration] aside), for
// first sight of a label, and for a label the views have not caught up with.
func (c *MetricsCollector) series(store map[string]*seriesCounter, key, overflow string, nowNanos int64) *seriesCounter {
	c.mu.RLock()
	if ctr, ok := store[key]; ok {
		c.mu.RUnlock()
		c.touch(&ctr.lastSeen, nowNanos)
		return ctr
	}
	if c.foldsLocked(store, nowNanos) {
		if ctr, ok := store[overflow]; ok {
			c.mu.RUnlock()
			c.touch(&ctr.lastSeen, nowNanos)
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
	c.maybePublishViewsLocked()
	return ctr
}

// histogramSeries is series() for the histogram map, which holds a different
// value type. Same locking contract.
func (c *MetricsCollector) histogramSeries(key string, nowNanos int64) *histogram {
	c.mu.RLock()
	if h, ok := c.histograms[key]; ok {
		c.mu.RUnlock()
		c.touch(&h.lastSeen, nowNanos)
		return h
	}
	if c.maxSeries > 0 && len(c.histograms) >= c.maxSeries && !c.sweepDue(nowNanos) {
		if h, ok := c.histograms[overflowSeriesKey]; ok {
			c.mu.RUnlock()
			c.touch(&h.lastSeen, nowNanos)
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
	c.maybePublishViewsLocked()
	return h
}

// foldsLocked reports whether an untracked label must fold into the overflow
// series right now, without escalating to the write lock. A due sweep is the one
// reason to escalate: it may free a slot for this very label. Caller holds the
// read lock.
func (c *MetricsCollector) foldsLocked(store map[string]*seriesCounter, nowNanos int64) bool {
	return c.foldsView(len(store), nowNanos)
}

// foldsView is foldsLocked expressed against a size, so the lock-free path can
// ask the same question of a published view. A view can only UNDER-report the
// live size (it is rebuilt after every insertion until eagerViewEntries, and
// after every sweep), and under-reporting merely declines to fold, sending the
// request to the locked path which decides again with the exact size. It can
// therefore never fold a label that the live store still had room for.
func (c *MetricsCollector) foldsView(size int, nowNanos int64) bool {
	return c.maxSeries > 0 && size >= c.maxSeries && !c.sweepDue(nowNanos)
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
//
// Republishing the views is part of sweeping, not of the caller's bookkeeping: a
// view that still holds a swept-away series would keep handing it out, and the
// increments landing on it would be invisible to every subsequent scrape. Both
// callers can return early between the sweep and their own insertion, so leaving
// the republish to them would leak exactly that.
func (c *MetricsCollector) maybeSweepLocked(nowNanos int64) {
	if !c.sweepDue(nowNanos) {
		return
	}
	c.lastSweep.Store(nowNanos)
	c.sweepLocked(nowNanos)
	c.publishViewsLocked(len(c.counters) + len(c.durations) + len(c.reqBytes) + len(c.histograms))
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
// latency histogram. Once the method+path has been seen it is allocation-free
// and lock-free: the key is built in stack scratch space, the histogram is
// resolved from the published view, and the observation itself is atomic.
func (c *MetricsCollector) ObserveDuration(method, path string, d time.Duration) {
	var kb [metricsKeyBufSize]byte
	key := appendDurationKey(kb[:0], method, path)
	c.lookupHistogram(c.views.Load().histograms, key, c.nowNanos()).observe(d)
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

			// Both keys are built once, into one stack buffer, and looked up as
			// map[string(bytes)] — no allocation for a label already tracked.
			var kb [metricsKeyBufSize]byte
			dKey := appendDurationKey(kb[:0], req.Method, path)
			cKey := appendCounterKey(dKey, status)

			// One atomic load serves all four lookups. A view that has gone stale
			// between them only costs the locked path, never a wrong answer.
			v := c.views.Load()

			// Increment request counter.
			c.lookupSeries(v.counters, c.counters, cKey, overflowCounterKey, nowNanos).Add(1)

			// Record duration (total) and latency histogram.
			c.lookupSeries(v.durations, c.durations, dKey, overflowSeriesKey, nowNanos).Add(int64(elapsed))
			c.lookupHistogram(v.histograms, dKey, nowNanos).observe(elapsed)

			// Record request body size.
			if len(req.Body) > 0 {
				c.lookupSeries(v.reqBytes, c.reqBytes, dKey, overflowSeriesKey, nowNanos).Add(int64(len(req.Body)))
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
//
// The collector lock is held to snapshot the series, not to format them (issue
// #109). Building the exposition for a collector at the default cardinality
// bound is ~17k Fprintf calls and measures at ~10ms; holding the read lock
// across that blocks the write lock for the whole time, and the write lock is
// what a first-sight series, an idle sweep and a republication of the lock-free
// views all wait on. Four clones of shared pointers is the allocation CLAUDE.md
// says to prefer over the lock.
//
// The guarantee is the one it always had: the SET of series is a point-in-time
// snapshot, while each series' values are read per-field through atomics at an
// unspecified instant at or after that point. Increments never took this lock,
// so they were never excluded from the build either.
func (c *MetricsCollector) WritePrometheus() string {
	var sb strings.Builder

	sb.WriteString("# HELP poseidon_requests_total Total HTTP requests by method, path, and status.\n")
	sb.WriteString("# TYPE poseidon_requests_total counter\n")

	c.mu.RLock()
	counters := maps.Clone(c.counters)
	durations := maps.Clone(c.durations)
	reqBytes := maps.Clone(c.reqBytes)
	histograms := maps.Clone(c.histograms)
	transportSrc := c.transportSrc
	c.mu.RUnlock()

	for key, ctr := range counters {
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
	for key, ctr := range durations {
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
	for key, ctr := range reqBytes {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		fmt.Fprintf(&sb, "poseidon_request_bytes_total{method=%q,path=%q} %d\n",
			parts[0], parts[1], ctr.Load())
	}

	sb.WriteString("\n# HELP poseidon_request_duration_seconds Request latency distribution in seconds.\n")
	sb.WriteString("# TYPE poseidon_request_duration_seconds histogram\n")
	for key, h := range histograms {
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

	writeTransport(&sb, transportSrc)

	return sb.String()
}

// writeTransport appends HTTP/2 transport metrics when a source is registered.
// src is read from the collector under the lock and passed in, so the callback
// itself runs outside it.
func writeTransport(sb *strings.Builder, src func() server.TransportStats) {
	if src == nil {
		return
	}
	t := src()

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
