package middleware

import (
	"context"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// RateLimit — token-bucket request limiting
// ---------------------------------------------------------------------------

// defaultRateLimit is the per-second token refill rate used when
// RateLimitConfig.Rate is unset (<= 0).
const defaultRateLimit = 100

// DefaultMaxBuckets bounds the number of distinct keys (token buckets) the
// limiter holds at once when RateLimitConfig.MaxBuckets is unset. It caps memory
// so an attacker streaming unbounded distinct keys (e.g. per-/128 IPv6 client
// IPs via KeyByClientIP) cannot grow the map without limit. ~65k buckets is a
// few MB.
const DefaultMaxBuckets = 1 << 16

// DefaultBucketIdleTTL is the floor for how long an untouched bucket is retained
// before opportunistic eviction when RateLimitConfig.BucketIdleTTL is unset. The
// effective TTL is max(this, refill-to-full time) so that an evicted idle bucket
// has always refilled to full burst — making its eviction indistinguishable from
// a fresh bucket (no rate-limit accuracy is lost).
const DefaultBucketIdleTTL = 10 * time.Minute

// defaultSweepEvery is the number of bucket insertions between opportunistic
// idle sweeps. A sweep is O(live buckets); gating it by insertion count keeps the
// amortized per-request cost negligible while still reclaiming idle buckets.
const defaultSweepEvery = 256

// RateLimitConfig configures the [RateLimit] middleware.
type RateLimitConfig struct {
	// Rate is the sustained number of requests allowed per second (the token
	// refill rate). Values <= 0 default to 100.
	Rate float64

	// Burst is the maximum number of requests allowed in an instantaneous
	// burst (the bucket capacity). Values <= 0 default to max(1, Rate).
	Burst int

	// Key maps a request to a bucket key. Requests sharing a key share a
	// bucket. When nil, a single global bucket is used for all requests
	// (i.e. every request maps to the same key).
	//
	// Key receives the request context so it can read values injected by
	// upstream middleware. A common per-client policy is [KeyByClientIP]
	// (keys on the RealIP-resolved client IP from the context); keying on
	// req.Authority is also typical.
	Key func(ctx context.Context, req *server.Request) string

	// MaxBuckets caps the number of distinct keys (buckets) held at once,
	// bounding memory against an attacker who streams unbounded distinct keys.
	// When the map is full, admitting a new key evicts the oldest one. Because
	// an evicted bucket has refilled to full (see BucketIdleTTL), eviction loses
	// no accuracy and grants an attacker no extra capacity (a fresh key already
	// gets a full bucket).
	//
	//	0  => DefaultMaxBuckets (the secure default)
	//	<0 => unbounded (no cap — the legacy behaviour; not recommended with
	//	      attacker-influenced keys such as KeyByClientIP)
	//	>0 => explicit cap
	MaxBuckets int

	// BucketIdleTTL is how long an untouched bucket is retained before it
	// becomes eligible for opportunistic eviction. The effective TTL is never
	// below the refill-to-full time, so an evicted idle bucket is always full.
	//
	//	0  => max(DefaultBucketIdleTTL, refill-to-full)
	//	<0 => idle eviction disabled (only the MaxBuckets cap reclaims memory)
	//	>0 => max(this, refill-to-full)
	BucketIdleTTL time.Duration

	// now is an injectable clock for deterministic testing. Nil uses
	// time.Now. Unexported so it is not part of the public API.
	now func() time.Time
}

// RateLimit returns a middleware that admits requests according to a
// token-bucket limiter. When a request's bucket has no token available the
// middleware short-circuits with 429 Too Many Requests and does NOT invoke
// the next handler.
//
// The limiter is self-contained (no external dependency). Buckets are keyed
// by cfg.Key (a single global bucket by default) and created lazily; each
// bucket is guarded by its own mutex, so unrelated keys do not contend.
func RateLimit(cfg RateLimitConfig) server.Middleware {
	rate := cfg.Rate
	if rate <= 0 {
		rate = defaultRateLimit
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = int(math.Max(1, rate))
	}
	clock := cfg.now
	if clock == nil {
		clock = time.Now
	}

	lim := &keyedLimiter{
		rate:       rate,
		burst:      burst,
		now:        clock,
		maxBuckets: resolveMaxBuckets(cfg.MaxBuckets),
		ttl:        resolveIdleTTL(cfg.BucketIdleTTL, rate, burst),
		sweepEvery: defaultSweepEvery,
		buckets:    make(map[string]*tokenBucket),
	}

	keyFn := cfg.Key

	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			key := ""
			if keyFn != nil {
				key = keyFn(ctx, req)
			}
			if !lim.allow(key) {
				return w.WriteHeaders(http.StatusTooManyRequests, nil)
			}
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

// KeyByClientIP returns a [RateLimitConfig.Key] function that buckets requests
// by the client IP resolved by the [RealIP] middleware (read from the context
// via [ClientIP]). RealIP MUST run before RateLimit in the chain for this to
// see a resolved address.
//
// When the client IP is unresolved (RealIP did not run, or could not determine
// an address) the key is the empty string, so all such requests share one
// bucket. This is a deliberate fail-closed default: unidentifiable traffic is
// throttled together rather than slipping past the limiter unbucketed.
//
// Note: the limiter bounds memory by capping the number of buckets
// ([RateLimitConfig.MaxBuckets], default [DefaultMaxBuckets]) and evicting idle
// ones, so unbounded distinct keys cannot exhaust memory. Still run RealIP with
// a TrustedProxies allowlist so the key is a real upstream IP rather than an
// attacker-spoofable forwarding header; note IPv6 keys are per-/128.
func KeyByClientIP() func(ctx context.Context, req *server.Request) string {
	return func(ctx context.Context, _ *server.Request) string {
		return ClientIP(ctx)
	}
}

// resolveMaxBuckets maps the configured cap to the internal value, where 0 means
// "unbounded": cfg 0 => DefaultMaxBuckets, cfg <0 => 0 (unbounded), cfg >0 => cfg.
func resolveMaxBuckets(cfg int) int {
	switch {
	case cfg == 0:
		return DefaultMaxBuckets
	case cfg < 0:
		return 0 // unbounded (idle sweep may still reclaim)
	default:
		return cfg
	}
}

// resolveIdleTTL maps the configured idle TTL to the internal value, where 0
// means "no idle sweeping". The effective TTL is never below the refill-to-full
// time (burst/rate seconds), guaranteeing an evicted idle bucket has refilled to
// full burst. cfg 0 => max(DefaultBucketIdleTTL, refill); <0 => 0 (disabled);
// >0 => max(cfg, refill).
func resolveIdleTTL(cfg time.Duration, rate float64, burst int) time.Duration {
	if cfg < 0 {
		return 0
	}
	floor := DefaultBucketIdleTTL
	if cfg > 0 {
		floor = cfg
	}
	// Clamp to avoid Duration (int64 ns) overflow on extreme burst/rate configs.
	const maxTTL = 24 * time.Hour
	refillToFull := maxTTL
	if d := time.Duration(float64(burst) / rate * float64(time.Second)); d > 0 && d < maxTTL {
		refillToFull = d
	}
	if refillToFull > floor {
		return refillToFull
	}
	return floor
}

// keyedLimiter holds one token bucket per key, created on demand. Memory is
// bounded two ways: an opportunistic idle sweep reclaims buckets untouched for
// `ttl` (which by construction have refilled to full burst, so eviction is
// loss-free), and a hard `maxBuckets` cap evicts the oldest-inserted bucket via
// an intrusive FIFO list so eviction is O(1) — no scan that a unique-key flood
// could amplify into CPU load.
//
// Locking: l.mu guards the map, the FIFO list (head/tail and every
// tb.prev/next/inList/key), and insertCt. Each tokenBucket's tokens/last are
// guarded by tb.mu. A bucket's recency (tb.lastSeen) is a lock-free atomic — the
// ONLY field eviction reads — so the sweep never takes tb.mu and there is no
// l.mu/tb.mu lock-ordering hazard.
type keyedLimiter struct {
	rate  float64
	burst int
	now   func() time.Time

	maxBuckets int           // 0 => unbounded
	ttl        time.Duration // 0 => idle sweeping disabled
	sweepEvery uint64        // insertions between idle sweeps; 0 => never sweep

	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	insertCt uint64       // bucket insertions; gates opportunistic sweeps
	head     *tokenBucket // most-recently-inserted
	tail     *tokenBucket // oldest-inserted (eviction victim)
}

// allow consumes one token from the bucket for key, creating it if needed.
// Eviction work is confined to the cold (new-key) path, so a steady-state hit on
// an existing key takes l.mu for exactly one map lookup — identical to before —
// then runs tb.allow() lock-free of l.mu.
func (l *keyedLimiter) allow(key string) bool {
	l.mu.Lock()
	if tb := l.buckets[key]; tb != nil {
		l.mu.Unlock()
		return tb.allow()
	}

	// Cold path: reclaim memory, then create + insert at the front of the list.
	l.insertCt++
	if l.ttl > 0 && l.sweepEvery > 0 && l.insertCt%l.sweepEvery == 0 {
		l.sweepLocked()
	}
	if l.maxBuckets > 0 && len(l.buckets) >= l.maxBuckets {
		if l.ttl > 0 {
			l.sweepLocked() // try a cheap reclaim before force-evicting
		}
		for len(l.buckets) >= l.maxBuckets && l.evictOldestLocked() {
		}
	}
	tb := newTokenBucket(l.rate, l.burst, l.now)
	tb.key = key
	l.buckets[key] = tb
	l.pushFrontLocked(tb)
	l.mu.Unlock()
	return tb.allow()
}

// sweepLocked deletes buckets untouched for at least ttl. Such a bucket has
// refilled to full burst (ttl >= refill-to-full by construction), so dropping it
// is indistinguishable from never having created it. Reads recency via the
// lock-free atomic only — never tb.mu. Caller holds l.mu.
func (l *keyedLimiter) sweepLocked() {
	cutoff := l.now().Add(-l.ttl).UnixNano()
	for _, tb := range l.buckets {
		if tb.lastSeen.Load() < cutoff {
			l.unlinkLocked(tb)
			delete(l.buckets, tb.key)
		}
	}
}

// evictOldestLocked removes the oldest-inserted bucket (the FIFO tail) in O(1),
// returning false if the list is empty. Caller holds l.mu. Under a sustained
// flood that exceeds the cap this may drop a still-active bucket; that client
// then gets a fresh full bucket — more permissive, never less — a deliberate
// fail-open trade that bounds memory without handing an attacker extra capacity
// (a fresh key already gets a full bucket).
func (l *keyedLimiter) evictOldestLocked() bool {
	v := l.tail
	if v == nil {
		return false
	}
	l.unlinkLocked(v)
	delete(l.buckets, v.key)
	return true
}

// pushFrontLocked inserts tb as the most-recently-inserted (head). Caller holds l.mu.
func (l *keyedLimiter) pushFrontLocked(tb *tokenBucket) {
	tb.prev = nil
	tb.next = l.head
	if l.head != nil {
		l.head.prev = tb
	}
	l.head = tb
	if l.tail == nil {
		l.tail = tb
	}
	tb.inList = true
}

// unlinkLocked removes tb from the FIFO list. Idempotent via inList. Caller holds l.mu.
func (l *keyedLimiter) unlinkLocked(tb *tokenBucket) {
	if !tb.inList {
		return
	}
	if tb.prev != nil {
		tb.prev.next = tb.next
	} else {
		l.head = tb.next
	}
	if tb.next != nil {
		tb.next.prev = tb.prev
	} else {
		l.tail = tb.prev
	}
	tb.prev, tb.next, tb.inList = nil, nil, false
}

// bucketCount returns the number of live buckets (for tests/observability).
func (l *keyedLimiter) bucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// tokenBucket is a self-contained token-bucket rate limiter. Tokens refill
// continuously at `rate` per second up to a maximum of `burst`. It is safe
// for concurrent use.
type tokenBucket struct {
	rate  float64 // tokens added per second
	burst float64 // maximum token capacity
	now   func() time.Time

	// lastSeen is the UnixNano of the most recent allow(). It is the ONLY field
	// the limiter's eviction logic reads, accessed solely via atomic Load/Store
	// (independent of mu) so a sweep reads it without taking mu and without
	// racing the Store here. Deliberately separate from `last` (which drives
	// token math under mu): eviction must never read `last`.
	lastSeen atomic.Int64

	mu     sync.Mutex
	tokens float64   // current tokens (fractional); refilled lazily on allow
	last   time.Time // timestamp tokens was last updated

	// Intrusive FIFO list node — guarded by keyedLimiter.mu, NOT mu. Touched
	// only when a bucket is inserted or evicted, never on a hit.
	key    string
	prev   *tokenBucket
	next   *tokenBucket
	inList bool
}

// newTokenBucket returns a full bucket (tokens == burst) with the given refill
// rate (per second) and capacity, using clock as its time source.
func newTokenBucket(rate float64, burst int, clock func() time.Time) *tokenBucket {
	if clock == nil {
		clock = time.Now
	}
	now := clock()
	b := &tokenBucket{
		rate:   rate,
		burst:  float64(burst),
		now:    clock,
		tokens: float64(burst),
		last:   now,
	}
	b.lastSeen.Store(now.UnixNano())
	return b
}

// allow refills the bucket for the elapsed time and consumes one token,
// returning true if a token was available.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	// Publish recency for the eviction sweep. The atomic store is what makes the
	// cross-goroutine read in sweepLocked race-free, independent of b.mu.
	b.lastSeen.Store(now.UnixNano())

	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
