package middleware

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// RateLimit — token-bucket request limiting
// ---------------------------------------------------------------------------

// defaultRateLimit is the per-second token refill rate used when
// RateLimitConfig.Rate is unset (<= 0).
const defaultRateLimit = 100

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
		rate:    rate,
		burst:   burst,
		now:     clock,
		buckets: make(map[string]*tokenBucket),
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
// Note: the limiter holds one bucket per distinct key and does not currently
// evict idle buckets, so the key space should stay bounded. Run RealIP with a
// TrustedProxies allowlist so the key is a real upstream IP rather than an
// attacker-spoofable forwarding header, and note that IPv6 keys are per-/128
// (a single client can span a large range).
func KeyByClientIP() func(ctx context.Context, req *server.Request) string {
	return func(ctx context.Context, _ *server.Request) string {
		return ClientIP(ctx)
	}
}

// keyedLimiter holds one token bucket per key, created on demand.
type keyedLimiter struct {
	rate  float64
	burst int
	now   func() time.Time

	mu      sync.Mutex // guards buckets map
	buckets map[string]*tokenBucket
}

// allow consumes one token from the bucket for key, creating it if needed.
func (l *keyedLimiter) allow(key string) bool {
	l.mu.Lock()
	tb := l.buckets[key]
	if tb == nil {
		tb = newTokenBucket(l.rate, l.burst, l.now)
		l.buckets[key] = tb
	}
	l.mu.Unlock()
	return tb.allow()
}

// tokenBucket is a self-contained token-bucket rate limiter. Tokens refill
// continuously at `rate` per second up to a maximum of `burst`. It is safe
// for concurrent use.
type tokenBucket struct {
	rate  float64 // tokens added per second
	burst float64 // maximum token capacity
	now   func() time.Time

	mu     sync.Mutex
	tokens float64   // current tokens (fractional); refilled lazily on allow
	last   time.Time // timestamp tokens was last updated
}

// newTokenBucket returns a full bucket (tokens == burst) with the given refill
// rate (per second) and capacity, using clock as its time source.
func newTokenBucket(rate float64, burst int, clock func() time.Time) *tokenBucket {
	if clock == nil {
		clock = time.Now
	}
	return &tokenBucket{
		rate:   rate,
		burst:  float64(burst),
		now:    clock,
		tokens: float64(burst),
		last:   clock(),
	}
}

// allow refills the bucket for the elapsed time and consumes one token,
// returning true if a token was available.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
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
