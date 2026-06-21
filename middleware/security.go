package middleware

import (
	"context"
	"strconv"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// SecurityHeaders — standard security response headers
// ---------------------------------------------------------------------------

// Default values for the security headers, chosen for a secure-by-default
// posture suitable for an HTTPS API/web origin.
const (
	// defaultHSTSMaxAge is one year, the value recommended for HSTS preload.
	defaultHSTSMaxAge = 31536000
	// defaultReferrerPolicy leaks no referrer information cross-origin.
	defaultReferrerPolicy = "no-referrer"
	// defaultFrameOptions forbids framing entirely (clickjacking protection).
	defaultFrameOptions = "DENY"
	// nosniff disables MIME-type sniffing.
	valNosniff = "nosniff"
)

// SecurityHeadersConfig controls the SecurityHeaders middleware. The zero value
// is not recommended; use DefaultSecurityHeadersConfig and override fields.
type SecurityHeadersConfig struct {
	// HSTSMaxAge is the max-age (seconds) for Strict-Transport-Security.
	// When <= 0 the HSTS header is omitted entirely (e.g. for h2c/plaintext
	// origins where HSTS is meaningless).
	HSTSMaxAge int

	// HSTSIncludeSubDomains adds the includeSubDomains directive to HSTS.
	HSTSIncludeSubDomains bool

	// HSTSPreload adds the preload directive to HSTS. Only meaningful with a
	// large MaxAge and includeSubDomains (per the preload-list requirements).
	HSTSPreload bool

	// FrameOptions is the X-Frame-Options value (e.g. "DENY", "SAMEORIGIN").
	// Empty omits the header.
	FrameOptions string

	// ReferrerPolicy is the Referrer-Policy value. Empty omits the header.
	ReferrerPolicy string

	// ContentTypeNosniff sends X-Content-Type-Options: nosniff when true.
	ContentTypeNosniff bool

	// ContentSecurityPolicy is the Content-Security-Policy value. Empty (the
	// default) omits the header — CSP is opt-in because a wrong policy breaks
	// pages.
	ContentSecurityPolicy string
}

// DefaultSecurityHeadersConfig returns a secure-by-default configuration:
// HSTS (1 year, includeSubDomains), X-Content-Type-Options: nosniff,
// X-Frame-Options: DENY, Referrer-Policy: no-referrer, and no CSP.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		HSTSMaxAge:            defaultHSTSMaxAge,
		HSTSIncludeSubDomains: true,
		HSTSPreload:           false,
		FrameOptions:          defaultFrameOptions,
		ReferrerPolicy:        defaultReferrerPolicy,
		ContentTypeNosniff:    true,
		ContentSecurityPolicy: "",
	}
}

// securityHeader is a fully precomputed header to inject. Both the []byte form
// (native hpack path) and the string form (stdlib http.Header path + presence
// check) are computed once at init, so the per-request hot path allocates none.
type securityHeader struct {
	name     []byte // lower-cased name, native hpack path
	value    []byte // value, native hpack path
	nameStr  string // name, stdlib http.Header path + presence check
	valueStr string // value, stdlib http.Header path
}

// SecurityHeaders returns a middleware that injects standard security response
// headers (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and
// an optional Content-Security-Policy) into every response.
//
// Because [server.ResponseWriter] is an interface, the headers are injected by
// WRAPPING the writer (the same pattern the Gzip middleware uses): the wrapper
// intercepts WriteHeaders (native path) and WriteHeader (stdlib path) and adds
// the security fields just before the headers are sent. A header the handler
// already set is left untouched, so handlers can opt out of an individual
// default (e.g. relax X-Frame-Options to SAMEORIGIN) by setting it themselves.
func SecurityHeaders(cfg SecurityHeadersConfig) server.Middleware {
	headers := buildSecurityHeaders(cfg)

	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			sw := &securityResponseWriter{ResponseWriter: w, headers: headers}
			return next.ServeHTTP(ctx, req, sw)
		})
	}
}

// buildSecurityHeaders precomputes the slice of headers to inject from cfg, so
// the per-request hot path performs no string formatting.
func buildSecurityHeaders(cfg SecurityHeadersConfig) []securityHeader {
	out := make([]securityHeader, 0, 5)

	if cfg.HSTSMaxAge > 0 {
		v := "max-age=" + strconv.Itoa(cfg.HSTSMaxAge)
		if cfg.HSTSIncludeSubDomains {
			v += "; includeSubDomains"
		}
		if cfg.HSTSPreload {
			v += "; preload"
		}
		out = append(out, mkSecurityHeader("strict-transport-security", v))
	}
	if cfg.ContentTypeNosniff {
		out = append(out, mkSecurityHeader("x-content-type-options", valNosniff))
	}
	if cfg.FrameOptions != "" {
		out = append(out, mkSecurityHeader("x-frame-options", cfg.FrameOptions))
	}
	if cfg.ReferrerPolicy != "" {
		out = append(out, mkSecurityHeader("referrer-policy", cfg.ReferrerPolicy))
	}
	if cfg.ContentSecurityPolicy != "" {
		out = append(out, mkSecurityHeader("content-security-policy", cfg.ContentSecurityPolicy))
	}
	return out
}

// mkSecurityHeader precomputes both the []byte (native hpack) and string (stdlib
// http.Header) representations of a header so the request path allocates nothing.
func mkSecurityHeader(name, value string) securityHeader {
	return securityHeader{
		name:     []byte(name),
		value:    []byte(value),
		nameStr:  name,
		valueStr: value,
	}
}

// securityResponseWriter wraps a server.ResponseWriter and injects the security
// headers on whichever header-writing path the handler uses.
type securityResponseWriter struct {
	server.ResponseWriter // wrapped writer; Header()/Write/Status/etc. delegate

	headers []securityHeader
}

// WriteHeaders injects the security fields (native path) before forwarding,
// skipping any field the handler already supplied.
func (s *securityResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	if s.Written() {
		return s.ResponseWriter.WriteHeaders(status, headers)
	}
	merged := headers
	for i := range s.headers {
		sh := &s.headers[i]
		if fieldPresent(headers, sh.nameStr) {
			continue
		}
		// sh.name / sh.value are precomputed at init — no per-request allocation.
		merged = append(merged, hpack.HeaderField{Name: sh.name, Value: sh.value})
	}
	return s.ResponseWriter.WriteHeaders(status, merged)
}

// WriteData forwards body chunks; if the handler skipped WriteHeaders the
// security headers are injected first via the auto-200 path.
func (s *securityResponseWriter) WriteData(p []byte) error {
	if !s.Written() {
		if err := s.WriteHeaders(200, nil); err != nil {
			return err
		}
	}
	return s.ResponseWriter.WriteData(p)
}

// WriteHeader injects the security fields into the wrapped writer's Header()
// map (stdlib path) before forwarding, skipping fields already present.
func (s *securityResponseWriter) WriteHeader(status int) {
	if !s.Written() {
		h := s.Header()
		for i := range s.headers {
			sh := &s.headers[i]
			if h.Get(sh.nameStr) == "" {
				h.Set(sh.nameStr, sh.valueStr)
			}
		}
	}
	s.ResponseWriter.WriteHeader(status)
}

// Write forwards body chunks; auto-200 goes through WriteHeader so the headers
// are still injected when a handler writes a body without an explicit status.
func (s *securityResponseWriter) Write(p []byte) (int, error) {
	if !s.Written() {
		s.WriteHeader(200)
	}
	return s.ResponseWriter.Write(p)
}

// --- Push delegation (server.Pusher) ----------------------------------------
//
// Pushed responses are forwarded unchanged so enabling SecurityHeaders does not
// silently disable Server Push.

func (s *securityResponseWriter) Push(promisePath string, promiseHeaders []hpack.HeaderField) (server.ResponseWriter, error) {
	if p, ok := s.ResponseWriter.(server.Pusher); ok {
		return p.Push(promisePath, promiseHeaders)
	}
	return nil, server.ErrPushNotSupported
}

func (s *securityResponseWriter) PushWithScheme(promisePath, promiseScheme string, promiseHeaders []hpack.HeaderField) (server.ResponseWriter, error) {
	if p, ok := s.ResponseWriter.(server.Pusher); ok {
		return p.PushWithScheme(promisePath, promiseScheme, promiseHeaders)
	}
	return nil, server.ErrPushNotSupported
}

func (s *securityResponseWriter) PushWithPriority(promisePath string, promiseHeaders []hpack.HeaderField, prio *frame.Priority) (server.ResponseWriter, error) {
	if p, ok := s.ResponseWriter.(server.Pusher); ok {
		return p.PushWithPriority(promisePath, promiseHeaders, prio)
	}
	return nil, server.ErrPushNotSupported
}

// fieldPresent reports whether headers already contains a field with the given
// (lower-cased) name.
func fieldPresent(headers []hpack.HeaderField, name string) bool {
	for _, h := range headers {
		if string(h.Name) == name {
			return true
		}
	}
	return false
}
