// Package middleware provides standard production-ready middlewares for
// the Poseidon HTTP/2 server.
//
// All middlewares follow the onion model and are safe for concurrent use.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Recovery — panic → 500
// ---------------------------------------------------------------------------

// Logger is the minimal logging interface used by middlewares.
type Logger interface {
	Printf(format string, args ...interface{})
}

// Recovery returns a middleware that catches panics and converts them
// to 500 Internal Server Error responses.
func Recovery(log Logger) server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) (err error) {
			defer func() {
				if r := recover(); r != nil {
					stack := debug.Stack()
					if log != nil {
						log.Printf("poseidon: panic recovered: %v\n%s", r, stack)
					}
					if !w.Written() {
						_ = w.WriteHeaders(http.StatusInternalServerError, nil)
					}
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

// ---------------------------------------------------------------------------
// RequestID — inject unique request ID
// ---------------------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = 0

// requestIDField is the response field name, precomputed. HTTP/2 and HTTP/3
// field names are lowercase on the wire (RFC 9113 §8.2.1).
var requestIDField = []byte("x-request-id")

// requestIDHeader is the same name in http.Header's canonical form, for the
// stdlib path's map.
const requestIDHeader = "X-Request-Id"

// RequestID returns a middleware that injects a unique request ID into the
// context and echoes it back as an X-Request-ID response header.
//
// The id is taken from the request's own x-request-id when the client supplied
// one, so a value assigned upstream survives this hop, and generated otherwise.
//
// It reaches the response through a wrapping writer rather than a plain
// w.Header().Set, for the reason SecurityHeaders wraps: setting the map only
// works for a handler that answers through the stdlib path, and a handler using
// the native WriteHeaders path would never carry it. Until issue #213 the header
// was documented here and set nowhere — the id existed only inside the process,
// which cannot do the one thing a request id is for, matching a client's report
// to a server's log line.
//
// A handler that sets X-Request-ID itself keeps its value.
func RequestID() server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			id := ""
			for _, h := range req.Headers {
				if string(h.Name) == "x-request-id" {
					id = string(h.Value)
					break
				}
			}
			if id == "" {
				id = generateRequestID()
			}

			ctx = context.WithValue(ctx, requestIDKey, id)
			return next.ServeHTTP(ctx, req, &requestIDResponseWriter{ResponseWriter: w, id: id})
		})
	}
}

// requestIDResponseWriter echoes the request id on whichever header-writing path
// the handler uses. It mirrors securityResponseWriter in middleware/security.go;
// the two differ only in what they inject.
type requestIDResponseWriter struct {
	server.ResponseWriter // wrapped writer; Header()/Status()/etc. delegate

	id string
}

// WriteHeaders injects the id on the native path, unless the handler supplied
// its own.
func (r *requestIDResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	if r.Written() || fieldPresent(headers, "x-request-id") {
		return r.ResponseWriter.WriteHeaders(status, headers)
	}
	// A fresh slice rather than append(headers, …): the caller owns that array,
	// and appending into its spare capacity would write a field into storage it
	// may still be using. One allocation per response, on a path that is already
	// allocating the id — ADR-0001 scopes the zero-allocation contract to the
	// native write path in server/, not to middleware wrappers.
	merged := make([]hpack.HeaderField, 0, len(headers)+1)
	merged = append(merged, headers...)
	merged = append(merged, hpack.HeaderField{Name: requestIDField, Value: []byte(r.id)})
	return r.ResponseWriter.WriteHeaders(status, merged)
}

// WriteData forwards body chunks; a handler that skipped WriteHeaders still gets
// the id, through the auto-200 above.
func (r *requestIDResponseWriter) WriteData(p []byte) error {
	if !r.Written() {
		if err := r.WriteHeaders(200, nil); err != nil {
			return err
		}
	}
	return r.ResponseWriter.WriteData(p)
}

// WriteHeader injects the id into the wrapped writer's Header() map (stdlib
// path), unless the handler already set one.
func (r *requestIDResponseWriter) WriteHeader(status int) {
	if !r.Written() {
		if h := r.Header(); h.Get(requestIDHeader) == "" {
			h.Set(requestIDHeader, r.id)
		}
	}
	r.ResponseWriter.WriteHeader(status)
}

// Write forwards body chunks; auto-200 goes through WriteHeader so the id is
// still injected when a handler writes a body without an explicit status.
func (r *requestIDResponseWriter) Write(p []byte) (int, error) {
	if !r.Written() {
		r.WriteHeader(200)
	}
	return r.ResponseWriter.Write(p)
}

// Unwrap returns the wrapped writer so server.PusherOf / server.FlusherOf can
// walk the chain — otherwise enabling RequestID would silently disable Server
// Push, which is the bug the same method on securityResponseWriter exists to
// avoid.
func (r *requestIDResponseWriter) Unwrap() server.ResponseWriter { return r.ResponseWriter }

// FromContext extracts the request ID from a context.
func FromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func generateRequestID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// ---------------------------------------------------------------------------
// AccessLog — structured request logging
// ---------------------------------------------------------------------------

// AccessLog returns a middleware that logs each request after completion.
func AccessLog(log Logger) server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			start := time.Now()
			err := next.ServeHTTP(ctx, req, w)

			if log != nil {
				id := FromContext(ctx)
				log.Printf("%s %s %d %v id=%s",
					req.Method, req.Path, w.StatusCode(),
					time.Since(start), id)
			}
			return err
		})
	}
}

// ---------------------------------------------------------------------------
// CORS — Cross-Origin Resource Sharing
// ---------------------------------------------------------------------------

// CORSConfig holds CORS middleware configuration.
type CORSConfig struct {
	AllowOrigins []string
	AllowMethods []string
	AllowHeaders []string
	MaxAge       int // seconds
}

// DefaultCORSConfig returns a permissive CORS configuration for development.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:       86400,
	}
}

// CORS returns a middleware that handles CORS preflight requests.
// For actual requests, CORS headers are appended to the response.
func CORS(cfg CORSConfig) server.Middleware {
	origin := "*"
	if len(cfg.AllowOrigins) == 1 {
		origin = cfg.AllowOrigins[0]
	}

	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			if req.Method == "OPTIONS" {
				// Preflight: respond immediately with CORS headers.
				headers := corsHeaders(cfg, origin)
				return w.WriteHeaders(http.StatusNoContent, headers)
			}

			// For non-preflight: let handler run, then CORS headers are
			// applied by the handler via WriteHeaders. This middleware
			// just passes through — actual CORS header injection for
			// non-preflight is the handler's responsibility (or use
			// http.Handler adapter for automatic injection).
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

func corsHeaders(cfg CORSConfig, origin string) []hpack.HeaderField {
	methods := joinStrings(cfg.AllowMethods, ", ")
	if methods == "" {
		methods = "GET, POST, PUT, DELETE, OPTIONS"
	}
	headers := joinStrings(cfg.AllowHeaders, ", ")
	if headers == "" {
		headers = "Content-Type, Authorization"
	}
	return []hpack.HeaderField{
		{Name: []byte("access-control-allow-origin"), Value: []byte(origin)},
		{Name: []byte("access-control-allow-methods"), Value: []byte(methods)},
		{Name: []byte("access-control-allow-headers"), Value: []byte(headers)},
		{Name: []byte("access-control-max-age"), Value: []byte(fmt.Sprintf("%d", cfg.MaxAge))},
	}
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}
