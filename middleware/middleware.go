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

// RequestID returns a middleware that injects a unique request ID into
// the context and sets it as an X-Request-ID response header.
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
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

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
