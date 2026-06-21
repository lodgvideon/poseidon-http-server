package middleware

import (
	"context"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Tracing — vendor-neutral distributed-tracing hooks
// ---------------------------------------------------------------------------
//
// This middleware starts a span per request and ends it when the handler
// returns, recording the request method, path, and response status. The
// Tracer/Span interfaces are intentionally minimal and vendor-neutral so an
// OpenTelemetry (or any other) adapter can be plugged in later WITHOUT this
// package taking on an otel dependency.
//
// Example OpenTelemetry adapter (lives in the caller's code, not here):
//
//	type otelTracer struct{ tr trace.Tracer }
//
//	func (t otelTracer) StartSpan(ctx context.Context, name string) (context.Context, middleware.Span) {
//		ctx, sp := t.tr.Start(ctx, name)
//		return ctx, otelSpan{sp}
//	}
//
//	type otelSpan struct{ sp trace.Span }
//	func (s otelSpan) SetAttribute(k string, v any) { s.sp.SetAttributes(toKV(k, v)) }
//	func (s otelSpan) SetStatus(code int)           { /* map HTTP code → otelcodes */ }
//	func (s otelSpan) End()                         { s.sp.End() }

// Span is a single in-flight unit of tracing work. Implementations must be
// safe for the sequential calls the middleware makes (SetAttribute*, SetStatus,
// then End); they need not be safe for concurrent use by multiple goroutines.
type Span interface {
	// SetAttribute records a typed key/value pair on the span.
	SetAttribute(key string, value any)
	// SetStatus records the final status of the span (HTTP status code).
	SetStatus(code int)
	// End marks the span complete. Called exactly once per span.
	End()
}

// Tracer starts spans. An adapter for any tracing backend (OpenTelemetry,
// OpenTracing, a custom collector) can implement this interface.
type Tracer interface {
	// StartSpan begins a new span named name, returning a context that carries
	// the span (so downstream handlers can create child spans) and the Span
	// itself. Implementations must not return a nil Span.
	StartSpan(ctx context.Context, name string) (context.Context, Span)
}

// Standard span attribute keys, aligned with OpenTelemetry HTTP semantic
// conventions so adapters can map them 1:1.
const (
	attrHTTPMethod     = "http.method"
	attrHTTPPath       = "http.path"
	attrHTTPStatusCode = "http.status_code"
)

// TracingConfig configures the Tracing middleware.
type TracingConfig struct {
	// Tracer is the span factory. If nil, the middleware is a pure
	// pass-through with zero per-request overhead.
	Tracer Tracer
}

// Tracing returns a middleware that wraps each request in a span produced by
// cfg.Tracer. The span name is "<method> <path>" and it carries the
// http.method, http.path, and (after the handler returns) http.status_code
// attributes plus the final status.
//
// If cfg.Tracer is nil the middleware returns the next handler unchanged, so
// disabled tracing costs nothing.
func Tracing(cfg TracingConfig) server.Middleware {
	tracer := cfg.Tracer
	return func(next server.Handler) server.Handler {
		// Nil/unconfigured Tracer => pass-through (zero overhead): no wrapper
		// closure, no allocation, no span work per request.
		if tracer == nil {
			return next
		}
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			ctx, span := tracer.StartSpan(ctx, req.Method+" "+req.Path)
			span.SetAttribute(attrHTTPMethod, req.Method)
			span.SetAttribute(attrHTTPPath, req.Path)

			// End the span (recording the final status) even if the handler
			// panics — otherwise a panicking handler would leak the span. The
			// panic is re-raised after the span is closed so the Recovery
			// middleware (or the server) still handles it.
			defer func() {
				if r := recover(); r != nil {
					span.SetAttribute(attrHTTPStatusCode, 500)
					span.SetStatus(500)
					span.End()
					panic(r)
				}
				status := w.StatusCode()
				if status == 0 {
					status = 200
				}
				span.SetAttribute(attrHTTPStatusCode, status)
				span.SetStatus(status)
				span.End()
			}()

			return next.ServeHTTP(ctx, req, w)
		})
	}
}
