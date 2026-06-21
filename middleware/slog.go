package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Structured logging (log/slog) — additive, non-breaking complement to the
// Printf-based Logger / AccessLog defined in middleware.go.
// ---------------------------------------------------------------------------

// bytesWritten is the optional capability a ResponseWriter may implement to
// expose how many response-body bytes it has written. When present, the
// structured access log includes a bytes_written attribute. It is kept
// separate (mirroring server.Pusher) so the core ResponseWriter interface
// stays small; absence simply omits the attribute.
type bytesWritten interface {
	BytesWritten() int
}

// StructuredAccessLog returns a middleware that emits exactly one structured
// slog record per request after the handler returns. Attributes:
//
//   - method       — request method
//   - path         — request :path
//   - status       — final status read from the ResponseWriter
//   - duration_ms  — handler wall-clock duration in milliseconds
//   - request_id   — from FromContext(ctx); omitted when empty
//   - bytes_written — only when the ResponseWriter exposes BytesWritten()
//
// The slog level is chosen by status class: 5xx → Error, 4xx → Warn, else Info.
// Logging runs in a defer so the record is still emitted if the handler panics —
// in which case the status is recorded as 500; the panic is then re-raised and is
// never swallowed.
func StructuredAccessLog(logger *slog.Logger) server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) (err error) {
			start := time.Now()
			defer func() {
				rec := recover()
				if logger != nil {
					status := w.StatusCode()
					if rec != nil {
						// Handler panicked before writing a status: record a 500
						// (server error) rather than the unwritten 0.
						status = 500
					}
					attrs := make([]slog.Attr, 0, 6)
					attrs = append(attrs,
						slog.String("method", req.Method),
						slog.String("path", req.Path),
						slog.Int("status", status),
						slog.Int64("duration_ms", time.Since(start).Milliseconds()),
					)
					if id := FromContext(ctx); id != "" {
						attrs = append(attrs, slog.String("request_id", id))
					}
					if bw, ok := w.(bytesWritten); ok {
						attrs = append(attrs, slog.Int("bytes_written", bw.BytesWritten()))
					}
					logger.LogAttrs(ctx, levelForStatus(status), "request", attrs...)
				}
				// Re-raise a recovered panic so it still propagates — logging must
				// never swallow it.
				if rec != nil {
					panic(rec)
				}
			}()
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

// levelForStatus maps an HTTP status code to an slog level by class:
// 5xx → Error, 4xx → Warn, everything else → Info.
func levelForStatus(status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case status >= 400:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// LoggerFromSlog adapts an *slog.Logger to the legacy Printf-based Logger
// interface, so the existing AccessLog and Recovery middlewares can route
// through slog without modification. Each Printf call is formatted with
// fmt.Sprintf and emitted as a single slog Info record.
func LoggerFromSlog(l *slog.Logger) Logger {
	return slogLogger{l: l}
}

type slogLogger struct {
	l *slog.Logger
}

func (s slogLogger) Printf(format string, args ...interface{}) {
	if s.l == nil {
		return
	}
	s.l.Info(fmt.Sprintf(format, args...))
}
