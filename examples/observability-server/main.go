// Package main demonstrates the Poseidon HTTP/2 server wired for production
// observability: a Prometheus /metrics endpoint, structured JSON access logs
// (log/slog), distributed-tracing hooks, opt-in pprof profiling endpoints, and
// Kubernetes-style liveness (/healthz) and readiness (/readyz) probes.
//
// What this example shows (all built on the REAL exported APIs):
//
//   - middleware.MetricsCollector: RED metrics (requests, errors, duration
//     histograms) exposed in Prometheus text format via MetricsCollector.
//     MetricsHandler(), served at GET /metrics.
//   - middleware.StructuredAccessLog(*slog.Logger): one structured JSON log
//     line per request (method, path, status, duration_ms, request_id).
//   - middleware.Tracing(TracingConfig{Tracer: ...}): every request is wrapped
//     in a span. A tiny stdout Tracer is provided here; swap in an
//     OpenTelemetry adapter in production.
//   - server.HealthState + server.HealthHandler: /healthz (liveness, always
//     200 while serving) and /readyz (readiness, 200 -> 503 at drain start).
//     HealthState.SetNotReady is wired into Options.OnDrainStart so Kubernetes
//     stops routing traffic before in-flight streams drain.
//   - server.PprofHandler(): opt-in Go runtime profiling under /debug/pprof/.
//     Mount it ONLY behind a private listener / auth in production.
//
// Run:
//
//	go run ./examples/observability-server
//
// Try it (HTTP/2 cleartext, prior knowledge):
//
//	curl --http2-prior-knowledge http://localhost:8080/
//	curl --http2-prior-knowledge http://localhost:8080/metrics
//	curl --http2-prior-knowledge http://localhost:8080/healthz
//	curl --http2-prior-knowledge http://localhost:8080/readyz
//	curl --http2-prior-knowledge http://localhost:8080/debug/pprof/
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

func main() {
	// --- Structured JSON logger (log/slog) -------------------------------
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// --- Metrics collector (Prometheus RED metrics) ----------------------
	metrics := middleware.NewMetricsCollector()

	// --- Readiness state; flipped to NOT-ready at drain start ------------
	health := server.NewHealthState()

	// --- Sub-handlers -----------------------------------------------------
	metricsHandler := metrics.MetricsHandler() // GET /metrics
	healthHandler := server.HealthHandler(health)
	pprofHandler := server.PprofHandler() // /debug/pprof/*

	// Application router. We dispatch the observability endpoints first so
	// they bypass the demo middleware noise, then fall through to the app.
	app := server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		path, _ := splitPath(req.Path)
		switch {
		case path == "/metrics":
			return metricsHandler.ServeHTTP(ctx, req, w)
		case path == server.LivenessPath, path == server.ReadinessPath:
			return healthHandler.ServeHTTP(ctx, req, w)
		case strings.HasPrefix(path, "/debug/pprof/"):
			return pprofHandler.ServeHTTP(ctx, req, w)
		case path == "/":
			return w.WriteData([]byte("Poseidon observability server\n"))
		case path == "/slow":
			// A deliberately slow route to populate the latency histogram.
			time.Sleep(150 * time.Millisecond)
			return w.WriteData([]byte("done\n"))
		default:
			return w.WriteHeaders(http.StatusNotFound, nil)
		}
	})

	// --- Server with the observability middleware chain ------------------
	srv, err := server.NewServer(server.Options{
		Addr:        ":8080",
		Handler:     app,
		IdleTimeout: 30 * time.Second,
		// Flip readiness to NOT-ready at the very start of Shutdown so k8s
		// removes this pod from Service endpoints before streams drain.
		OnDrainStart: func() {
			logger.Info("drain start: marking not-ready")
			health.SetNotReady()
		},
		Middleware: []server.Middleware{
			middleware.Recovery(middleware.LoggerFromSlog(logger)),
			middleware.RequestID(),
			middleware.StructuredAccessLog(logger),
			middleware.Tracing(middleware.TracingConfig{Tracer: stdoutTracer{logger}}),
			metrics.Metrics(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		logger.Info("listening", "addr", ":8080", "proto", "h2c")
		if err := srv.Serve(ctx, ln); err != nil {
			logger.Error("serve stopped", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("draining")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		logger.Error("drain", "err", err)
	}
}

// splitPath returns the path component of a raw :path value (everything before
// the '?'), discarding any query string.
func splitPath(raw string) (path, query string) {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

// stdoutTracer is a minimal middleware.Tracer that logs span lifecycle to slog.
// In production, replace it with an OpenTelemetry / OpenTracing adapter — the
// middleware.Tracer / middleware.Span interfaces map 1:1 onto OTel semantics.
type stdoutTracer struct{ logger *slog.Logger }

func (t stdoutTracer) StartSpan(ctx context.Context, name string) (context.Context, middleware.Span) {
	return ctx, &stdoutSpan{logger: t.logger, name: name, start: time.Now()}
}

type stdoutSpan struct {
	logger *slog.Logger
	name   string
	start  time.Time
	status int
}

func (s *stdoutSpan) SetAttribute(key string, value any) { _ = key; _ = value }
func (s *stdoutSpan) SetStatus(code int)                 { s.status = code }
func (s *stdoutSpan) End() {
	s.logger.Debug("span",
		slog.String("name", s.name),
		slog.Int("status", s.status),
		slog.String("duration", fmt.Sprintf("%v", time.Since(s.start))),
	)
}
