package middleware

import (
	"context"
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/server"
)

func TestMetricsCollector_RequestCounting(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		return nil
	}))

	for range 3 {
		_ = handler.ServeHTTP(context.Background(), &server.Request{
			Method: "GET",
			Path:   "/api",
		}, server.NewResponseWriter(nil))
	}

	if got := mc.TotalRequests("GET", "/api", 200); got != 3 {
		t.Fatalf("TotalRequests = %d, want 3", got)
	}
}

func TestMetricsCollector_DifferentPaths(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		return nil
	}))

	paths := []string{"/ok", "/ok", "/error"}
	for _, p := range paths {
		_ = handler.ServeHTTP(context.Background(), &server.Request{
			Method: "GET",
			Path:   p,
		}, server.NewResponseWriter(nil))
	}

	if got := mc.TotalRequests("GET", "/ok", 200); got != 2 {
		t.Fatalf("/ok 200 = %d, want 2", got)
	}
	if got := mc.TotalRequests("GET", "/error", 200); got != 1 {
		t.Fatalf("/error 200 = %d, want 1", got)
	}
}

func TestMetricsCollector_ActiveRequests(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	if got := mc.ActiveRequests(); got != 0 {
		t.Fatalf("initial ActiveRequests = %d, want 0", got)
	}
}

func TestMetricsCollector_WritePrometheus(t *testing.T) {
	mc := NewMetricsCollector()

	mc.getOrCreateCounter("GET|/api|200").Add(5)
	mc.getOrCreateCounter("POST|/api|201").Add(2)
	mc.getOrCreateDuration("GET|/api").Add(1000000000) // 1s in ns
	mc.active.Add(3)

	output := mc.WritePrometheus()

	checks := []string{
		"poseidon_requests_total",
		"GET",
		"/api",
		"poseidon_active_requests",
		"poseidon_request_duration_seconds_total",
		"poseidon_active_requests 3",
	}
	for _, s := range checks {
		if !strings.Contains(output, s) {
			t.Errorf("missing %q in output:\n%s", s, output)
		}
	}
}

func TestMetricsCollector_MetricsHandler(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mc.getOrCreateCounter("GET|/metrics|200").Add(1)

	h := mc.MetricsHandler()
	if h == nil {
		t.Fatal("MetricsHandler returned nil")
	}
	var _ server.Handler = h
}

func TestMetricsCollector_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		return nil
	}))

	done := make(chan struct{}, 10)
	for range 10 {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = handler.ServeHTTP(context.Background(), &server.Request{
				Method: "GET",
				Path:   "/concurrent",
			}, server.NewResponseWriter(nil))
		}()
	}

	for range 10 {
		<-done
	}

	if got := mc.TotalRequests("GET", "/concurrent", 200); got != 10 {
		t.Fatalf("TotalRequests = %d, want 10", got)
	}
}

func TestMetricsCollector_BodyTracking(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	body := []byte("request body data")
	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		return nil
	}))

	_ = handler.ServeHTTP(context.Background(), &server.Request{
		Method: "POST",
		Path:   "/upload",
		Body:   body,
	}, server.NewResponseWriter(nil))

	dKey := durationKey("POST", "/upload")
	mc.mu.RLock()
	reqBytesCtr, ok := mc.reqBytes[dKey]
	mc.mu.RUnlock()

	if !ok {
		t.Fatal("request body bytes not tracked")
	}
	if got := reqBytesCtr.Load(); got != int64(len(body)) {
		t.Fatalf("reqBytes = %d, want %d", got, len(body))
	}
}

func TestMetricsCollector_EmptyRequest(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ *server.ResponseWriter) error {
		return nil
	}))

	_ = handler.ServeHTTP(context.Background(), &server.Request{}, server.NewResponseWriter(nil))
}
