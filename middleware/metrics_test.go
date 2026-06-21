package middleware

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

func TestMetricsCollector_RequestCounting(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
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

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
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

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
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
	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
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

func TestMetricsCollector_HistogramObservations(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()

	// Observe durations that land in distinct default buckets:
	//   1ms  -> first bucket whose le >= 0.001 (i.e. 0.005)
	//   30ms -> 0.05
	//   300ms-> 0.5
	//   3s   -> 5
	mc.ObserveDuration("GET", "/h", 1*time.Millisecond)
	mc.ObserveDuration("GET", "/h", 30*time.Millisecond)
	mc.ObserveDuration("GET", "/h", 300*time.Millisecond)
	mc.ObserveDuration("GET", "/h", 3*time.Second)

	output := mc.WritePrometheus()

	// TYPE line and metric family must be present.
	wantSubstrings := []string{
		"# TYPE poseidon_request_duration_seconds histogram",
		`poseidon_request_duration_seconds_bucket{method="GET",path="/h",le="+Inf"} 4`,
		`poseidon_request_duration_seconds_count{method="GET",path="/h"} 4`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(output, s) {
			t.Errorf("missing %q in output:\n%s", s, output)
		}
	}

	// Cumulative bucket monotonicity: le="0.005" should have 1 (the 1ms obs),
	// le="0.05" should have 2 (1ms + 30ms), le="0.5" should have 3, le="5" 4.
	bucketChecks := map[string]string{
		`le="0.005"`: `poseidon_request_duration_seconds_bucket{method="GET",path="/h",le="0.005"} 1`,
		`le="0.05"`:  `poseidon_request_duration_seconds_bucket{method="GET",path="/h",le="0.05"} 2`,
		`le="0.5"`:   `poseidon_request_duration_seconds_bucket{method="GET",path="/h",le="0.5"} 3`,
		`le="5"`:     `poseidon_request_duration_seconds_bucket{method="GET",path="/h",le="5"} 4`,
	}
	for name, line := range bucketChecks {
		if !strings.Contains(output, line) {
			t.Errorf("bucket %s: missing line %q in output:\n%s", name, line, output)
		}
	}

	// _sum should equal total seconds observed: 0.001+0.03+0.3+3 = 3.331.
	if !strings.Contains(output, `poseidon_request_duration_seconds_sum{method="GET",path="/h"}`) {
		t.Errorf("missing _sum line in output:\n%s", output)
	}
}

func TestMetricsCollector_HistogramOverflowBucket(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	// 15s exceeds the largest finite bucket (10s): it must count ONLY in the
	// +Inf bucket, not in any finite bucket.
	mc.ObserveDuration("GET", "/big", 15*time.Second)

	output := mc.WritePrometheus()
	checks := []string{
		`poseidon_request_duration_seconds_bucket{method="GET",path="/big",le="10"} 0`,
		`poseidon_request_duration_seconds_bucket{method="GET",path="/big",le="+Inf"} 1`,
		`poseidon_request_duration_seconds_count{method="GET",path="/big"} 1`,
	}
	for _, s := range checks {
		if !strings.Contains(output, s) {
			t.Errorf("over-max histogram: missing %q in output:\n%s", s, output)
		}
	}
}

func TestMetricsCollector_HistogramRecordedViaMiddleware(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		return nil
	}))

	for range 5 {
		_ = handler.ServeHTTP(context.Background(), &server.Request{
			Method: "GET",
			Path:   "/mw",
		}, server.NewResponseWriter(nil))
	}

	output := mc.WritePrometheus()
	if !strings.Contains(output, `poseidon_request_duration_seconds_count{method="GET",path="/mw"} 5`) {
		t.Errorf("histogram count not recorded via middleware:\n%s", output)
	}
}

func TestMetricsCollector_EmptyRequest(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mw := mc.Metrics()

	handler := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		return nil
	}))

	_ = handler.ServeHTTP(context.Background(), &server.Request{}, server.NewResponseWriter(nil))
}
