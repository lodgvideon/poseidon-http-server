package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestParseSize_Deterministic pins the fix for the critical map-iteration bug:
// every unit suffix ends in "B", so a map-based parser let "B" win for "16MiB"
// on a random fraction of calls (→ 16 bytes instead of 16 MiB). The ordered
// slice must resolve every input identically every time.
func TestParseSize_Deterministic(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"16MiB", 16 << 20},
		{"64MiB", 64 << 20},
		{"10GiB", 10 << 30},
		{"1KiB", 1 << 10},
		{"3MB", 3_000_000},
		{"10GB", 10_000_000_000},
		{"2KB", 2_000},
		{"512B", 512},
		{"-1", -1},
		{"1048576", 1048576},
		{"0", 0},
	}
	// Run many iterations: the old map-based parser flaked ~half the time.
	for iter := 0; iter < 200; iter++ {
		for _, c := range cases {
			got, err := parseSize(c.in)
			if err != nil {
				t.Fatalf("parseSize(%q): unexpected error %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("parseSize(%q) = %d, want %d (iter %d)", c.in, got, c.want, iter)
			}
		}
	}

	if _, err := parseSize("notasize"); err == nil {
		t.Fatalf("parseSize(\"notasize\"): expected an error")
	}
}

// TestPatternReader_ExactBytes checks the shared-buffer reader yields exactly n
// bytes of the repeating pattern and then EOF, across boundary and multi-read
// sizes.
func TestPatternReader_ExactBytes(t *testing.T) {
	for _, n := range []int64{0, 1, 31, 32 * 1024, 32*1024 + 7, 200000} {
		r := newPatternReader(n)
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("n=%d: ReadAll error %v", n, err)
		}
		if int64(len(got)) != n {
			t.Fatalf("n=%d: read %d bytes, want %d", n, len(got), n)
		}
		// Every byte is drawn from the printable 'A'..'Z' pattern. (The pattern
		// restarts at each Read boundary, so it is not globally continuous — that
		// is fine; the harness only needs arbitrary streamed bytes.)
		for i := range got {
			if got[i] < 'A' || got[i] > 'Z' {
				t.Fatalf("n=%d: byte %d = %q, outside 'A'..'Z' pattern", n, i, got[i])
			}
		}
	}
}

// TestFeatureServers_EndToEnd boots both feature servers and drives one of each
// scenario's underlying helper, asserting the whole stack (TLS h2, the full
// middleware onion, gRPC framing, /metrics exposition, health) works and records
// zero errors — i.e. the harness measures a healthy server, not a broken client.
func TestFeatureServers_EndToEnd(t *testing.T) {
	fs, err := newFeatureServer(100000, -1)
	if err != nil {
		t.Fatalf("newFeatureServer: %v", err)
	}
	defer fs.stop()

	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:    fs.clientTLS,
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // gzip is driven explicitly
		},
		Timeout: 15 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const dataSize = int64(1 << 20) // 1 MiB
	m := newMetrics(buildScenarios(config{dataSize: dataSize, jsonItems: 800}, fs.grpcURL))

	// HTTP hot path.
	if err := get(ctx, cli, fs.baseURL+"/", 200, m); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Large upload + X-Body-Len echo.
	resp, err := post(ctx, cli, fs.baseURL+"/sink", newPatternReader(dataSize), m)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := resp.Header.Get("X-Body-Len"); got != fmt.Sprint(dataSize) {
		t.Fatalf("sink X-Body-Len = %s, want %d", got, dataSize)
	}
	drain(resp)
	// Streamed download + big-JSON element-by-element parse.
	if err := get(ctx, cli, fs.baseURL+"/download?n=262144", 200, m); err != nil {
		t.Fatalf("download: %v", err)
	}
	if err := bigParse(ctx, cli, fs.baseURL+"/bigjson?n=800", 800, m); err != nil {
		t.Fatalf("bigparse: %v", err)
	}
	// Gzip round-trip (asserts Content-Encoding: gzip).
	if err := gzipGet(ctx, cli, fs.baseURL+"/gziptext?n=131072", m); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	// HPACK-heavy headers.
	if err := getHeaders(ctx, cli, fs.baseURL+"/headers", m); err != nil {
		t.Fatalf("headers: %v", err)
	}
	// Error-status path (expected non-2xx is NOT an error).
	if err := get(ctx, cli, fs.baseURL+"/status?code=503", 503, m); err != nil {
		t.Fatalf("errors: %v", err)
	}
	// Health probe (poseidon HealthHandler /readyz).
	if err := get(ctx, cli, fs.baseURL+"/readyz", 200, m); err != nil {
		t.Fatalf("health: %v", err)
	}
	// Prometheus exposition scrape + assertion.
	if err := scrapeMetrics(ctx, cli, fs.baseURL+"/metrics", m); err != nil {
		t.Fatalf("metrics: %v", err)
	}
	// gRPC unary echo — exact round-trip through poseidon's grpcserver.
	payload := []byte("hello-grpc-⚡-12345")
	if err := grpcEcho(ctx, cli, fs.grpcURL, payload, m); err != nil {
		t.Fatalf("grpc: %v", err)
	}

	if e := m.errs.Load(); e != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", e, m.errSamples)
	}
	if fs.tracer.spans.Load() == 0 {
		t.Fatalf("Tracing middleware recorded 0 spans — chain not exercised")
	}
}

// TestGRPCEcho_LargePayload drives a gRPC echo larger than a single HTTP/2 frame
// so the length-prefixed framing spans multiple DATA frames on both directions.
func TestGRPCEcho_LargePayload(t *testing.T) {
	fs, err := newFeatureServer(100000, -1)
	if err != nil {
		t.Fatalf("newFeatureServer: %v", err)
	}
	defer fs.stop()
	cli := &http.Client{
		Transport: &http.Transport{TLSClientConfig: fs.clientTLS, ForceAttemptHTTP2: true},
		Timeout:   15 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	m := newMetrics(nil)
	// A payload larger than one HTTP/2 frame, to exercise multi-frame gRPC bodies.
	payload := bytes.Repeat([]byte("x"), 128*1024)
	if err := grpcEcho(ctx, cli, fs.grpcURL, payload, m); err != nil {
		t.Fatalf("grpcEcho large: %v", err)
	}
	if e := m.errs.Load(); e != 0 {
		t.Fatalf("expected 0 errors, got %d", e)
	}
}
