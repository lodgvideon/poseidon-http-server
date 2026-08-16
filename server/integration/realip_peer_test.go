package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Peer address plumbing (issue #87).
//
// These tests drive a REAL listener on purpose. The pre-existing RealIP unit
// tests call middleware.WithPeerAddr themselves, so they pass whether or not
// the server ever populates the value — which is exactly how a dead RealIP
// shipped. Nothing below may set the peer address; only the server may.
// ---------------------------------------------------------------------------

// getWithHeaders issues a GET to "/" with the given request headers and returns
// the response status and body.
func getWithHeaders(t *testing.T, ts *testServer, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL()+"/", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestE2E_PeerAddr_PopulatedOnNativePath asserts the server puts the immediate
// peer's address on every request context, so middleware.PeerAddr sees it
// without anyone calling WithPeerAddr.
func TestE2E_PeerAddr_PopulatedOnNativePath(t *testing.T) {
	t.Parallel()

	ts := startTestServer(t, server.HandlerFunc(func(ctx context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteData([]byte(middleware.PeerAddr(ctx)))
	}))

	status, body := getWithHeaders(t, ts, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body == "" {
		t.Fatalf("middleware.PeerAddr(ctx) = %q on a live connection; the server never populated it", body)
	}
	host, port, err := net.SplitHostPort(body)
	if err != nil {
		t.Fatalf("peer addr %q is not host:port: %v", body, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("peer host = %q, want 127.0.0.1", host)
	}
	if port == "" || port == "0" {
		t.Errorf("peer port = %q, want the client's ephemeral port", port)
	}
}

// TestE2E_PeerAddr_PopulatedOnCompatPath asserts the same for the
// net/http-compatible path (Options.HTTPHandler → FromHTTPHandler), which
// threads the poseidon context onto the *http.Request.
func TestE2E_PeerAddr_PopulatedOnCompatPath(t *testing.T) {
	t.Parallel()

	ts := startTestServer(t, nil, func(o *server.Options) {
		o.Handler = nil
		o.HTTPHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(middleware.PeerAddr(r.Context())))
		})
	})

	status, body := getWithHeaders(t, ts, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if host, _, err := net.SplitHostPort(body); err != nil || host != "127.0.0.1" {
		t.Fatalf("compat-path peer addr = %q (host %q, err %v), want 127.0.0.1:<port>", body, host, err)
	}
}

// TestE2E_RealIP_UntrustedPeer_UsesPeerAddress asserts the secure default:
// with no trusted proxies, RealIP resolves the peer itself and ignores a
// forged X-Forwarded-For.
func TestE2E_RealIP_UntrustedPeer_UsesPeerAddress(t *testing.T) {
	t.Parallel()

	ts := startTestServer(t, server.HandlerFunc(func(ctx context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteData([]byte(middleware.ClientIP(ctx)))
	}), func(o *server.Options) {
		o.Middleware = []server.Middleware{middleware.RealIP(middleware.RealIPConfig{})}
	})

	_, body := getWithHeaders(t, ts, map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if body != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want 127.0.0.1 (peer address, spoofed XFF ignored)", body)
	}
}

// TestE2E_RealIP_TrustedPeer_HonoursXForwardedFor asserts that when the real
// peer is inside TrustedProxies the forwarding header is honoured end-to-end.
// This cannot work at all unless the peer address is populated: an empty peer
// matches no CIDR, so the header is never trusted.
func TestE2E_RealIP_TrustedPeer_HonoursXForwardedFor(t *testing.T) {
	t.Parallel()

	ts := startTestServer(t, server.HandlerFunc(func(ctx context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteData([]byte(middleware.ClientIP(ctx)))
	}), func(o *server.Options) {
		o.Middleware = []server.Middleware{
			middleware.RealIP(middleware.RealIPConfig{TrustedProxies: []string{"127.0.0.1/32"}}),
		}
	})

	_, body := getWithHeaders(t, ts, map[string]string{"X-Forwarded-For": "203.0.113.7"})
	if body != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7 (XFF honoured for a trusted peer)", body)
	}
}

// TestE2E_RateLimit_PerClientBuckets asserts that two distinct client IPs get
// distinct token buckets end-to-end. With the peer address absent every request
// keys on "" and shares one global bucket, so exhausting client A also throttles
// client B — the shipped defect in issue #87.
func TestE2E_RateLimit_PerClientBuckets(t *testing.T) {
	t.Parallel()

	ts := startTestServer(t, server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteData([]byte("ok"))
	}), func(o *server.Options) {
		o.Middleware = []server.Middleware{
			middleware.RealIP(middleware.RealIPConfig{TrustedProxies: []string{"127.0.0.1/32"}}),
			// Refill is effectively frozen for the duration of the test, so the
			// only thing that can hand client B a token is a bucket of its own.
			middleware.RateLimit(middleware.RateLimitConfig{Rate: 0.0001, Burst: 2, Key: middleware.KeyByClientIP()}),
		}
	})

	clientA := map[string]string{"X-Forwarded-For": "203.0.113.1"}
	clientB := map[string]string{"X-Forwarded-For": "203.0.113.2"}

	// Drain client A's bucket: burst 2 admitted, the third rejected.
	for i := 1; i <= 2; i++ {
		if status, _ := getWithHeaders(t, ts, clientA); status != http.StatusOK {
			t.Fatalf("client A request %d: status = %d, want 200", i, status)
		}
	}
	if status, _ := getWithHeaders(t, ts, clientA); status != http.StatusTooManyRequests {
		t.Fatalf("client A request 3: status = %d, want 429 (its own bucket must be empty)", status)
	}

	// Client B must be untouched by client A exhausting its bucket.
	if status, _ := getWithHeaders(t, ts, clientB); status != http.StatusOK {
		t.Fatalf("client B: status = %d, want 200 — a second client is sharing client A's bucket", status)
	}
}
