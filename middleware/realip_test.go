package middleware

import (
	"context"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// captureHandler records the ClientIP resolved by the RealIP middleware. It is
// the terminal handler in the test chains below.
type captureHandler struct {
	gotClientIP string
}

func (h *captureHandler) ServeHTTP(ctx context.Context, _ *server.Request, _ server.ResponseWriter) error {
	h.gotClientIP = ClientIP(ctx)
	return nil
}

// noopWriter is a server.ResponseWriter that discards everything; it lets the
// RealIP middleware run without a live stream. The methods are inert because
// these tests assert on the resolved ClientIP, not on the response.
type noopWriter struct{ hdr http.Header }

func newNoopWriter() *noopWriter { return &noopWriter{hdr: make(http.Header)} }

func (w *noopWriter) Header() http.Header                       { return w.hdr }
func (*noopWriter) Write(p []byte) (int, error)                 { return len(p), nil }
func (*noopWriter) WriteHeader(int)                             {}
func (*noopWriter) WriteHeaders(int, []hpack.HeaderField) error { return nil }
func (*noopWriter) WriteData([]byte) error                      { return nil }
func (*noopWriter) WriteTrailers([]hpack.HeaderField) error     { return nil }
func (*noopWriter) Status() int                                 { return 0 }
func (*noopWriter) StatusCode() int                             { return 0 }
func (*noopWriter) Written() bool                               { return false }

// runRealIP wires the middleware around a captureHandler, seeds the peer
// address into the context, and runs one request. It returns the resolved
// client IP observed by the handler.
func runRealIP(t *testing.T, cfg RealIPConfig, peer string, headers []hpack.HeaderField) string {
	t.Helper()
	ch := &captureHandler{}
	h := RealIP(cfg)(ch)
	ctx := WithPeerAddr(context.Background(), peer)
	req := &server.Request{Method: "GET", Path: "/", Headers: headers}
	if err := h.ServeHTTP(ctx, req, newNoopWriter()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return ch.gotClientIP
}

func xff(v string) []hpack.HeaderField {
	return []hpack.HeaderField{{Name: []byte("x-forwarded-for"), Value: []byte(v)}}
}

func xrealip(v string) []hpack.HeaderField {
	return []hpack.HeaderField{{Name: []byte("x-real-ip"), Value: []byte(v)}}
}

// TestRealIP_TrustedProxy_HonorsXFF: when the immediate peer is inside a
// trusted CIDR, the rightmost untrusted address in X-Forwarded-For is used.
func TestRealIP_TrustedProxy_HonorsXFF(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("203.0.113.7"))
	if got != "203.0.113.7" {
		t.Fatalf("trusted proxy: want client IP 203.0.113.7, got %q", got)
	}
}

// TestRealIP_UntrustedProxy_IgnoresXFF: an untrusted peer cannot spoof the
// client IP — XFF is ignored and the peer address is used instead.
func TestRealIP_UntrustedProxy_IgnoresXFF(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := runRealIP(t, cfg, "198.51.100.23:443", xff("203.0.113.7"))
	if got != "198.51.100.23" {
		t.Fatalf("untrusted proxy: want peer IP 198.51.100.23, got %q", got)
	}
}

// TestRealIP_SecureByDefault_NoTrustConfigured: with no trusted proxies the
// middleware trusts nothing, so XFF is always ignored.
func TestRealIP_SecureByDefault_NoTrustConfigured(t *testing.T) {
	got := runRealIP(t, RealIPConfig{}, "10.0.0.1:54321", xff("203.0.113.7"))
	if got != "10.0.0.1" {
		t.Fatalf("secure default: want peer IP 10.0.0.1, got %q", got)
	}
}

// TestRealIP_XRealIP_TrustedProxy: X-Real-IP is honored from a trusted peer.
func TestRealIP_XRealIP_TrustedProxy(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := runRealIP(t, cfg, "10.0.0.5:9000", xrealip("203.0.113.99"))
	if got != "203.0.113.99" {
		t.Fatalf("trusted X-Real-IP: want 203.0.113.99, got %q", got)
	}
}

// TestRealIP_XForwardedFor_PrefersXFFOverXRealIP: X-Forwarded-For takes
// precedence over X-Real-IP when both are present from a trusted peer.
func TestRealIP_XForwardedFor_PrefersXFFOverXRealIP(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	headers := []hpack.HeaderField{
		{Name: []byte("x-forwarded-for"), Value: []byte("203.0.113.7")},
		{Name: []byte("x-real-ip"), Value: []byte("203.0.113.99")},
	}
	got := runRealIP(t, cfg, "10.0.0.1:54321", headers)
	if got != "203.0.113.7" {
		t.Fatalf("want XFF preferred 203.0.113.7, got %q", got)
	}
}

// TestRealIP_XFF_ChainSkipsTrustedHops: with a chain of forwarders, the
// rightmost address that is NOT itself a trusted proxy is the real client.
func TestRealIP_XFF_ChainSkipsTrustedHops(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	// client 203.0.113.7 → internal LB 10.0.0.2 → edge 10.0.0.1 (peer)
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("203.0.113.7, 10.0.0.2"))
	if got != "203.0.113.7" {
		t.Fatalf("chain: want client 203.0.113.7, got %q", got)
	}
}

// TestRealIP_XFF_AllTrusted_FallsBackToLeftmost: if every hop in XFF is
// trusted, the leftmost (claimed origin) is returned.
func TestRealIP_XFF_AllTrusted_FallsBackToLeftmost(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("10.0.0.9, 10.0.0.2"))
	if got != "10.0.0.9" {
		t.Fatalf("all-trusted: want leftmost 10.0.0.9, got %q", got)
	}
}

// TestRealIP_MalformedXFF_FallsBackToPeer: a garbage XFF from a trusted peer
// must not break resolution; the peer address is used.
func TestRealIP_MalformedXFF_FallsBackToPeer(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("not-an-ip"))
	if got != "10.0.0.1" {
		t.Fatalf("malformed XFF: want peer 10.0.0.1, got %q", got)
	}
}

// TestRealIP_PeerWithoutPort: a peer address with no port is handled.
func TestRealIP_PeerWithoutPort(t *testing.T) {
	got := runRealIP(t, RealIPConfig{}, "192.0.2.10", nil)
	if got != "192.0.2.10" {
		t.Fatalf("no-port peer: want 192.0.2.10, got %q", got)
	}
}

// TestRealIP_IPv6Peer: an IPv6 peer in [host]:port form is parsed.
func TestRealIP_IPv6Peer(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"::1/128"}}
	got := runRealIP(t, cfg, "[::1]:8443", xff("2001:db8::1"))
	if got != "2001:db8::1" {
		t.Fatalf("ipv6 trusted peer: want 2001:db8::1, got %q", got)
	}
}

// TestRealIP_NoPeerInContext: with no peer seeded and no trust, ClientIP is "".
func TestRealIP_NoPeerInContext(t *testing.T) {
	ch := &captureHandler{}
	h := RealIP(RealIPConfig{})(ch)
	req := &server.Request{Method: "GET", Path: "/"}
	if err := h.ServeHTTP(context.Background(), req, newNoopWriter()); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if ch.gotClientIP != "" {
		t.Fatalf("no peer: want empty ClientIP, got %q", ch.gotClientIP)
	}
}

// TestClientIP_EmptyContext returns "" for a bare context.
func TestClientIP_EmptyContext(t *testing.T) {
	if got := ClientIP(context.Background()); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

// TestPeerAddr_RoundTrip exercises the exported peer-addr context helpers.
func TestPeerAddr_RoundTrip(t *testing.T) {
	ctx := WithPeerAddr(context.Background(), "10.1.2.3:5555")
	if got := PeerAddr(ctx); got != "10.1.2.3:5555" {
		t.Fatalf("want 10.1.2.3:5555, got %q", got)
	}
	if got := PeerAddr(context.Background()); got != "" {
		t.Fatalf("want empty for bare ctx, got %q", got)
	}
}

// TestRealIP_InvalidCIDRIgnored: a malformed CIDR entry is skipped rather than
// silently trusting everything.
func TestRealIP_InvalidCIDRIgnored(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"not-a-cidr", "10.0.0.0/8"}}
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("203.0.113.7"))
	if got != "203.0.113.7" {
		t.Fatalf("want valid CIDR still honored, got %q", got)
	}
	// And an untrusted peer with only the bad CIDR present trusts nothing.
	got = runRealIP(t, RealIPConfig{TrustedProxies: []string{"not-a-cidr"}},
		"198.51.100.1:443", xff("203.0.113.7"))
	if got != "198.51.100.1" {
		t.Fatalf("bad-CIDR-only: want peer 198.51.100.1, got %q", got)
	}
}

// TestRealIP_SingleIPTrusted: a bare IP (no /mask) in TrustedProxies is treated
// as a /32 (or /128) host entry.
func TestRealIP_SingleIPTrusted(t *testing.T) {
	cfg := RealIPConfig{TrustedProxies: []string{"10.0.0.1"}}
	got := runRealIP(t, cfg, "10.0.0.1:54321", xff("203.0.113.7"))
	if got != "203.0.113.7" {
		t.Fatalf("single-IP trust: want 203.0.113.7, got %q", got)
	}
	got = runRealIP(t, cfg, "10.0.0.2:54321", xff("203.0.113.7"))
	if got != "10.0.0.2" {
		t.Fatalf("single-IP non-match: want peer 10.0.0.2, got %q", got)
	}
}
