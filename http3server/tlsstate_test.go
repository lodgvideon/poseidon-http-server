package http3server

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Peer identity on HTTP/3 (issue #102).
//
// Both tests drive a REAL QUIC listener with the production HTTP/3 client,
// because the thing under test is what a handler sees on a live connection —
// exactly the shape of proof issue #87 needed on the HTTP/2 side, where unit
// tests that supplied the value themselves passed while the server never
// populated it. Nothing below constructs a tls.ConnectionState; the only source
// is the handshake the server actually completed.
//
// Only the TLS half is covered. http.Request.RemoteAddr and the peer address on
// the request context are NOT populated and cannot be: quic.Conn exposes no
// remote-address accessor (poseidon-http-client#710). See the package doc.
// ---------------------------------------------------------------------------

// requestTLSState issues one GET over a live HTTP/3 connection and returns the
// http.Request.TLS the handler saw.
func requestTLSState(ctx context.Context, t *testing.T, c *http3.Client, states <-chan *tls.ConnectionState) *tls.ConnectionState {
	t.Helper()
	resp, _, err := c.Do(ctx, &http3.Request{
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/who",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	return <-states
}

// dialTLSStateServer starts a server that reports each request's TLS state on the
// returned channel, and dials it with the production HTTP/3 client.
func dialTLSStateServer(ctx context.Context, t *testing.T) (*http3.Client, <-chan *tls.ConnectionState) {
	t.Helper()
	states := make(chan *tls.ConnectionState, 4)
	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		states <- r.TLS
		w.WriteHeader(http.StatusOK)
	}))
	c, err := http3.Dial(ctx, addr, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatalf("http3.Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, states
}

// TestServer_RequestTLSStateIsPopulated asserts a handler can read the TLS
// connection state off the request. HTTP/3 is TLS 1.3 by construction (RFC
// 9001), so a nil here means every net/http handler that gates on `r.TLS != nil`
// — HSTS, secure cookies, mTLS authorization — treats HTTP/3 as cleartext.
func TestServer_RequestTLSStateIsPopulated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, states := dialTLSStateServer(ctx, t)
	st := requestTLSState(ctx, t, c, states)

	if st == nil {
		t.Fatal("http.Request.TLS = nil on a live QUIC connection; the server never populated it")
	}
	if !st.HandshakeComplete {
		t.Error("HandshakeComplete = false; the state did not come from a finished handshake")
	}
	if st.Version != tls.VersionTLS13 {
		t.Errorf("Version = %#x, want %#x (QUIC is TLS 1.3 only)", st.Version, tls.VersionTLS13)
	}
	if st.CipherSuite == 0 {
		t.Error("CipherSuite = 0; the state is zero-valued, not the negotiated one")
	}
	// ServerName and NegotiatedProtocol come from the client's ClientHello, so
	// they are only right if this is THIS connection's state rather than some
	// default: a zero value would pass the checks above but fail these.
	if st.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com (the SNI this client sent)", st.ServerName)
	}
	if st.NegotiatedProtocol != "h3" {
		t.Errorf("NegotiatedProtocol = %q, want h3", st.NegotiatedProtocol)
	}
}

// TestServer_TLSStateIsSnapshotOncePerConnection asserts every request on a
// connection shares one state. That is the design, not an accident: quic.Conn is
// not safe for concurrent use and the serveConn goroutine owns it, so the state
// is taken once before the Poll loop and read from there — no lock, no atomic,
// and no tls.ConnectionState copy per request. Moving the call into serveRequest
// would compile, pass the test above, race the Poll loop under load, and copy a
// certificate chain per request; this is what notices.
func TestServer_TLSStateIsSnapshotOncePerConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, states := dialTLSStateServer(ctx, t)
	first := requestTLSState(ctx, t, c, states)
	second := requestTLSState(ctx, t, c, states)

	if first == nil || second == nil {
		t.Fatalf("http.Request.TLS = nil (first=%v second=%v)", first, second)
	}
	if first != second {
		t.Errorf("two requests on one connection got distinct *tls.ConnectionState (%p, %p); "+
			"the state is being re-derived per request instead of snapshotted per connection", first, second)
	}
}
