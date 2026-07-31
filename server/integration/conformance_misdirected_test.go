package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// Conformance tests for 421 (Misdirected Request).
//
// RFC 9110 §7.4 (rfc9110.txt:2510):
//
//	"Unless the connection is from a trusted gateway, an origin server MUST
//	 reject a request if any scheme-specific requirements for the target URI
//	 are not met. In particular, a request for an "https" resource MUST be
//	 rejected unless it has been received over a connection that has been
//	 secured via a certificate valid for that target URI's origin, as defined
//	 by Section 4.2.2."
//
// and (:2517): "The 421 (Misdirected Request) status code in a response
// indicates that the origin server has rejected the request because it appears
// to have been misdirected".
//
// Nothing compared :authority against the identity the connection was
// authenticated for, and the repository contained no 421 path at all. A client
// could reach any virtual host on this server over a certificate valid for a
// different one — the connection-coalescing case the status code exists for.
//
// The test cert is valid for 127.0.0.1 and localhost, so an :authority naming
// anything else is misdirected by construction.

// tlsH2Client dials the server over TLS and completes the HTTP/2 handshake.
func tlsH2Client(t *testing.T, addr string, cert *x509.Certificate) *frame.Framer {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		RootCAs:    roots,
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12, //nolint:gosec // test cert
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	fr := frame.NewFramer(c, c)
	if err := rawH2Handshake(c, fr); err != nil {
		t.Fatalf("h2 handshake: %v", err)
	}
	return fr
}

func requestAuthority(t *testing.T, fr *frame.Framer, streamID uint32, authority string) string {
	t.Helper()
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte(authority)},
		{Name: []byte(":path"), Value: []byte("/")},
	})
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: streamID, BlockFragment: block, EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	status, _, err := readH2Response(fr)
	if err != nil {
		t.Fatalf("read response for %q: %v", authority, err)
	}
	return status
}

// TestConformance_RFC9110_Sec74_MisdirectedAuthorityRejected pins :2510.
func TestConformance_RFC9110_Sec74_MisdirectedAuthorityRejected(t *testing.T) {
	t.Parallel()

	addr, cert := startRawTLSServer(t, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteData([]byte("handler must not run"))
		}))

	fr := tlsH2Client(t, addr, cert)
	if got := requestAuthority(t, fr, 1, "not-in-the-cert.example"); got != "421" {
		t.Errorf(":status = %q for an :authority the connection's certificate is not "+
			"valid for, want 421 (RFC 9110 §7.4)", got)
	}
}

// TestConformance_RFC9110_Sec74_AuthorityInCertAccepted is the control: an
// :authority the certificate does cover must be served normally. Without it the
// obvious way to pass the test above is to reject everything.
func TestConformance_RFC9110_Sec74_AuthorityInCertAccepted(t *testing.T) {
	t.Parallel()

	addr, cert := startRawTLSServer(t, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteData([]byte("served"))
		}))

	fr := tlsH2Client(t, addr, cert)
	for i, authority := range []string{"127.0.0.1", "localhost", "localhost:8443"} {
		streamID := uint32(1 + 2*i) //nolint:gosec // small loop index
		if got := requestAuthority(t, fr, streamID, authority); got != "200" {
			t.Errorf(":status = %q for :authority %q, want 200 — the certificate covers it "+
				"(a port is not part of the identity being verified)", got, authority)
		}
	}
}
