package http3server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// testCert returns a self-signed certificate for example.com and a pool trusting it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}

// serveTest starts a Server on the loopback with h and returns its address and a
// pool trusting its certificate.
func serveTest(ctx context.Context, t *testing.T, h http.Handler) (addr string, pool *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t)
	srv := &Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	l, err := quic.Listen("127.0.0.1:0", srv.TLSConfig, quic.ServerTransportParams{
		MaxStreamsBidi: maxStreamsBidi,
		MaxStreamsUni:  maxStreamsUni,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(ctx, l) }()
	return l.Addr().String(), pool
}

// TestServer_ServesRealHTTP3Client runs the real HTTP/3 client from
// poseidon-http-client against this server: it dials over UDP, completes the QUIC
// handshake, exchanges control streams and SETTINGS, sends a QPACK-encoded
// request, and reads the response. Nothing here is mocked — the peer is the
// production client.
func TestServer_ServesRealHTTP3Client(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello %s %s", r.Method, r.URL.Path)
	}))

	c, err := http3.Dial(ctx, addr, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatalf("http3.Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	resp, body, err := c.Do(ctx, &http3.Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/hi",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	if got, want := string(body), "hello GET /hi"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if ct := headerValue(resp.Headers, "content-type"); ct != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
}

// TestServer_RequestBodyAndStatus checks a request body reaches the handler and a
// non-200 status and custom header come back.
func TestServer_RequestBodyAndStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := make([]byte, 32)
		n, _ := r.Body.Read(got)
		w.Header().Set("X-Echo", string(got[:n]))
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewed"))
	}))

	c, err := http3.Dial(ctx, addr, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatalf("http3.Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	resp, body, err := c.Do(ctx, &http3.Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/brew",
		Headers:   []hpack.HeaderField{{Name: []byte("x-trace"), Value: []byte("abc")}},
		Body:      []byte("coffee"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.Status, http.StatusTeapot)
	}
	if got := headerValue(resp.Headers, "x-echo"); got != "coffee" {
		t.Errorf("server saw request body %q, want %q", got, "coffee")
	}
	if string(body) != "brewed" {
		t.Errorf("body = %q, want %q", body, "brewed")
	}
}

// headerValue returns the first value for name, or "".
func headerValue(fields []hpack.HeaderField, name string) string {
	for _, f := range fields {
		if string(f.Name) == name {
			return string(f.Value)
		}
	}
	return ""
}
