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

// TestBuildRequest_Rejects checks the pseudo-header rules (RFC 9114 §4.3.1): the
// mandatory ones must be present, and an unknown pseudo-header is malformed.
func TestBuildRequest_Rejects(t *testing.T) {
	t.Parallel()
	field := func(n, v string) hpack.HeaderField {
		return hpack.HeaderField{Name: []byte(n), Value: []byte(v)}
	}
	full := []hpack.HeaderField{field(":method", "GET"), field(":scheme", "https"), field(":path", "/")}

	cases := map[string][]hpack.HeaderField{
		"no :method":        {field(":scheme", "https"), field(":path", "/")},
		"no :scheme":        {field(":method", "GET"), field(":path", "/")},
		"no :path":          {field(":method", "GET"), field(":scheme", "https")},
		"unknown pseudo":    append(append([]hpack.HeaderField{}, full...), field(":bogus", "x")),
		"unparseable :path": {field(":method", "GET"), field(":scheme", "https"), field(":path", "://")},
	}
	for name, fields := range cases {
		if _, err := buildRequest(fields, nil); err == nil {
			t.Errorf("%s: buildRequest = nil error, want a malformed-message error", name)
		}
	}

	req, err := buildRequest(append(full, field(":authority", "example.com"), field("x-a", "1")), []byte("hi"))
	if err != nil {
		t.Fatalf("buildRequest(valid): %v", err)
	}
	if req.Method != "GET" || req.URL.Path != "/" || req.Host != "example.com" {
		t.Errorf("built %s %s host=%q, want GET / host=example.com", req.Method, req.URL.Path, req.Host)
	}
	if req.Header.Get("x-a") != "1" || req.ContentLength != 2 {
		t.Errorf("header x-a=%q len=%d, want 1 and 2", req.Header.Get("x-a"), req.ContentLength)
	}
}

// TestDecodeRequest_NoHeaders rejects a request stream carrying no HEADERS frame.
func TestDecodeRequest_NoHeaders(t *testing.T) {
	t.Parallel()
	if _, err := decodeRequest(http3.AppendData(nil, []byte("body only"))); err == nil {
		t.Fatal("decodeRequest without HEADERS = nil error, want a malformed-message error")
	}
	if _, err := decodeRequest(nil); err == nil {
		t.Fatal("decodeRequest(empty) = nil error, want a malformed-message error")
	}
}

// TestResponseWriter checks the status latch: the first WriteHeader wins, and a
// bare Write implies 200.
func TestResponseWriter(t *testing.T) {
	t.Parallel()
	w := &responseWriter{header: http.Header{}, status: http.StatusOK}
	w.WriteHeader(http.StatusTeapot)
	w.WriteHeader(http.StatusGone) // ignored: the status is already fixed
	if w.status != http.StatusTeapot {
		t.Errorf("status = %d, want %d", w.status, http.StatusTeapot)
	}

	implied := &responseWriter{header: http.Header{}, status: http.StatusOK}
	if _, err := implied.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !implied.wroteHeader || implied.status != http.StatusOK {
		t.Errorf("bare Write left status %d wrote=%v, want 200 and true", implied.status, implied.wroteHeader)
	}
}

// TestServer_HandlerDefaults falls back to http.DefaultServeMux when Handler is nil.
func TestServer_HandlerDefaults(t *testing.T) {
	t.Parallel()
	if (&Server{}).handler() != http.DefaultServeMux {
		t.Error("a nil Handler does not fall back to http.DefaultServeMux")
	}
	h := http.NewServeMux()
	if (&Server{Handler: h}).handler() != h {
		t.Error("handler() did not return the configured Handler")
	}
}

// TestListenAndServe_BadAddr surfaces the bind error rather than blocking.
func TestListenAndServe_BadAddr(t *testing.T) {
	t.Parallel()
	cert, _ := testCert(t)
	srv := &Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.ListenAndServe(ctx, "127.0.0.1:not-a-port"); err == nil {
		t.Fatal("ListenAndServe on a bad address = nil error, want a bind error")
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
