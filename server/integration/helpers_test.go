// Package integration provides end-to-end tests for the Poseidon HTTP/2 server.
//
// These tests use the standard library's net/http client (with HTTP/2 support
// enabled) to talk to a real Poseidon server over TCP/TLS. This validates
// wire-format compatibility, frame parsing, flow control, and observable
// behaviour from a real client's perspective.
//
// The package is kept separate from the main server package to:
//   - Avoid pulling httptest/net/http into the server unit tests.
//   - Make E2E failures easy to identify.
//   - Allow running integration tests separately via `go test ./server/integration/...`.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// init forces stdlib http.Transport to initialise its h2 configuration
// once, sequentially, before any test starts. This works around a known
// false positive in the race detector on stdlib internals
// (see https://github.com/golang/go/issues/67813) where concurrent
// first-time h2 setup trips a data race warning.
//
// We trigger the init path with a throwaway GET to a non-existent
// address. The result is irrelevant; the side-effect we want is the
// one-time execution of http2configureTransports.
func init() {
	tr := &http.Transport{ForceAttemptHTTP2: true}
	cli := &http.Client{Transport: tr, Timeout: 10 * time.Millisecond}
	req, _ := http.NewRequest("GET", "https://127.0.0.1:1/", nil)
	if r, err := cli.Do(req); err == nil { //nolint:bodyclose
		_ = r.Body.Close()
	}
}

// testServer bundles a Poseidon server with a stdlib HTTP/2 client and
// a TLS config that trusts the server's self-signed certificate.
type testServer struct {
	poseidon *server.Server
	listener net.Listener
	addr     string
	tls      *tls.Config
	client   *http.Client
}

// startTestServer brings up a real Poseidon server on a random localhost
// port with a freshly generated self-signed TLS certificate. Returns a
// configured testServer with an http.Client that trusts the certificate.
//
// The Poseidon server is launched in a background goroutine; cleanup is
// automatic via t.Cleanup.
func startTestServer(t *testing.T, h server.Handler, opts ...func(*server.Options)) *testServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cert, tlsCfg := generateSelfSignedTLS(t)

	o := server.Options{
		Addr:                    ln.Addr().String(),
		Handler:                 h,
		GracefulShutdownTimeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(&o)
	}

	srv, err := server.NewServer(o)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("NewServer: %v", err)
	}

	// ServeTLS in the current server package is broken (it serves raw
	// TCP, not TLS). Wrap the listener in TLS ourselves and Serve.
	tlsListener := tls.NewListener(ln, tlsCfg)

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, tlsListener)
	}()

	if err := waitForServer(ln.Addr().String()); err != nil {
		cancel()
		_ = srv.Close()
		t.Fatalf("server not reachable: %v", err)
	}

	clientTLS := &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12, //nolint:gosec // test cert
	}
	clientTLS.RootCAs.AddCert(cert)

	transport := &http.Transport{
		TLSClientConfig:       clientTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // measure wire, not client auto-decompression
	}

	// Run one synchronous warmup request to settle stdlib http.Transport
	// h2 initialisation. The race detector otherwise flags a false
	// positive on stdlib internals when later test code runs requests
	// in parallel (see https://github.com/golang/go/issues/67813).
	warmupClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	if wresp, werr := warmupClient.Get("https://" + ln.Addr().String() + "/__warmup__"); werr == nil {
		_, _ = io.Copy(io.Discard, wresp.Body)
		_ = wresp.Body.Close()
	}

	ts := &testServer{
		poseidon: srv,
		listener: ln,
		addr:     ln.Addr().String(),
		tls:      clientTLS,
		client:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
		}
		transport.CloseIdleConnections()
	})

	return ts
}

// URL returns a https:// base URL for the server.
func (ts *testServer) URL() string {
	return "https://" + ts.addr
}

// generateSelfSignedTLS creates a 2048-bit RSA self-signed certificate
// valid for 127.0.0.1, returns the parsed cert and a *tls.Config ready
// to use with tls.NewListener.
func generateSelfSignedTLS(t *testing.T) (*x509.Certificate, *tls.Config) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1", Organization: []string{"poseidon-test"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	// InsecureSkipVerify is not appropriate here; we use a self-signed
	// cert with explicit trust via RootCAs. The TLS config is built
	// above; this block is here to attach the cert to the client.
	_ = cert
	return cert, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12, //nolint:gosec // test cert, controlled environment
	}
}

// waitForServer polls until the listener accepts a TCP connection, or fails.
func waitForServer(addr string) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("server %s did not become reachable", addr)
}

// parallelResult is the outcome of one parallel HTTP request.
type parallelResult struct {
	status int
	body   []byte
	err    error
	took   time.Duration
}

// parallelRequests fans out N requests over `concurrency` goroutines and
// returns the results in order. It reuses one *http.Client (and therefore
// the connection pool) across all requests.
func parallelRequests(client *http.Client, url string, n, concurrency int) []parallelResult {
	var (
		mu   sync.Mutex
		out  = make([]parallelResult, n)
		jobs = make(chan int, n)
		wg   sync.WaitGroup
	)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				start := time.Now()
				resp, err := client.Get(url)
				r := parallelResult{took: time.Since(start)}
				if err != nil {
					r.err = err
				} else {
					r.body, _ = io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					r.status = resp.StatusCode
				}
				mu.Lock()
				out[j] = r
				mu.Unlock()
			}
		}()
	}
	for k := range n {
		jobs <- k
	}
	close(jobs)
	wg.Wait()
	return out
}
