package integration

// End-to-end parallel benchmark (issue #95).
//
// The benchmarks in conn/ and middleware/ each isolate one lock. This one isolates
// nothing: it is a real Poseidon server behind real TLS, driven by the stdlib
// HTTP/2 client, which multiplexes every concurrent request onto ONE TCP
// connection. Its job is not ns/op — it is to be the thing you point
// -mutexprofile and -blockprofile at, so the contended sites are NAMED by the
// runtime rather than inferred from a benchmark's shape:
//
//	POSEIDON_BENCH_E2E=1 go test -run='^$' -bench=BenchmarkE2E_OneConnManyStreams \
//	    -benchtime=5s -cpu=16 -mutexprofile=mutex.out -blockprofile=block.out \
//	    ./server/integration
//	go tool pprof -top -nodecount=25 mutex.out
//
// Opt-in via POSEIDON_BENCH_E2E because scripts/bench-gate.sh benchmarks ./...
// at -benchtime=2s -count=10: a TLS + TCP + stdlib-client benchmark is an order
// of magnitude noisier than the in-process ones and would be a false-positive
// source the day the gate gets a baseline to compare against (see #101).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// benchParQuietLogger drops server log output. A benchmark's stdout is parsed
// by benchstat; connection-level log lines do not belong in it.
type benchParQuietLogger struct{}

func (benchParQuietLogger) Printf(string, ...any) {}

// benchParTLS mints a throwaway self-signed certificate for the benchmark
// listener. Separate from the test helper of the same purpose so this file does
// not depend on helpers_test.go's *testing.T signatures.
func benchParTLS(b *testing.B) (*x509.Certificate, *tls.Config) {
	b.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		b.Fatalf("rand.Int: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1", Organization: []string{"poseidon-bench"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		b.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatalf("ParseCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		b.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("X509KeyPair: %v", err)
	}
	return cert, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
}

// benchParServer starts a real Poseidon server over TLS and returns its base URL
// plus a client that trusts it. One client, so every request multiplexes onto
// one connection.
func benchParServer(b *testing.B) (string, *http.Client) {
	b.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	cert, serverTLS := benchParTLS(b)

	body := make([]byte, 256)
	srv, err := server.NewServer(server.Options{
		Addr:   ln.Addr().String(),
		Logger: benchParQuietLogger{},
		Handler: server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			if werr := w.WriteHeaders(200, nil); werr != nil {
				return werr
			}
			if werr := w.WriteData(body); werr != nil {
				return werr
			}
			return w.WriteTrailers(nil)
		}),
		GracefulShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = ln.Close()
		b.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, tls.NewListener(ln, serverTLS)) }()

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	url := "https://" + ln.Addr().String() + "/bench"

	// Warm up: this doubles as the readiness wait. A bare TCP dial would reach
	// the server as a connection that never sends a preface, which it correctly
	// logs as a handshake failure — noise in the middle of benchmark output.
	var warmErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, gerr := client.Get(url)
		if gerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			warmErr = nil
			break
		}
		warmErr = gerr
		time.Sleep(10 * time.Millisecond)
	}
	if warmErr != nil {
		cancel()
		_ = srv.Close()
		b.Fatalf("warmup: %v", warmErr)
	}

	b.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
		}
		transport.CloseIdleConnections()
	})
	return url, client
}

// BenchmarkE2E_OneConnManyStreams issues concurrent requests that all land on a
// single HTTP/2 connection — the sidecar shape, and the one in which every
// response HEADERS and DATA frame queues behind the same conn.ServerConn.wmu,
// and every accepted stream behind the same server.Server.mu.
func BenchmarkE2E_OneConnManyStreams(b *testing.B) {
	if os.Getenv("POSEIDON_BENCH_E2E") == "" {
		b.Skip("set POSEIDON_BENCH_E2E=1 to run the end-to-end contention benchmark")
	}
	url, client := benchParServer(b)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(url) //nolint:bodyclose // closed below
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
}
