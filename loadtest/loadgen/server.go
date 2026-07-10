// Command loadgen is a self-contained load/soak + profiling harness for
// poseidon-http-server. Unlike the external-tool scripts in this directory
// (h2load/ghz/k6), it drives a real HTTP/2 server end-to-end from Go, so it can:
//
//   - exercise ~all of the HTTP/2 + middleware feature surface in one run,
//   - stream arbitrarily large bodies (up to 10 GiB) from a fixed buffer, so
//     memory stays flat regardless of -data-size,
//   - correlate variables across a weighted + conditional + nested scenario mix,
//   - fire a sharp traffic spike partway through a sustained soak,
//   - stream-parse large (>3 MiB) responses under load, and
//   - capture CPU/heap pprof profiles + a runtime resource report to prove the
//     server stays lean.
//
// This file defines the feature server; main.go defines the driver, scenarios,
// spike, profiling, and report. Build/run:
//
//	go run ./loadtest/loadgen -h
//	go run ./loadtest/loadgen -duration=20s -vus=64 -data-size=64MiB \
//	    -spike-after=8s -spike-dur=6s -cpuprofile=cpu.out -memprofile=heap.out
package main

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
	"strconv"
	"time"

	"github.com/lodgvideon/poseidon-http-server/conn"
	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// patternReader yields n bytes of a repeating printable pattern from a small
// fixed buffer, so streaming a 10 GiB body never allocates 10 GiB. Not safe for
// concurrent use; each request makes its own.
type patternReader struct {
	remaining int64
	buf       []byte
}

func newPatternReader(n int64) *patternReader {
	b := make([]byte, 32*1024)
	for i := range b {
		b[i] = byte('A' + i%26)
	}
	return &patternReader{remaining: n, buf: b}
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for w := 0; w < n; {
		w += copy(p[w:n], r.buf)
	}
	r.remaining -= int64(n)
	return n, nil
}

// featureServer is an in-process poseidon HTTP/2 (TLS) server whose mux
// exercises the feature surface a load run wants to hit.
type featureServer struct {
	baseURL   string
	clientTLS *tls.Config
	metrics   *middleware.MetricsCollector
	stop      func()
}

// newFeatureServer starts the server on a random localhost port and returns it
// ready to accept requests. rateLimit is the global token-bucket rate (req/s);
// a soak stays under it while the spike deliberately exceeds it to exercise 429s.
func newFeatureServer(rateLimit float64, maxBodyBytes int64) (*featureServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cert, serverTLS, clientTLS, err := selfSignedTLS()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	_ = cert

	mux := newFeatureMux()
	metrics := middleware.NewMetricsCollector()

	secCfg := middleware.DefaultSecurityHeadersConfig()
	secCfg.HSTSMaxAge = 0 // meaningless for a local test cert

	// Onion order (outermost first): Recovery → RequestID → SecurityHeaders →
	// Gzip → RateLimit → Metrics. Every request flows through the full stack.
	mw := []server.Middleware{
		middleware.Recovery(noopLogger{}),
		middleware.RequestID(),
		middleware.SecurityHeaders(secCfg),
		middleware.Gzip(middleware.DefaultGzipConfig()),
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate:  rateLimit,
			Burst: int(rateLimit),
			Key:   middleware.KeyByClientIP(),
		}),
		metrics.Metrics(),
	}

	srv, err := server.NewServer(server.Options{
		Addr:                ln.Addr().String(),
		HTTPHandler:         mux,
		Middleware:          mw,
		MaxRequestBodyBytes: maxBodyBytes,
		// Enlarge the connection recv window so large uploads are not throttled
		// into many WINDOW_UPDATE round-trips (the opt-in knob added in #37).
		ConnOpts: conn.ServerConnOptions{ConnRecvWindow: 4 << 20},
		Logger:   noopLogger{},
	})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	metrics.SetTransportSource(srv.TransportStats)

	ctx, cancel := context.WithCancel(context.Background())
	tlsLn := tls.NewListener(ln, serverTLS)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, tlsLn) }()

	if err := waitReachable(ln.Addr().String()); err != nil {
		cancel()
		_ = srv.Close()
		return nil, err
	}

	return &featureServer{
		baseURL:   "https://" + ln.Addr().String(),
		clientTLS: clientTLS,
		metrics:   metrics,
		stop: func() {
			cancel()
			_ = srv.Close()
			select {
			case <-serveErr:
			case <-time.After(3 * time.Second):
			}
		},
	}, nil
}

// newFeatureMux builds the endpoint set. Each endpoint isolates one feature so a
// scenario can target it precisely.
func newFeatureMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Tiny hot-path GET — the RPS/latency baseline.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})

	// "Login": echoes a session token derived from the request so the client can
	// correlate it into later requests (variable-management).
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Session", "sess-"+strconv.FormatInt(n, 36)+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		w.WriteHeader(http.StatusOK)
	})

	// Large-upload sink: drains the body (streamed, minimal memory) and reports
	// the byte count. Exercises inbound flow control + WINDOW_UPDATE refunds.
	mux.HandleFunc("POST /sink", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Body-Len", strconv.FormatInt(n, 10))
		w.WriteHeader(http.StatusOK)
	})

	// Large-download source: streams n bytes down (outbound flow control).
	mux.HandleFunc("GET /download", func(w http.ResponseWriter, r *http.Request) {
		n := queryInt64(r, "n", 1<<20)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, newPatternReader(n))
	})

	// Big JSON array (> a few MiB) for the large-response stream-parse scenario.
	// Written incrementally so the SERVER also stays lean.
	mux.HandleFunc("GET /bigjson", func(w http.ResponseWriter, r *http.Request) {
		count := queryInt64(r, "n", 20000)
		w.Header().Set("Content-Type", "application/json")
		bw := w
		_, _ = io.WriteString(bw, `{"items":[`)
		for i := int64(0); i < count; i++ {
			if i > 0 {
				_, _ = io.WriteString(bw, ",")
			}
			_, _ = fmt.Fprintf(bw, `{"id":%d,"name":"item-%d","payload":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ok":true}`, i, i)
		}
		_, _ = io.WriteString(bw, `]}`)
	})

	// Chunked streaming response: k flushed chunks (server-streaming shape).
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		k := queryInt64(r, "chunks", 16)
		fl, _ := w.(http.Flusher)
		for i := int64(0); i < k; i++ {
			_, _ = fmt.Fprintf(w, "chunk-%d\n", i)
			if fl != nil {
				fl.Flush()
			}
		}
	})

	// Compressible text so the Gzip middleware actually compresses (client sends
	// Accept-Encoding: gzip and asserts Content-Encoding: gzip).
	mux.HandleFunc("GET /gziptext", func(w http.ResponseWriter, r *http.Request) {
		n := queryInt64(r, "n", 64<<10)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.Copy(w, newPatternReader(n))
	})

	// Arbitrary status code — exercises error/paths handling on the client.
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(queryInt64(r, "code", 200)))
	})

	// Header-heavy: echoes the inbound header count and sets many response
	// headers (HPACK dynamic-table pressure).
	mux.HandleFunc("GET /headers", func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 24; i++ {
			w.Header().Set("X-Resp-"+strconv.Itoa(i), strconv.Itoa(i))
		}
		w.Header().Set("X-Req-Header-Count", strconv.Itoa(len(r.Header)))
		w.WriteHeader(http.StatusOK)
	})

	// Slow endpoint — keeps streams open (idle-timeout / concurrency pressure).
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		d := time.Duration(queryInt64(r, "ms", 25)) * time.Millisecond
		select {
		case <-time.After(d):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	})

	return mux
}

func queryInt64(r *http.Request, key string, def int64) int64 {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// noopLogger satisfies both server.Options.Logger and middleware.Recovery's
// Logger — the load run does not want per-request log spam.
type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}

func waitReachable(addr string) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("server %s not reachable", addr)
}

// selfSignedTLS returns a fresh cert plus matching server and client TLS configs
// (the client trusts the generated cert; ALPN advertises h2).
func selfSignedTLS() (*x509.Certificate, *tls.Config, *tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}
	clientTLS := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}
	return cert, serverTLS, clientTLS, nil
}
