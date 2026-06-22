// Package main demonstrates a hardened Poseidon HTTP/2 server that stacks the
// production security primitives the library ships:
//
//   - middleware.SecurityHeaders: HSTS, X-Content-Type-Options, X-Frame-Options,
//     Referrer-Policy and an optional CSP, injected by wrapping the writer.
//   - middleware.RateLimit: a self-contained token-bucket limiter (keyed here
//     per request :authority); over-budget requests get 429 without reaching the app.
//   - middleware.RealIP: resolves the true client IP from forwarding headers
//     when the immediate peer is a trusted proxy (read via middleware.ClientIP).
//   - Options.MaxRequestBodyBytes: caps inbound bodies (here 1 MiB) so a large
//     upload is rejected with 413 instead of exhausting memory.
//   - Slowloris defenses: ConnOpts.HandshakeTimeout bounds the HTTP/2 preface +
//     SETTINGS exchange, IdleTimeout bounds idle keep-alive connections, and
//     ConnOpts.MaxRapidResets mitigates the HTTP/2 Rapid Reset flood
//     (CVE-2023-44487).
//   - TLS + ALPN ("h2"): served over HTTPS via Server.ListenAndServeTLS.
//
// Run:
//
//	go run ./examples/secure-server
//
// Try it (a self-signed cert is generated at startup, so -k is required):
//
//	curl -k --http2 https://localhost:8443/
//	curl -k --http2 -i https://localhost:8443/        # inspect security headers
//	# hammer it to trip the rate limiter (HTTP 429):
//	for i in $(seq 1 50); do curl -k -s -o /dev/null -w "%{http_code}\n" --http2 https://localhost:8443/; done
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-server/conn"
	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

func main() {
	// --- Application handler ---------------------------------------------
	app := server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		// The client IP resolved by RealIP (peer address when no trusted
		// proxy is configured) is available on the context.
		client := middleware.ClientIP(ctx)
		body := fmt.Sprintf("Poseidon secure server\nyour ip: %s\n", client)
		return w.WriteData([]byte(body))
	})

	// --- Hardened server options -----------------------------------------
	srv, err := server.NewServer(server.Options{
		Addr:    ":8443",
		Handler: app,

		// Cap request bodies at 1 MiB. Over-cap uploads are rejected with 413
		// and never buffered beyond the cap.
		MaxRequestBodyBytes: 1 << 20,

		// Idle keep-alive connections are dropped after 30s (Slowloris defense
		// against connections held open without sending streams).
		IdleTimeout: 30 * time.Second,

		// Connection-level hardening (RFC 7540 + CVE-2023-44487).
		ConnOpts: conn.ServerConnOptions{
			// Drop clients that connect but trickle the HTTP/2 preface /
			// SETTINGS exchange (Slowloris at handshake time).
			HandshakeTimeout: 5 * time.Second,
			// Tear down a connection that floods RST_STREAM (Rapid Reset).
			// 0 here means "secure default" (max(MaxConcurrentStreams*4, floor));
			// set an explicit positive budget to tune, or -1 to disable.
			MaxRapidResets: 0,
			AdvertisedSettings: conn.AdvertisedSettings{
				MaxConcurrentStreams: 100,
			},
		},

		Middleware: []server.Middleware{
			middleware.Recovery(nil),

			// Resolve the real client IP. With an empty TrustedProxies set we
			// trust nothing and fall back to the peer address — the secure
			// default. Behind a known L7 proxy, list its CIDR(s) here so
			// X-Forwarded-For is honored.
			middleware.RealIP(middleware.RealIPConfig{
				TrustedProxies: nil, // e.g. []string{"10.0.0.0/8", "::1/128"}
			}),

			// Inject standard security response headers (secure defaults:
			// HSTS 1y + includeSubDomains, nosniff, X-Frame-Options: DENY,
			// Referrer-Policy: no-referrer). HSTS is meaningful here because we
			// serve over TLS.
			middleware.SecurityHeaders(middleware.DefaultSecurityHeadersConfig()),

			// Token-bucket rate limit: 10 req/s sustained, burst 20, keyed per
			// client IP. KeyByClientIP reads the RealIP-resolved address from the
			// context, so RealIP (above) must precede RateLimit in the chain.
			middleware.RateLimit(middleware.RateLimitConfig{
				Rate:  10,
				Burst: 20,
				Key:   middleware.KeyByClientIP(),
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// --- Self-signed cert for the demo (use real certs in production) ----
	certFile, keyFile := generateSelfSignedCert()
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Println("Poseidon secure (TLS) server listening on :8443")
		if err := srv.ListenAndServeTLS(ctx, certFile, keyFile); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("draining...")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	_ = srv.Shutdown(drainCtx)
	log.Println("bye")
}

// generateSelfSignedCert writes a throwaway P-256 self-signed cert/key pair to
// temp files for the demo and returns their paths. Use real certificates (or an
// ACME source) in production.
func generateSelfSignedCert() (certFile, keyFile string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Poseidon Demo"}, CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certOut, _ := os.CreateTemp("", "poseidon-cert-*.pem")
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.CreateTemp("", "poseidon-key-*.pem")
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = keyOut.Close()

	return certOut.Name(), keyOut.Name()
}
