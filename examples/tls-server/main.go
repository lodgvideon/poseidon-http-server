// Package main demonstrates Poseidon HTTP/2 server with TLS + ALPN.
//
// Generate self-signed cert:
//   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
//
// Run: go run ./examples/tls-server
// Test: curl --cert cert.pem --key key.pem https://localhost:8443/
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

type Status struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

func main() {
	// --- Router ---
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Poseidon HTTP/2 over TLS ✅\n")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{
			Status: "ok",
			Time:   time.Now().Format(time.RFC3339),
		})
	})

	// --- Generate self-signed cert (for demo; use real certs in production) ---
	certFile, keyFile := generateSelfSignedCert()

	// --- Poseidon server ---
	srv, err := server.NewServer(server.Options{
		Addr:    ":8443",
		Handler: server.FromHTTPHandler(mux),
		Middleware: []server.Middleware{
			middleware.Recovery(nil),
			middleware.RequestID(),
		},
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Println("Poseidon TLS server listening on :8443")
		if err := srv.ListenAndServeTLS(ctx, certFile, keyFile); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("draining...")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	_ = srv.Shutdown(drainCtx)
	log.Println("bye 👋")
}

func generateSelfSignedCert() (certFile, keyFile string) {
	// In production: load from files instead.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Poseidon Demo"},
			CommonName:   "localhost",
		},
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
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.CreateTemp("", "poseidon-key-*.pem")
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()

	return certOut.Name(), keyOut.Name()
}
