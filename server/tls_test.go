package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Poseidon Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"127.0.0.1", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func TestTLS_ListenAndServe(t *testing.T) {
	cert := generateSelfSignedCert(t)

	handlerCalled := make(chan struct{})
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			close(handlerCalled)
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	// Client dials with ALPN h2, skip cert verification.
	clientTLS := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test cert
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Verify ALPN negotiated h2.
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN protocol = %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}

	// Perform HTTP/2 handshake and send a request.
	cliFr := frame.NewFramer(conn, conn)
	if err := performClientHandshake(conn, cliFr); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Read server SETTINGS + ACK.
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Read(buf)

	// Send SETTINGS ACK.
	cliFr.WriteSettingsAck()

	// Send HEADERS to open stream 1.
	enc := hpack.NewEncoder()
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/test")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	block := enc.EncodeBlock(nil, headers)
	if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	select {
	case <-handlerCalled:
		// Success.
	case <-time.After(3 * time.Second):
		t.Fatal("handler was not called")
	}
}
