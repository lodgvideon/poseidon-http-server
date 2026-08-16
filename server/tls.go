package server

import (
	"context"
	"crypto/tls"
	"net"
)

// ---------------------------------------------------------------------------
// TLS + ALPN — RFC 7540 §3.3 (HTTP/2 over TLS)
// ---------------------------------------------------------------------------

// ListenAndServeTLS listens on the TCP address in Options.Addr and
// serves HTTPS (HTTP/2 over TLS with ALPN negotiation).
//
// The TLS config is configured with NextProtos = ["h2"] so that clients
// negotiating ALPN will select HTTP/2.
func (s *Server) ListenAndServeTLS(ctx context.Context, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
		// RFC 9113 §9.2.2: "A deployment of HTTP/2 over TLS 1.2
		// SHOULD NOT use any of the cipher suites that are listed in Appendix A."
		// Appendix A is a denylist of several hundred entries; the tractable way to
		// honour it is to name the allowed suites instead. These six are the
		// AEAD-with-ECDHE set §9.2.2 describes as the target ("TLS_ECDHE_RSA_WITH_
		// AES_128_GCM_SHA256... is available in TLS 1.2").
		//
		// crypto/tls ignores CipherSuites for TLS 1.3, so this bounds only the 1.2
		// negotiation — which is the entire scope of Appendix A.
		//
		// Deliberately not applied in ListenAndServeTLSConfig: that path takes the
		// caller's config, and silently overriding an explicit cipher choice is a
		// worse failure than the SHOULD NOT it would fix.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	return s.ListenAndServeTLSConfig(ctx, tlsConfig)
}

// ListenAndServeTLSConfig listens with a custom *tls.Config.
// The caller must set NextProtos to include "h2".
func (s *Server) ListenAndServeTLSConfig(ctx context.Context, cfg *tls.Config) error {
	// Ensure "h2" is in NextProtos.
	hasH2 := false
	for _, p := range cfg.NextProtos {
		if p == "h2" {
			hasH2 = true
			break
		}
	}
	if !hasH2 {
		cfg.NextProtos = append(cfg.NextProtos, "h2")
	}

	ln, err := tls.Listen("tcp", s.opts.Addr, cfg)
	if err != nil {
		return err
	}
	s.logger.Printf("poseidon: TLS listening on %s", ln.Addr())
	return s.serve(ctx, ln, cfg)
}

// ServeTLS serves on an existing TLS listener.
//
// Deprecated for new code in favour of [Server.ServeTLSConfig]: without the
// *tls.Config that produced ln, the server cannot tell which certificate it
// presented, so it cannot enforce RFC 9110 §7.4 (421 Misdirected Request) on
// this listener.
func (s *Server) ServeTLS(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, ln, nil)
}

// ServeTLSConfig serves on an existing TLS listener, given the *tls.Config that
// produced it.
//
// The config is what lets the server answer 421 (Misdirected Request) for an
// ":authority" its certificate is not valid for, as RFC 9110 §7.4 requires:
// crypto/tls does not expose the server's own certificate through
// ConnectionState, so it has to be reached through the config that selected it.
//
// Prefer this over [Server.ServeTLS] whenever the config is available. Passing
// a listener to the bare [Server.Serve] remains supported and skips the check.
func (s *Server) ServeTLSConfig(ctx context.Context, ln net.Listener, cfg *tls.Config) error {
	return s.serve(ctx, ln, cfg)
}
