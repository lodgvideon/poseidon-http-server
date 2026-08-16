package server

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the RFC 9113 rules that bind the server/ layer rather
// than the connection state machine.

// TestConformance_RFC9113_Sec823_CookiesConcatenated pins RFC 9113 §8.2.3 —
// "If there are multiple Cookie header fields after decompression, these MUST be
// concatenated into a single octet string using the two-octet delimiter of 0x3B,
// 0x20 (the ASCII string '; ') before being passed into a non-HTTP/2 context."
//
// §8.2.3 (:2578) is why a conformant client produces them: "To allow for better
// compression efficiency, the Cookie header field MAY be split into separate
// header fields, each with one or more cookie-pairs." Chrome and Firefox both
// do. Without the join, http.Request.Cookies() sees only the first crumb.
func TestConformance_RFC9113_Sec823_CookiesConcatenated(t *testing.T) {
	req := &Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
		Headers: []hpack.HeaderField{
			{Name: []byte("cookie"), Value: []byte("a=1")},
			{Name: []byte("cookie"), Value: []byte("b=2")},
			{Name: []byte("cookie"), Value: []byte("c=3")},
			{Name: []byte("x-other"), Value: []byte("keep")},
		},
	}
	hr, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}

	if got, want := hr.Header.Get("Cookie"), "a=1; b=2; c=3"; got != want {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
	if n := len(hr.Header.Values("Cookie")); n != 1 {
		t.Errorf("Cookie present as %d field values, want 1 concatenated value", n)
	}
	cookies := hr.Cookies()
	if len(cookies) != 3 {
		t.Errorf("Cookies() returned %d cookies, want 3; the crumbs after the first "+
			"are what a split Cookie field loses", len(cookies))
	}
	if got := hr.Header.Get("X-Other"); got != "keep" {
		t.Errorf("unrelated field lost: X-Other = %q", got)
	}
}

// TestConformance_RFC9113_Sec823_SingleCookieUnchanged is the control: the
// common case must not be disturbed by the join.
func TestConformance_RFC9113_Sec823_SingleCookieUnchanged(t *testing.T) {
	req := &Request{
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
		Headers: []hpack.HeaderField{
			{Name: []byte("cookie"), Value: []byte("a=1; b=2")},
		},
	}
	hr, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}
	if got, want := hr.Header.Get("Cookie"), "a=1; b=2"; got != want {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
}

// TestConformance_RFC9113_Sec33_And92_TLSAdmission pins the two conditions
// RFC 9113 places on HTTP/2 over TLS, both MUST:
//
//	§3.3 — "HTTP/2 connections over TLS MUST use protocol
//	negotiation in TLS [TLS-ALPN]."
//	§9.2 — "Implementations of HTTP/2 MUST use TLS version 1.2
//	[TLS12] or higher for HTTP/2 over TLS."
//
// Checked against what was negotiated, not against the configuration: a
// *tls.Config may come from the caller (ListenAndServeTLSConfig, ServeTLSConfig)
// or already be in force on a connection handed to Serve, so the config is not
// evidence of what the peer actually agreed to.
func TestConformance_RFC9113_Sec33_And92_TLSAdmission(t *testing.T) {
	t.Run("cleartext_is_not_judged", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		if _, ok := tlsAdmissible(c1); !ok {
			t.Error("a cleartext connection was rejected; §3.3 and §9.2 bind TLS only")
		}
	})

	// A *tls.Conn that has not completed a handshake reports Version 0 and an
	// empty NegotiatedProtocol — which is exactly the shape of "no ALPN, no TLS
	// 1.2" and must be refused rather than admitted by default.
	t.Run("unnegotiated_tls_is_rejected", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		tc := tls.Server(c1, &tls.Config{MinVersion: tls.VersionTLS12})
		cs, ok := tlsAdmissible(tc)
		if ok {
			t.Errorf("admitted a TLS connection with alpn=%q version=%#04x",
				cs.NegotiatedProtocol, cs.Version)
		}
	})
}
