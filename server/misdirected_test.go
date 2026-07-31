package server

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// Unit tests for the two halves of the RFC 9110 §7.4 check: which certificate
// the connection is judged against (selectLeaf) and the judgement itself
// (misdirectedRequest). The end-to-end behaviour over a real TLS socket is in
// server/integration/conformance_misdirected_test.go.

func leafFor(t *testing.T, hosts ...string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	leaf := &x509.Certificate{DNSNames: hosts}
	return leaf, tls.Certificate{Leaf: leaf}
}

func TestSelectLeaf(t *testing.T) {
	oneLeaf, one := leafFor(t, "a.example")
	_, two := leafFor(t, "b.example")

	t.Run("one static certificate is the only unambiguous case", func(t *testing.T) {
		got := selectLeaf(&tls.Config{Certificates: []tls.Certificate{one}})
		if got != oneLeaf {
			t.Errorf("selectLeaf = %v, want the only configured certificate", got)
		}
	})

	// Everything below stands the check down rather than guessing which
	// certificate the handshake presented. Verifying against one the peer never
	// saw produces false 421s on legitimate traffic, which is worse than not
	// enforcing RFC 9110 §7.4 at all.
	t.Run("several certificates", func(t *testing.T) {
		if got := selectLeaf(&tls.Config{Certificates: []tls.Certificate{one, two}}); got != nil {
			t.Errorf("selectLeaf = %v, want nil: crypto/tls picks among these by SNI", got)
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		if got := selectLeaf(&tls.Config{}); got != nil {
			t.Errorf("selectLeaf = %v, want nil", got)
		}
	})

	t.Run("GetCertificate", func(t *testing.T) {
		// crypto/tls consults GetCertificate only when Certificates is empty or
		// SNI is non-empty, and treats a (nil, nil) return as "fall back to
		// Certificates". Calling it here reproduces neither rule, and a callback
		// written with the documented hello.SupportsCertificate idiom errors
		// against a synthetic ClientHelloInfo.
		cfg := &tls.Config{
			Certificates:   []tls.Certificate{one},
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &two, nil },
		}
		if got := selectLeaf(cfg); got != nil {
			t.Errorf("selectLeaf = %v, want nil when a callback selects the certificate", got)
		}
	})

	t.Run("GetConfigForClient", func(t *testing.T) {
		// The whole config can be swapped per connection, so even Certificates
		// is not authoritative.
		cfg := &tls.Config{
			Certificates: []tls.Certificate{one},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{Certificates: []tls.Certificate{two}}, nil //nolint:gosec // test config
			},
		}
		if got := selectLeaf(cfg); got != nil {
			t.Errorf("selectLeaf = %v, want nil when the config itself may be replaced", got)
		}
	})
}

func TestMisdirectedRequest(t *testing.T) {
	leaf, _ := leafFor(t, "a.example")

	for _, tc := range []struct {
		name string
		req  *Request
		leaf *x509.Certificate
		want bool
	}{
		{"authority covered by the certificate", &Request{Scheme: "https", Authority: "a.example"}, leaf, false},
		{"authority not covered", &Request{Scheme: "https", Authority: "b.example"}, leaf, true},
		{"port is not part of the identity", &Request{Scheme: "https", Authority: "a.example:8443"}, leaf, false},
		{"non-https scheme is out of scope", &Request{Scheme: "http", Authority: "b.example"}, leaf, false},
		// RFC 9110 §4.2.3 (rfc9110.txt:1179): "The scheme and host are
		// case-insensitive". An uppercase spelling is the same scheme, so it
		// must not be a way to opt out of the check.
		{"uppercase scheme still checked", &Request{Scheme: "HTTPS", Authority: "b.example"}, leaf, true},
		{"mixed-case scheme still checked", &Request{Scheme: "HtTpS", Authority: "b.example"}, leaf, true},
		{"uppercase scheme, covered authority", &Request{Scheme: "HTTPS", Authority: "a.example"}, leaf, false},
		{"no certificate to judge against", &Request{Scheme: "https", Authority: "b.example"}, nil, false},
		{"hostless authority is rejected earlier", &Request{Scheme: "https", Authority: ""}, leaf, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := misdirectedRequest(tc.req, tc.leaf); got != tc.want {
				t.Errorf("misdirectedRequest = %v, want %v", got, tc.want)
			}
		})
	}
}
