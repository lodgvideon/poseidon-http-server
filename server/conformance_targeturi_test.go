package server

import (
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for target-URI reconstruction.
//
// RFC 9110 §4.2.1 (rfc9110.txt:1106) and §4.2.2 (:1135), identical wording for
// each scheme:
//
//	"A sender MUST NOT generate an "http" URI with an empty host identifier.
//	 A recipient that processes such a URI reference MUST reject it as invalid."
//
// The authority has two legal sources. RFC 9110 §7.2 (rfc9110.txt:2426):
//
//	"A user agent MUST generate a Host header field in a request unless it
//	 sends that information as an ":authority" pseudo-header field."
//
// Note this rule is deliberately NOT enforced in conn/: RFC 9113 §8.3.1 makes
// only :method, :scheme and :path mandatory, so a block without :authority is
// not malformed at the HTTP/2 layer. The rule binds "a recipient that processes
// such a URI reference" — which is exactly here, where scheme://host/path is
// assembled.

func fieldsFor(pairs ...string) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, hpack.HeaderField{Name: []byte(pairs[i]), Value: []byte(pairs[i+1])})
	}
	return out
}

// TestConformance_RFC9110_Sec42_EmptyHostRejected pins rfc9110.txt:1106/:1135.
// The server used to substitute the literal "localhost" here, inventing an
// authority the client never sent.
func TestConformance_RFC9110_Sec42_EmptyHostRejected(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			req := &Request{Method: "GET", Path: "/", Scheme: scheme}
			got, err := NewHTTPRequest(req)
			if err == nil {
				t.Fatalf("built a request with an empty host: %q — RFC 9110 §4.2 says a "+
					"recipient MUST reject such a URI reference as invalid", got.URL.String())
			}
			if !strings.Contains(err.Error(), "authority") {
				t.Errorf("error = %v; want it to name the missing authority", err)
			}
		})
	}
}

// TestConformance_RFC9110_Sec72_HostSuppliesAuthority pins rfc9110.txt:2426:
// a request that carries Host instead of :authority is legal, and its authority
// must come from that field rather than being invented.
func TestConformance_RFC9110_Sec72_HostSuppliesAuthority(t *testing.T) {
	s := &Server{}
	req := s.buildRequest(fieldsFor(
		":method", "GET",
		":scheme", "https",
		":path", "/x",
		"host", "example.com:8443",
	), 1)

	if req.Authority != "example.com:8443" {
		t.Fatalf("Authority = %q, want it taken from the Host field", req.Authority)
	}
	httpReq, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}
	if got, want := httpReq.URL.String(), "https://example.com:8443/x"; got != want {
		t.Errorf("target URI = %q, want %q", got, want)
	}
}

// TestConformance_RFC9110_Sec72_AuthorityWinsOverHost pins RFC 9113 §8.3.1
// (rfc9113.txt:2649): "The recipient of an HTTP/2 request MUST NOT use the Host
// header field to determine the target URI if ":authority" is present."
func TestConformance_RFC9110_Sec72_AuthorityWinsOverHost(t *testing.T) {
	s := &Server{}
	req := s.buildRequest(fieldsFor(
		":method", "GET",
		":scheme", "https",
		":path", "/x",
		":authority", "authoritative.example",
		"host", "decoy.example",
	), 1)

	if req.Authority != "authoritative.example" {
		t.Errorf("Authority = %q, want the :authority value; the Host field MUST NOT "+
			"determine the target URI when :authority is present", req.Authority)
	}
}

// TestConformance_RFC9110_Sec42_NonHTTPSchemeUnaffected guards the boundary:
// the empty-host rule names the "http" and "https" schemes, and RFC 9113
// (rfc9113.txt:2643) says ":scheme" is not restricted to those, so a non-HTTP
// scheme must not be dragged into it.
func TestConformance_RFC9110_Sec42_NonHTTPSchemeUnaffected(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", Scheme: "ftp", Authority: "files.example"}
	if _, err := NewHTTPRequest(req); err != nil {
		t.Errorf("NewHTTPRequest for a non-HTTP scheme: %v", err)
	}
}
