package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for request pseudo-header validation (RFC 9113 §8.3).
//
// Quotes copied verbatim from rfc9113.txt fetched from rfc-editor.org:
//
//	§8.3 "Endpoints MUST NOT generate pseudo-header fields other than those
//	       defined in this document."
//	§8.3 "Endpoints MUST treat a request or response that contains undefined
//	       or invalid pseudo-header fields as malformed (Section 8.1.1)."
//	§8.3 "All pseudo-header fields MUST appear in a field block before all
//	       regular field lines. Any request or response that contains a
//	       pseudo-header field that appears in a field block after a regular
//	       field line MUST be treated as malformed (Section 8.1.1)."
//	§8.3 "The same pseudo-header field name MUST NOT appear more than once in
//	       a field block. A field block for an HTTP request or response that
//	       contains a repeated pseudo-header field name MUST be treated as
//	       malformed (Section 8.1.1)."
//	§8.3.1 "':authority' MUST NOT include the deprecated userinfo subcomponent
//	       for 'http' or 'https' schemed URIs."
//	§8.3.1 "This pseudo-header field MUST NOT be empty for 'http' or 'https'
//	       URIs"
//	§8.3.1 "All HTTP/2 requests MUST include exactly one valid value for the
//	       ':method', ':scheme', and ':path' pseudo-header fields, unless
//	       they are CONNECT requests (Section 8.5). An HTTP request that omits
//	       mandatory pseudo-header fields is malformed (Section 8.1.1)."
//
// The reaction is fixed by §8.1.1: "Malformed requests or responses
// that are detected MUST be treated as a stream error (Section 5.4.2) of type
// PROTOCOL_ERROR" — reset the stream, keep the connection.

func hf(name, value string) hpack.HeaderField {
	return hpack.HeaderField{Name: []byte(name), Value: []byte(value)}
}

func TestConformance_RFC9113_Sec83_MalformedPseudoHeaders_StreamError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []hpack.HeaderField
		why     string
	}{
		{
			"missing_method",
			[]hpack.HeaderField{hf(":scheme", "https"), hf(":path", "/")},
			"RFC 9113 §8.3.1 — :method is mandatory",
		},
		{
			"missing_scheme",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":path", "/")},
			"RFC 9113 §8.3.1 — :scheme is mandatory",
		},
		{
			"missing_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https")},
			"RFC 9113 §8.3.1 — :path is mandatory",
		},
		{
			"empty_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "")},
			"RFC 9113 §8.3.1 — :path MUST NOT be empty for http/https URIs",
		},
		{
			"duplicate_method",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":method", "POST"), hf(":scheme", "https"), hf(":path", "/")},
			"RFC 9113 §8.3 — a repeated pseudo-header name is malformed",
		},
		{
			"duplicate_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/a"), hf(":path", "/b")},
			"RFC 9113 §8.3 — a repeated pseudo-header name is malformed",
		},
		{
			"undefined_pseudo_header",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":protocol-x", "y")},
			"RFC 9113 §8.3 — an undefined pseudo-header is malformed",
		},
		{
			"pseudo_after_regular_field",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf("x-early", "1"), hf(":path", "/")},
			"RFC 9113 §8.3 — pseudo-headers MUST precede all regular field lines",
		},
		{
			"authority_with_userinfo",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "user@example.com")},
			"RFC 9113 §8.3.1 — :authority MUST NOT include userinfo for http/https",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, tc.headers, true)
			})
			if !rc.sawRST {
				t.Fatalf("no RST_STREAM: %s (goaway=%v code=%v)", tc.why, rc.sawGoAway, rc.goAwayCode)
			}
			if rc.rstCode != frame.ErrCodeProtocolError {
				t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR (RFC 9113 §8.1.1); %s", rc.rstCode, tc.why)
			}
			if rc.sawGoAway {
				t.Errorf("GOAWAY(%v): a malformed request is a STREAM error, not a connection error", rc.goAwayCode)
			}
		})
	}
}

// TestConformance_RFC9113_Sec83_ValidRequestsAccepted guards the other
// direction. Over-eager validation is its own bug: each of these is explicitly
// legal and must NOT be reset.
func TestConformance_RFC9113_Sec83_ValidRequestsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []hpack.HeaderField
		why     string
	}{
		{
			"plain_get",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "example.com")},
			"the ordinary case",
		},
		{
			"asterisk_form_options",
			[]hpack.HeaderField{hf(":method", "OPTIONS"), hf(":scheme", "https"), hf(":path", "*")},
			"RFC 9113 §8.3.1 — asterisk-form OPTIONS carries :path '*'",
		},
		{
			"connect_omits_scheme_and_path",
			[]hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "example.com:443")},
			"RFC 9113 §8.3.1 — the mandatory-pseudo-header rule exempts CONNECT",
		},
		{
			"non_http_scheme",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "ftp"), hf(":path", "/x"), hf(":authority", "example.com")},
			"RFC 9113 §8.3.1 — \":scheme\" is not restricted to http and https",
		},
		{
			"authority_with_port",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "example.com:8443")},
			"a port is part of the authority, not userinfo",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, tc.headers, true)
			})
			if rc.sawRST {
				t.Errorf("RST_STREAM(%v) for a legal request; %s", rc.rstCode, tc.why)
			}
			if rc.sawGoAway {
				t.Errorf("GOAWAY(%v) for a legal request; %s", rc.goAwayCode, tc.why)
			}
		})
	}
}

// TestConformance_RFC9113_Sec83_SchemeIsCaseInsensitive pins RFC 9110 §4.2.3
// (RFC 9110 §4.2.3): "The scheme and host are case-insensitive and normally
// provided in lowercase; all other components are compared in a case-sensitive
// manner."
//
// So "HTTPS" is the same scheme as "https", not a different one. The scheme
// comparison decides whether the http/https-specific rules of §8.3 apply — the
// non-empty :path rule (RFC 9113 §8.3.1) and the userinfo prohibition
// (RFC 9113 §8.3.1) — so a case-sensitive comparison lets a client opt out of both by
// uppercasing a single header value.
func TestConformance_RFC9113_Sec83_SchemeIsCaseInsensitive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []hpack.HeaderField
		why     string
	}{
		{
			"uppercase_scheme_empty_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "HTTPS"), hf(":path", "")},
			"an empty :path is malformed for https however the scheme is spelled",
		},
		{
			"mixed_case_scheme_empty_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "HtTp"), hf(":path", "")},
			"same for http",
		},
		{
			"uppercase_scheme_userinfo",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "HTTPS"), hf(":path", "/"), hf(":authority", "user@example.com")},
			"userinfo is forbidden for https however the scheme is spelled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, tc.headers, true)
			})
			if !rc.sawRST {
				t.Fatalf("no RST_STREAM: %s (goaway=%v)", tc.why, rc.sawGoAway)
			}
			if rc.rstCode != frame.ErrCodeProtocolError {
				t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR", rc.rstCode)
			}
		})
	}
}
