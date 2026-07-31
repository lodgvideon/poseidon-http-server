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
//	:2606 "Endpoints MUST NOT generate pseudo-header fields other than those
//	       defined in this document."
//	:2614 "Endpoints MUST treat a request or response that contains undefined
//	       or invalid pseudo-header fields as malformed (Section 8.1.1)."
//	:2619 "All pseudo-header fields MUST appear in a field block before all
//	       regular field lines. Any request or response that contains a
//	       pseudo-header field that appears in a field block after a regular
//	       field line MUST be treated as malformed (Section 8.1.1)."
//	:2624 "The same pseudo-header field name MUST NOT appear more than once in
//	       a field block. A field block for an HTTP request or response that
//	       contains a repeated pseudo-header field name MUST be treated as
//	       malformed (Section 8.1.1)."
//	:2690 "\":authority\" MUST NOT include the deprecated userinfo subcomponent
//	       for \"http\" or \"https\" schemed URIs."
//	:2699 "This pseudo-header field MUST NOT be empty for \"http\" or \"https\"
//	       URIs"
//	:2710 "All HTTP/2 requests MUST include exactly one valid value for the
//	       \":method\", \":scheme\", and \":path\" pseudo-header fields, unless
//	       they are CONNECT requests (Section 8.5). An HTTP request that omits
//	       mandatory pseudo-header fields is malformed (Section 8.1.1)."
//
// The reaction is fixed by §8.1.1 (:2463): "Malformed requests or responses
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
			"rfc9113.txt:2710 — :method is mandatory",
		},
		{
			"missing_scheme",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":path", "/")},
			"rfc9113.txt:2710 — :scheme is mandatory",
		},
		{
			"missing_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https")},
			"rfc9113.txt:2710 — :path is mandatory",
		},
		{
			"empty_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "")},
			"rfc9113.txt:2699 — :path MUST NOT be empty for http/https URIs",
		},
		{
			"duplicate_method",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":method", "POST"), hf(":scheme", "https"), hf(":path", "/")},
			"rfc9113.txt:2624 — a repeated pseudo-header name is malformed",
		},
		{
			"duplicate_path",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/a"), hf(":path", "/b")},
			"rfc9113.txt:2624 — a repeated pseudo-header name is malformed",
		},
		{
			"undefined_pseudo_header",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":protocol-x", "y")},
			"rfc9113.txt:2614 — an undefined pseudo-header is malformed",
		},
		{
			"pseudo_after_regular_field",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf("x-early", "1"), hf(":path", "/")},
			"rfc9113.txt:2619 — pseudo-headers MUST precede all regular field lines",
		},
		{
			"authority_with_userinfo",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "user@example.com")},
			"rfc9113.txt:2690 — :authority MUST NOT include userinfo for http/https",
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
				t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR (rfc9113.txt:2463); %s", rc.rstCode, tc.why)
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
			"rfc9113.txt:2703 — asterisk-form OPTIONS carries :path '*'",
		},
		{
			"connect_omits_scheme_and_path",
			[]hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "example.com:443")},
			"rfc9113.txt:2710 — the mandatory-pseudo-header rule exempts CONNECT",
		},
		{
			"non_http_scheme",
			[]hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "ftp"), hf(":path", "/x"), hf(":authority", "example.com")},
			"rfc9113.txt:2643 — \":scheme\" is not restricted to http and https",
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
