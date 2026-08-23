package http3server

import (
	"errors"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Inbound field validation on the HTTP/3 request path (issue #209).
//
// Before this, buildRequest ran no validation at all: every check below passed
// straight through to the handler, while the HTTP/2 front door of the same binary
// refused all of them. The two that matter beyond conformance are
// transfer-encoding and CR/LF — forwarded to an HTTP/1.1 backend they are a
// request-smuggling and header-injection differential between two doors of one
// server.
//
// The table is deliberately expressed against buildRequest rather than a live
// QUIC connection: the verdict is a pure function of the decoded field section,
// so testing it as one is deterministic on every platform and strictly more
// discriminating than one connection per case. TestDecodeRequest_RejectsProhibited
// covers the other half — that the verdict survives the real decode chain — and
// TestRequestAbortCode_MalformedIsMessageError covers the third — that it reaches
// the peer as the error code §4.1.2 names.
// ---------------------------------------------------------------------------

// withFields returns the minimal conformant section plus extra.
func withFields(extra ...hpack.HeaderField) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(validFields)+len(extra))
	out = append(out, validFields...)
	return append(out, extra...)
}

func TestBuildRequest_RejectsProhibitedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		fields []hpack.HeaderField
		cite   string
	}{
		// RFC 9114 §4.2: "An endpoint MUST NOT generate an HTTP/3 field section
		// containing connection-specific fields... any message containing
		// connection-specific fields MUST be treated as malformed."
		{"connection", withFields(field("connection", "keep-alive")), "§4.2"},
		{"proxy-connection", withFields(field("proxy-connection", "keep-alive")), "§4.2"},
		{"keep-alive", withFields(field("keep-alive", "timeout=5")), "§4.2"},
		{"transfer-encoding", withFields(field("transfer-encoding", "chunked")), "§4.2"},
		{"upgrade", withFields(field("upgrade", "websocket")), "§4.2"},

		// §4.2: "when [TE] is present it MUST NOT contain any value other than
		// 'trailers'."
		{"te with a non-trailers value", withFields(field("te", "gzip")), "§4.2"},
		{"te with trailers plus more", withFields(field("te", "trailers, deflate")), "§4.2"},

		// §4.1: "invalid characters in field names or values". RFC 9110 §5.5 makes
		// CR, LF and NUL in a value invalid and dangerous.
		{"CR LF in a value", withFields(field("x-a", "a\r\nx-injected: yes")), "§4.1"},
		{"bare CR in a value", withFields(field("x-a", "a\rb")), "§4.1"},
		{"bare LF in a value", withFields(field("x-a", "a\nb")), "§4.1"},
		{"NUL in a value", withFields(field("x-a", "a\x00b")), "§4.1"},
		{"leading SP in a value", withFields(field("x-a", " lead")), "§4.1"},
		{"trailing SP in a value", withFields(field("x-a", "trail ")), "§4.1"},
		{"leading HTAB in a value", withFields(field("x-a", "\tlead")), "§4.1"},

		// §4.2: "A request or response containing uppercase characters in field
		// names MUST be treated as malformed."
		{"uppercase field name", withFields(field("X-Upper", "1")), "§4.2"},
		{"single uppercase octet", withFields(field("x-uppeR", "1")), "§4.2"},

		// §4.1: prohibited field names. An empty name names nothing; an interior
		// colon survives HTTP/3 as one field and splits in two at the next
		// HTTP/1.1 hop.
		{"empty field name", withFields(field("", "v")), "§4.1"},
		{"interior colon in a name", withFields(field("x-forwarded-for:extra", "1")), "§4.1"},
		{"SP in a field name", withFields(field("x bad", "1")), "§4.1"},
		{"DEL in a field name", withFields(field("x-\x7f", "1")), "§4.1"},

		// §4.1: "pseudo-header fields after fields", "prohibited... pseudo-header
		// fields", and duplicates. §4.3.1 forbids userinfo in :authority.
		{"duplicate :method", withFields(field(":method", "POST")), "§4.3.1"},
		{"duplicate :path", withFields(field(":path", "/other")), "§4.3.1"},
		{
			"pseudo-header after a regular field",
			[]hpack.HeaderField{
				field(":method", "GET"), field(":scheme", "https"),
				field("x-a", "1"),
				field(":path", "/"),
			},
			"§4.3",
		},
		{
			"userinfo in :authority",
			[]hpack.HeaderField{
				field(":method", "GET"), field(":scheme", "https"),
				field(":authority", "user@example.com"), field(":path", "/"),
			},
			"§4.3.1",
		},
		{"undefined pseudo-header", withFields(field(":protocol", "websocket")), "§4.3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := buildRequest(tc.fields, nil)
			assertRequestContract(t, req, err)
			if err == nil {
				t.Fatalf("RFC 9114 %s: accepted, want malformed", tc.cite)
			}
			if !errors.Is(err, http3.ErrH3Message) {
				t.Fatalf("err = %v, want http3.ErrH3Message so §4.1.2 reports H3_MESSAGE_ERROR", err)
			}
		})
	}
}

// TestBuildRequest_AcceptsConformant is the other half of the table: the
// validation must not have swept up anything legal. te: trailers in particular is
// on every gRPC request, and rejecting it would take gRPC-over-HTTP/3 offline.
func TestBuildRequest_AcceptsConformant(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		fields []hpack.HeaderField
	}{
		{"the minimal section", validFields},
		{"te: trailers (gRPC)", withFields(field("te", "trailers"))},
		{"te: TRAILERS — transfer codings are case-insensitive", withFields(field("te", "TRAILERS"))},
		{"interior HTAB in a value stays legal", withFields(field("x-a", "a\tb"))},
		{"obs-text in a value stays legal", withFields(field("x-a", "caf\xc3\xa9"))},
		{"an empty value", withFields(field("x-a", ""))},
		{"no :authority", []hpack.HeaderField{
			field(":method", "GET"), field(":scheme", "https"), field(":path", "/"),
		}},
		{"a query string", []hpack.HeaderField{
			field(":method", "POST"), field(":scheme", "https"),
			field(":authority", "example.com"), field(":path", "/x?a=1&b=2"),
		}},
		{"repeated regular fields are not duplicates", withFields(
			field("x-a", "1"), field("x-a", "2"),
		)},
		{"cookie crumbs (§4.2 permits the split)", withFields(
			field("cookie", "a=1"), field("cookie", "b=2"),
		)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := buildRequest(tc.fields, nil)
			assertRequestContract(t, req, err)
			if err != nil {
				t.Fatalf("conformant section rejected: %v", err)
			}
		})
	}
}

// TestDecodeRequest_RejectsProhibited drives the real decode chain — QPACK field
// section, HEADERS frame, decodeRequest — for the two classes with teeth, so the
// table above cannot pass while the production path bypasses it.
//
// Only lowercase names are exercised here: the QPACK encoder is a conformant
// sender and will not emit an uppercase name, so that case is reachable only at
// the buildRequest seam (and from a hostile peer, which is what the fuzz target
// covers).
func TestDecodeRequest_RejectsProhibited(t *testing.T) {
	t.Parallel()

	cases := map[string][]hpack.HeaderField{
		"transfer-encoding": withFields(field("transfer-encoding", "chunked")),
		"connection":        withFields(field("connection", "keep-alive")),
		"CRLF in a value":   withFields(field("x-a", "a\r\nx-injected: yes")),
		"NUL in a value":    withFields(field("x-a", "a\x00b")),
	}

	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stream := http3.AppendHeaders(nil, encodeSection(fields))
			req, err := decodeRequest(stream)
			assertRequestContract(t, req, err)
			if err == nil {
				t.Fatal("decodeRequest accepted a malformed request")
			}
			if !errors.Is(err, http3.ErrH3Message) {
				t.Fatalf("err = %v, want http3.ErrH3Message", err)
			}
			if got := requestAbortCode(err); got != http3.H3MessageError {
				t.Fatalf("requestAbortCode = %#x, want H3_MESSAGE_ERROR %#x", got, http3.H3MessageError)
			}
		})
	}
}

// TestDecodeRequest_AcceptsConformant pins the negative control on the same
// chain: a conformant request must still reach a handler.
func TestDecodeRequest_AcceptsConformant(t *testing.T) {
	t.Parallel()

	stream := http3.AppendHeaders(nil, encodeSection(withFields(field("te", "trailers"))))
	req, err := decodeRequest(stream)
	assertRequestContract(t, req, err)
	if err != nil {
		t.Fatalf("conformant request rejected: %v", err)
	}
	if req.Method != "GET" || req.URL.Path != "/" {
		t.Fatalf("decoded %s %s, want GET /", req.Method, req.URL.Path)
	}
}
