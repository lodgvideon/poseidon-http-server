package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for RFC 9113 §8.2.1 field validation and §8.2.2's ban on
// connection-specific fields.
//
//	§8.2.1 — "implementations MUST perform the following
//	minimal validation of field names and values"
//	  :2508 names must avoid 0x00-0x20, 0x41-0x5a (uppercase) and 0x7f-0xff
//	  :2513 names must not include a colon, except a single leading one
//	  :2517 values must not contain NUL, LF or CR at any position
//	  :2521 values must not start or end with SP or HTAB
//
//	§8.2.2 — "Any message containing connection-specific
//	header fields MUST be treated as malformed."
//
//	§8.1.1 fixes the reaction: a stream error of type
//	PROTOCOL_ERROR, so the connection and its sibling streams survive.
//
// Only the value half of :2517 was implemented. A field name went entirely
// unchecked, which is why `Content-Length` — uppercase, and therefore a
// different field from `content-length` to every lowercase comparison in this
// repository — was forwarded verbatim.

func reqWith(extra ...hpack.HeaderField) []hpack.HeaderField {
	base := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
	}
	return append(base, extra...)
}

// TestConformance_RFC9113_Sec821_MalformedFieldSyntax_StreamError pins the four
// checks of RFC 9113 §8.2.1 and §8.2.2's field ban, each as a stream error.
func TestConformance_RFC9113_Sec821_MalformedFieldSyntax_StreamError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field hpack.HeaderField
		why   string
	}{
		{"uppercase_name", hpack.HeaderField{Name: []byte("Content-Length"), Value: []byte("0")}, ":2508 excludes 'A' to 'Z'"},
		{"space_in_name", hpack.HeaderField{Name: []byte("x te"), Value: []byte("1")}, ":2508 excludes 0x00-0x20"},
		{"del_in_name", hpack.HeaderField{Name: []byte("x-\x7f"), Value: []byte("1")}, ":2508 excludes 0x7f-0xff"},
		{"high_octet_in_name", hpack.HeaderField{Name: []byte("x-\xff"), Value: []byte("1")}, ":2508 excludes 0x7f-0xff"},
		{"interior_colon_in_name", hpack.HeaderField{Name: []byte("x-forwarded-for:extra"), Value: []byte("1")}, ":2513 forbids a non-leading colon"},
		{"empty_name", hpack.HeaderField{Name: []byte(""), Value: []byte("1")}, "a field must have a name"},
		{"leading_space_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte(" v")}, ":2521 forbids leading SP"},
		{"trailing_space_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("v ")}, ":2521 forbids trailing SP"},
		{"leading_htab_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("\tv")}, ":2521 forbids leading HTAB"},
		{"trailing_htab_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("v\t")}, ":2521 forbids trailing HTAB"},

		// §8.2.2 (:2547) — the five connection-specific field names.
		{"connection", hpack.HeaderField{Name: []byte("connection"), Value: []byte("close")}, "§8.2.2"},
		{"keep_alive", hpack.HeaderField{Name: []byte("keep-alive"), Value: []byte("timeout=5")}, "§8.2.2"},
		{"proxy_connection", hpack.HeaderField{Name: []byte("proxy-connection"), Value: []byte("close")}, "§8.2.2"},
		{"transfer_encoding", hpack.HeaderField{Name: []byte("transfer-encoding"), Value: []byte("chunked")}, "§8.2.2"},
		{"upgrade", hpack.HeaderField{Name: []byte("upgrade"), Value: []byte("websocket")}, "§8.2.2"},

		// §8.2.2 (:2559) — TE is the one exception, and only for "trailers".
		{"te_with_other_value", hpack.HeaderField{Name: []byte("te"), Value: []byte("gzip")}, ":2559 permits only \"trailers\""},
		{"te_with_list", hpack.HeaderField{Name: []byte("te"), Value: []byte("trailers, deflate")}, ":2559 permits only \"trailers\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, reqWith(tc.field), true)
			})
			if !rc.sawRST {
				t.Fatalf("no RST_STREAM for %s (%s); RFC 9113 §8.1.1 requires a malformed "+
					"request be reset (goaway=%v code=%v)", tc.name, tc.why, rc.sawGoAway, rc.goAwayCode)
			}
			if rc.rstCode != frame.ErrCodeProtocolError {
				t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR", rc.rstCode)
			}
			if rc.sawGoAway {
				t.Errorf("GOAWAY(%v); §8.1.1 makes a malformed message a STREAM error", rc.goAwayCode)
			}
		})
	}
}

// TestConformance_RFC9113_Sec821_LegalFieldsAccepted is the other half, and it
// is not decoration. The colon rule is the easiest in the specification to
// implement as "reject any name containing a colon", which refuses every
// pseudo-header and bricks the server on the first request of every connection.
// This test fails loudly if the leading-colon exemption is ever simplified away.
//
// It also pins the parts deliberately left legal: an interior HTAB in a value,
// obs-text, and `te: trailers`, which every gRPC client sends.
func TestConformance_RFC9113_Sec821_LegalFieldsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field hpack.HeaderField
	}{
		{"lowercase_name", hpack.HeaderField{Name: []byte("content-length"), Value: []byte("0")}},
		{"interior_htab_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("a\tb")}},
		{"interior_space_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("a b")}},
		{"obs_text_in_value", hpack.HeaderField{Name: []byte("x-a"), Value: []byte{0xC3, 0xA9}}},
		{"colon_in_value_is_fine", hpack.HeaderField{Name: []byte("x-a"), Value: []byte("host:443")}},
		{"te_trailers", hpack.HeaderField{Name: []byte("te"), Value: []byte("trailers")}},
		{"te_trailers_uppercase", hpack.HeaderField{Name: []byte("te"), Value: []byte("Trailers")}},
		{"digits_and_dashes", hpack.HeaderField{Name: []byte("x-request-id-2"), Value: []byte("abc")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, reqWith(tc.field), true)
			})
			if rc.sawRST {
				t.Errorf("RST_STREAM(%v) for a legal field", rc.rstCode)
			}
			if rc.sawGoAway {
				t.Errorf("GOAWAY(%v) for a legal field", rc.goAwayCode)
			}
		})
	}
}

// TestConformance_RFC9113_Sec81_TrailerRules pins the two rules that apply only
// to a trailer section.
//
//	:2411 — "Trailers MUST NOT include pseudo-header fields."
//	:2415 — the field section that ends a message "bears an END_STREAM flag".
//
// Both are reached only on a request whose opening HEADERS left the stream open;
// a field section arriving after END_STREAM is answered STREAM_CLOSED by §5.1
// before these rules apply.
func TestConformance_RFC9113_Sec81_TrailerRules(t *testing.T) {
	trailer := func(fields []hpack.HeaderField, endStream bool) func(*frame.Framer) {
		return func(cliFr *frame.Framer) {
			// Request stays open: no END_STREAM, so the next field section on this
			// stream is a trailer section.
			sendReq(t, cliFr, 1, reqWith(), false)
			sendReq(t, cliFr, 1, fields, endStream)
		}
	}

	t.Run("pseudo_header_in_trailers", func(t *testing.T) {
		rc := runRSTProbe(t, trailer([]hpack.HeaderField{
			{Name: []byte(":status"), Value: []byte("200")},
		}, true))
		if !rc.sawRST {
			t.Fatalf("no RST_STREAM for a pseudo-header in a trailer section "+
				"(goaway=%v code=%v)", rc.sawGoAway, rc.goAwayCode)
		}
		if rc.rstCode != frame.ErrCodeProtocolError {
			t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR", rc.rstCode)
		}
	})

	t.Run("trailers_without_end_stream", func(t *testing.T) {
		rc := runRSTProbe(t, trailer([]hpack.HeaderField{
			{Name: []byte("x-checksum"), Value: []byte("deadbeef")},
		}, false))
		if !rc.sawRST {
			t.Fatalf("no RST_STREAM for a trailer section without END_STREAM "+
				"(goaway=%v code=%v)", rc.sawGoAway, rc.goAwayCode)
		}
		if rc.rstCode != frame.ErrCodeProtocolError {
			t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR", rc.rstCode)
		}
	})

	t.Run("well_formed_trailers_accepted", func(t *testing.T) {
		rc := runRSTProbe(t, trailer([]hpack.HeaderField{
			{Name: []byte("x-checksum"), Value: []byte("deadbeef")},
		}, true))
		if rc.sawRST {
			t.Errorf("RST_STREAM(%v) for a well-formed trailer section", rc.rstCode)
		}
		if rc.sawGoAway {
			t.Errorf("GOAWAY(%v) for a well-formed trailer section", rc.goAwayCode)
		}
	})
}
