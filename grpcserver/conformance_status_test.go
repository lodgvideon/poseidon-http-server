package grpcserver

import (
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the grpc-status / grpc-message trailers.
//
// The binding MUST is RFC 9110 §2.2 (rfc9110.txt:572):
//
//	"A sender MUST NOT generate protocol elements that do not match the
//	 grammar defined by the corresponding ABNF rules."
//
// The grammar for these trailers comes from the gRPC-over-HTTP/2 spec
// (grpc/grpc doc/PROTOCOL-HTTP2.md, fetched from raw.githubusercontent.com):
//
//	Status-Message         -> "grpc-message" Percent-Encoded          (:112)
//	Percent-Encoded        -> 1*(Percent-Byte-Unencoded / Percent-Byte-Encoded)  (:114)
//	Percent-Byte-Unencoded -> 1*( %x20-%x24 / %x26-%x7E ) ; space and VCHAR, except %  (:115)
//	Percent-Byte-Encoded   -> "%" 2HEXDIGIT ; 0-9 A-F                 (:116)
//
//	"The value portion of Status-Message is conceptually a Unicode string
//	 description of the error, physically encoded as UTF-8 followed by
//	 percent-encoding."                                                (:130)
//
// This matters beyond pedantry: the message is built from attacker-controlled
// input -- Statusf(Unimplemented, "unknown method %s", req.Path) interpolates
// the client's :path, and errToStatus falls back to err.Error().

func findField(fields []hpack.HeaderField, name string) (string, bool) {
	for _, f := range fields {
		if string(f.Name) == name {
			return string(f.Value), true
		}
	}
	return "", false
}

// TestConformance_RFC9110_Sec22_GRPCMessagePercentEncoded pins the
// Percent-Byte-Unencoded production: every octet outside %x20-%x24 and
// %x26-%x7E must be emitted as "%" 2HEXDIGIT.
func TestConformance_RFC9110_Sec22_GRPCMessagePercentEncoded(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"percent_itself", "50%", "50%25"},
		{"CR_LF", "bad\r\nvalue", "bad%0D%0Avalue"},
		{"NUL", "a\x00b", "a%00b"},
		{"tab", "a\tb", "a%09b"},
		{"DEL", "a\x7fb", "a%7Fb"},
		{"utf8_multibyte", "café", "caf%C3%A9"},
		{"header_injection_via_path", "unknown method /x\r\ngrpc-status: 0", "unknown method /x%0D%0Agrpc-status: 0"},
		{"clean_ascii_untouched", "resource not found", "resource not found"},
		{"space_and_bang_untouched", " !\"#$&~", " !\"#$&~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := statusToHPack(RPCStatus{Code: NotFound, Message: tc.in})
			got, ok := findField(fields, HeaderGRPCMessage)
			if !ok {
				t.Fatalf("no %s field emitted for message %q", HeaderGRPCMessage, tc.in)
			}
			if got != tc.want {
				t.Errorf("grpc-message = %q, want %q", got, tc.want)
			}
			// Hex digits must be uppercase per "2HEXDIGIT ; 0-9 A-F".
			for i := 0; i+2 < len(got); i++ {
				if got[i] != '%' {
					continue
				}
				if h := got[i+1 : i+3]; h != strings.ToUpper(h) {
					t.Errorf("grpc-message %q has lowercase hex %q; the ABNF says 0-9 A-F", got, h)
				}
			}
		})
	}
}

// TestConformance_RFC9110_Sec22_GRPCMessageOmittedWhenEmpty pins the "1*" in
// Percent-Encoded: the production cannot match zero octets, and Status-Message
// is optional in Trailers (PROTOCOL-HTTP2.md:109), so an empty message must be
// left out rather than emitted as an empty field value.
func TestConformance_RFC9110_Sec22_GRPCMessageOmittedWhenEmpty(t *testing.T) {
	fields := statusToHPack(RPCStatus{Code: OK})
	if v, ok := findField(fields, HeaderGRPCMessage); ok {
		t.Errorf("emitted %s: %q for an empty message; Percent-Encoded is 1*(...) "+
			"and Status-Message is optional", HeaderGRPCMessage, v)
	}
	if v, ok := findField(fields, HeaderGRPCStatus); !ok || v != "0" {
		t.Errorf("grpc-status = %q (present=%v), want \"0\"", v, ok)
	}
}
