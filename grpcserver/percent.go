package grpcserver

// Percent-encoding for the grpc-message trailer.
//
// RFC 9110 §2.2 (rfc9110.txt:572): "A sender MUST NOT generate protocol
// elements that do not match the grammar defined by the corresponding ABNF
// rules." The grammar is supplied by the gRPC-over-HTTP/2 spec
// (doc/PROTOCOL-HTTP2.md):
//
//	Status-Message         -> "grpc-message" Percent-Encoded
//	Percent-Encoded        -> 1*(Percent-Byte-Unencoded / Percent-Byte-Encoded)
//	Percent-Byte-Unencoded -> 1*( %x20-%x24 / %x26-%x7E ) ; space and VCHAR, except %
//	Percent-Byte-Encoded   -> "%" 2HEXDIGIT ; 0-9 A-F
//
// The message is attacker-reachable: the router interpolates the client's
// :path into "unknown method %s", and errToStatus falls back to err.Error().
// Emitted raw, a message carrying CR LF is a trailer-injection primitive.

// upperHex is the "0-9 A-F" alphabet the ABNF's 2HEXDIGIT requires.
const upperHex = "0123456789ABCDEF"

// mustEncode reports whether an octet falls outside Percent-Byte-Unencoded,
// i.e. outside %x20-%x24 and %x26-%x7E. That covers every CTL, DEL, the
// percent sign itself, and every octet of a multi-byte UTF-8 sequence.
func mustEncode(c byte) bool {
	return c < 0x20 || c == '%' || c > 0x7E
}

// percentEncodeMessage renders a status message as Percent-Encoded.
//
// Returns nil for an empty message: Percent-Encoded is 1*(...) so it cannot
// match zero octets, and Status-Message is optional in Trailers — the field is
// omitted rather than emitted empty.
//
// The common case is a message that needs no encoding at all, which costs the
// same single []byte conversion the unencoded path always did.
func percentEncodeMessage(s string) []byte {
	if s == "" {
		return nil
	}
	extra := 0
	for i := range len(s) {
		if mustEncode(s[i]) {
			extra += 2
		}
	}
	if extra == 0 {
		return []byte(s)
	}
	out := make([]byte, 0, len(s)+extra)
	for i := range len(s) {
		c := s[i]
		if mustEncode(c) {
			out = append(out, '%', upperHex[c>>4], upperHex[c&0x0F])
			continue
		}
		out = append(out, c)
	}
	return out
}
