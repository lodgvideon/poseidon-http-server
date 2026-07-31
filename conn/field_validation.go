package conn

import (
	"bytes"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Inbound HTTP field validation (RFC 9110 §5.5 via RFC 9113 §8.2.1).
//
// RFC 9110 §5.5 (rfc9110.txt:1606):
//
//	"Field values containing CR, LF, or NUL characters are invalid and
//	 dangerous, due to the varying ways that implementations might parse and
//	 interpret those characters; a recipient of CR, LF, or NUL within a field
//	 value MUST either reject the message or replace each of those characters
//	 with SP before further processing or forwarding of that message."
//
// This server rejects. RFC 9113 §8.1.1 (rfc9113.txt:2463) fixes how:
// "Malformed requests or responses that are detected MUST be treated as a
// stream error (Section 5.4.2) of type PROTOCOL_ERROR" — the offending stream
// is reset and the connection survives.
//
// Deliberately narrow: RFC 9110 §5.5 goes on to say that field values
// "containing other CTL characters are also invalid; however, recipients MAY
// retain such characters" (rfc9110.txt:1611), so only the three dangerous
// octets are rejected here. HTAB and obs-text stay legal.

// hasProhibitedFieldChar reports whether a field value contains CR, LF, or NUL.
//
// Hot path: called once per decoded header field, one pass, no allocation.
func hasProhibitedFieldChar(value []byte) bool {
	for _, c := range value {
		if c == '\r' || c == '\n' || c == 0x00 {
			return true
		}
	}
	return false
}

// Request pseudo-header validation (RFC 9113 §8.3), verbatim rules:
//
//	:2614 "Endpoints MUST treat a request or response that contains undefined
//	       or invalid pseudo-header fields as malformed (Section 8.1.1)."
//	:2619 "All pseudo-header fields MUST appear in a field block before all
//	       regular field lines."
//	:2624 "The same pseudo-header field name MUST NOT appear more than once in
//	       a field block."
//	:2690 ":authority" MUST NOT include the deprecated userinfo subcomponent
//	       for "http" or "https" schemed URIs."
//	:2699 "This pseudo-header field MUST NOT be empty for "http" or "https"
//	       URIs"
//	:2710 "All HTTP/2 requests MUST include exactly one valid value for the
//	       ":method", ":scheme", and ":path" pseudo-header fields, unless they
//	       are CONNECT requests (Section 8.5)."
//
// Before this existed the target URI was reconstructed with no validation at
// all: a missing :authority was silently repaired with the literal "localhost"
// (RFC 9110 §4.2 requires a URI with an empty host be rejected, not invented),
// and a request could arrive with no :scheme or no :path.

var (
	pseudoMethod    = []byte(":method")
	pseudoScheme    = []byte(":scheme")
	pseudoPath      = []byte(":path")
	pseudoAuthority = []byte(":authority")
	methodCONNECT   = []byte("CONNECT")
	schemeHTTP      = []byte("http")
	schemeHTTPS     = []byte("https")
)

// requestPseudoHeaders holds the four request pseudo-header values defined by
// RFC 9113 §8.3.1. A nil value means the field was absent; seenPath
// distinguishes an absent :path from a present-but-empty one.
type requestPseudoHeaders struct {
	method    []byte
	scheme    []byte
	path      []byte
	authority []byte
	seenPath  bool
}

// scanRequestPseudoHeaders collects the pseudo-headers, enforcing the two rules
// that depend on position and repetition (:2619, :2624) plus the
// undefined-name rule (:2614). Reports false the moment the block is malformed.
func scanRequestPseudoHeaders(fields []hpack.HeaderField) (requestPseudoHeaders, bool) {
	var ph requestPseudoHeaders
	seenRegular := false

	for i := range fields {
		name := fields[i].Name
		if len(name) == 0 {
			return ph, false
		}
		if name[0] != ':' {
			seenRegular = true
			continue
		}
		// :2619 — a pseudo-header after a regular field line is malformed.
		if seenRegular {
			return ph, false
		}
		// :2624 — a repeated pseudo-header name is malformed.
		var dup bool
		switch {
		case bytes.Equal(name, pseudoMethod):
			dup, ph.method = ph.method != nil, fields[i].Value
		case bytes.Equal(name, pseudoScheme):
			dup, ph.scheme = ph.scheme != nil, fields[i].Value
		case bytes.Equal(name, pseudoPath):
			dup, ph.path, ph.seenPath = ph.seenPath, fields[i].Value, true
		case bytes.Equal(name, pseudoAuthority):
			dup, ph.authority = ph.authority != nil, fields[i].Value
		default:
			// :2614 — undefined pseudo-header fields are malformed. Extensions
			// negotiate additional ones (§5.5); none are negotiated here.
			return ph, false
		}
		if dup {
			return ph, false
		}
	}
	return ph, true
}

// validRequestPseudoHeaders reports whether a decoded request field block
// satisfies RFC 9113 §8.3. One pass, no allocation.
func validRequestPseudoHeaders(fields []hpack.HeaderField) bool {
	ph, ok := scanRequestPseudoHeaders(fields)
	if !ok {
		return false
	}
	// :2710 — :method is mandatory for every request, CONNECT included.
	if ph.method == nil {
		return false
	}
	httpScheme := bytes.Equal(ph.scheme, schemeHTTP) || bytes.Equal(ph.scheme, schemeHTTPS)
	// :2690 — userinfo is forbidden in :authority for http/https URIs.
	if httpScheme && bytes.IndexByte(ph.authority, '@') >= 0 {
		return false
	}
	// :2710 — the mandatory-:scheme/:path rule exempts CONNECT, which omits
	// both (§8.5).
	if bytes.Equal(ph.method, methodCONNECT) {
		return true
	}
	if ph.scheme == nil || !ph.seenPath {
		return false
	}
	// :2699 — :path MUST NOT be empty for http/https URIs. Other schemes are
	// out of that sentence's scope (:2643 — ":scheme" is not restricted to
	// "http" and "https"), so the emptiness rule is not extended to them.
	return !httpScheme || len(ph.path) > 0
}
