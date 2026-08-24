// Package httpfields holds the field rules that HTTP/2 and HTTP/3 share, in both
// directions.
//
// The rules are the same rules. RFC 9113 §8.2.1 and RFC 9114 §4.1/§4.2 impose the
// same character checks, the same connection-specific-field ban, the same TE rule
// and the same pseudo-header rules on both endpoints; only the error code differs
// (PROTOCOL_ERROR for HTTP/2, H3_MESSAGE_ERROR for HTTP/3), and that is the
// caller's business, not this package's.
//
// Receiving: [Prohibited] and [ValidRequestPseudoHeaders] say whether an arriving
// message is malformed. Sending: [ProhibitedInResponse] and [InterimStatus] say
// what a response this server generates may not contain. The two directions are
// separate because the verdicts differ — a receiver rejects the message, a sender
// drops the field.
//
// # Why this is its own package
//
// These checks used to live unexported inside conn/, so http3server — which does
// not import conn — could not reach them and shipped with none of them: a request
// arriving over HTTP/3 could carry Transfer-Encoding, a CRLF-split field value or
// an uppercase field name that the HTTP/2 front door on the same binary refuses.
// Forwarded to an HTTP/1.1 backend that is a smuggling and header-injection
// differential between two doors of one server (issue #209).
//
// So the rule for anything added here: it is a property of an HTTP message, not of
// a transport. Anything that needs to know about frames, streams, HPACK dynamic
// tables or QPACK belongs in conn/ or http3server/, not here.
//
// # Hot path
//
// [Prohibited] is called once per decoded field from inside the HTTP/2 decode
// callback that already runs, so it must stay allocation-free (ADR-0001). Every
// comparison below is length-first with string(b) == "lit", which the compiler
// does not allocate for. Do not "simplify" these into map lookups or
// strings.ToLower.
package httpfields

import (
	"bytes"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Inbound HTTP field validation (RFC 9110 §5.5 via RFC 9113 §8.2.1, RFC 9114 §4.2).
//
// RFC 9110 §5.5:
//
//	"Field values containing CR, LF, or NUL characters are invalid and
//	 dangerous, due to the varying ways that implementations might parse and
//	 interpret those characters; a recipient of CR, LF, or NUL within a field
//	 value MUST either reject the message or replace each of those characters
//	 with SP before further processing or forwarding of that message."
//
// This server rejects. RFC 9113 §8.1.1 fixes how for HTTP/2:
// "Malformed requests or responses that are detected MUST be treated as a
// stream error (Section 5.4.2) of type PROTOCOL_ERROR" — the offending stream
// is reset and the connection survives. RFC 9114 §4.1.2 says the same for
// HTTP/3 with H3_MESSAGE_ERROR.
//
// RFC 9113 §8.2.1 turns that into four checks a receiver
// must perform, "a minimal set of validations":
//
//	"A field name MUST NOT contain characters in the ranges 0x00-0x20,
//	 0x41-0x5a, or 0x7f-0xff (all ranges inclusive). This specifically
//	 excludes all non-visible ASCII characters, ASCII SP (0x20), and
//	 uppercase characters ('A' to 'Z', ASCII 0x41 to 0x5a)."
//	"With the exception of pseudo-header fields (Section 8.3), which have
//	 a name that starts with a single colon, field names MUST NOT include
//	 a colon (ASCII COLON, 0x3a)."
//	"A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line
//	 feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any
//	 position."
//	"A field value MUST NOT start or end with an ASCII whitespace
//	 character (ASCII SP or HTAB, 0x20 or 0x09)."
//
// RFC 9114 §4.2 restates the uppercase half for HTTP/3 — "A request or response
// containing uppercase characters in field names MUST be treated as malformed" —
// and §4.1's malformed list carries the rest as "invalid characters in field
// names or values".
//
// Interior HTAB and obs-text stay legal — RFC 9110 §5.5 says
// values "containing other CTL characters are also invalid; however, recipients
// MAY retain such characters", so nothing beyond the four checks is rejected.

// hasProhibitedFieldChar reports whether a field value breaks either of the two
// value rules: a CR, LF or NUL anywhere in it, or leading/trailing whitespace.
//
// Hot path: called once per decoded header field, one pass, no allocation.
func hasProhibitedFieldChar(value []byte) bool {
	if n := len(value); n > 0 {
		if c := value[0]; c == ' ' || c == '\t' {
			return true
		}
		if c := value[n-1]; c == ' ' || c == '\t' {
			return true
		}
	}
	for _, c := range value {
		if c == '\r' || c == '\n' || c == 0x00 {
			return true
		}
	}
	return false
}

// hasProhibitedFieldName reports whether a field name breaks either of the two
// name rules. An empty name is prohibited too: it can name nothing, and every
// caller downstream assumes at least one octet.
//
// The i != 0 on the colon test is load-bearing rather than incidental: every
// pseudo-header begins with one, so rejecting any colon at all would refuse the
// first request on every connection. What it catches is the interior colon —
// "x-forwarded-for:extra" survives HTTP/2 as one field and splits into two at
// the next HTTP/1.1 hop.
//
// Hot path: one pass over the name, no allocation.
func hasProhibitedFieldName(name []byte) bool {
	if len(name) == 0 {
		return true
	}
	for i, c := range name {
		if c <= 0x20 || c >= 0x7f || (c >= 'A' && c <= 'Z') {
			return true
		}
		if c == ':' && i != 0 {
			return true
		}
	}
	return false
}

// teTrailers is the sole value RFC 9113 permits the TE field to carry.
var teTrailers = []byte("trailers")

// isConnectionSpecificName reports whether the field name is one HTTP/2 forbids
// outright.
//
//	RFC 9113 §8.2.2 — "An endpoint MUST NOT generate an
//	HTTP/2 message containing connection-specific header fields. This includes
//	the Connection header field and those listed as having connection-specific
//	semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive,
//	Transfer-Encoding, and Upgrade). Any message containing connection-specific
//	header fields MUST be treated as malformed."
//
// RFC 9114 §4.2 carries the identical list and the identical verdict for HTTP/3,
// which is why this lives here rather than in conn/.
//
// TE is the documented exception and is checked separately, by value: gRPC
// clients send "te: trailers" on every request.
//
// Length-first switch, and string(n) == "lit" is the comparison the compiler
// does not allocate for (ADR-0001).
func isConnectionSpecificName(n []byte) bool {
	switch len(n) {
	case 7:
		return string(n) == "upgrade"
	case 10:
		return string(n) == "connection" || string(n) == "keep-alive"
	case 16:
		return string(n) == "proxy-connection"
	case 17:
		return string(n) == "transfer-encoding"
	}
	return false
}

// Prohibited reports whether one decoded field makes the message malformed,
// covering RFC 9113 §8.2.1's four character checks and §8.2.2's
// connection-specific ban — and, identically, RFC 9114 §4.1's malformed list and
// §4.2's field rules. isTrailer selects the extra rule that applies only to a
// trailer section.
//
// Hot path: called once per decoded field inside the decode callback that
// already runs. No allocation.
func Prohibited(name, value []byte, isTrailer bool) bool {
	if hasProhibitedFieldName(name) || hasProhibitedFieldChar(value) {
		return true
	}
	// RFC 9113 §8.1 — "Trailers MUST NOT include pseudo-header
	// fields". The name check above has already established the name is non-empty.
	if isTrailer && name[0] == ':' {
		return true
	}
	// §8.2.2 — TE "MUST NOT contain any value other than 'trailers'".
	// EqualFold because transfer codings are case-insensitive tokens (RFC 9110
	// §10.1.4): a case-sensitive compare here would be the same opt-out-by-
	// uppercasing bypass already closed for :scheme.
	if len(name) == 2 && string(name) == "te" {
		return !bytes.EqualFold(value, teTrailers)
	}
	return isConnectionSpecificName(name)
}

// ---------------------------------------------------------------------------
// Sender side: what a response field section may not carry
// ---------------------------------------------------------------------------

// responseStatus is the only pseudo-header defined for a response.
var responseStatus = []byte(":status")

// ProhibitedInResponse reports whether a field name must not appear in a
// response field section this server generates.
//
//	RFC 9113 §8.2.2 / RFC 9114 §4.2 — "An endpoint MUST NOT generate an
//	 HTTP/2 message containing connection-specific header fields", the same list
//	 [Prohibited] enforces on the way in.
//	RFC 9113 §8.3 / RFC 9114 §4.3 — pseudo-header fields are limited to those
//	 defined, and ":status" is the only one defined for a response.
//	RFC 9114 §4.2 — TE "MAY be present in an HTTP/3 request header"; a response
//	 is not a request, so TE has no place in one at any value.
//
// # Why strip rather than fail
//
// A handler written for net/http sets Connection: close as a matter of routine,
// and answering 500 because of it would break ordinary code for no safety gain.
// Removing the field is also literally what §4.2 instructs an intermediary
// translating from HTTP/1.x to do. So a caller drops the field and sends the
// rest.
//
// The pseudo-header half is not routine and is the reason this is not merely
// tidiness: textproto.CanonicalMIMEHeaderKey leaves a name containing ':'
// untouched, so w.Header().Set(":authority", …) reached the wire verbatim on
// both transports. A handler that builds a header name out of user input could
// therefore be made to inject a pseudo-header into the response.
//
// Hot path: called once per response field. Length-first, and EqualFold rather
// than a plain compare because the native HTTP/2 write path takes field names
// from the caller and cannot assume they were lowercased. Allocation-free.
func ProhibitedInResponse(name []byte) bool {
	if len(name) == 0 {
		return true
	}
	if name[0] == ':' {
		return !bytes.Equal(name, responseStatus) // pseudo-headers are case-sensitive
	}
	if len(name) == 2 && (name[0]|0x20) == 't' && (name[1]|0x20) == 'e' {
		return true
	}
	switch len(name) {
	case 7:
		return bytes.EqualFold(name, sUpgrade)
	case 10:
		return bytes.EqualFold(name, sConnection) || bytes.EqualFold(name, sKeepAlive)
	case 16:
		return bytes.EqualFold(name, sProxyConnection)
	case 17:
		return bytes.EqualFold(name, sTransferEncoding)
	}
	return false
}

var (
	sUpgrade          = []byte("upgrade")
	sConnection       = []byte("connection")
	sKeepAlive        = []byte("keep-alive")
	sProxyConnection  = []byte("proxy-connection")
	sTransferEncoding = []byte("transfer-encoding")
)

// InterimStatus reports whether status is a 1xx, which may not be used as a
// response's final status.
//
//	RFC 9113 §8.1 / RFC 9114 §4.1 — a response is "zero or more interim
//	 responses (1xx) followed by a single final response".
//
// Both servers latched the first status a handler passed and ignored every
// later one, so WriteHeader(http.StatusContinue) or StatusEarlyHints ended the
// exchange on an interim response and no final one ever followed — and on
// HTTP/3, RFC 9114 §4.4 additionally has no 101 at all, since HTTP/3 does not
// carry the Upgrade mechanism.
//
// Zero or more interim responses includes zero, so declining to send one is
// conformant where letting it stand as the final response is not. Sending them
// properly is a separate piece of work: it needs the response written in stages
// rather than at the end, which http3server's buffered writer does not yet do.
func InterimStatus(status int) bool { return status >= 100 && status < 200 }

// Request pseudo-header validation, verbatim rules:
//
//	RFC 9113 §8.3 — "Endpoints MUST treat a request or response that contains
//	 undefined or invalid pseudo-header fields as malformed (Section 8.1.1)."
//	RFC 9113 §8.3 — "All pseudo-header fields MUST appear in a field block
//	 before all regular field lines."
//	RFC 9113 §8.3 — "The same pseudo-header field name MUST NOT appear more
//	 than once in a field block."
//	RFC 9113 §8.3.1 — "':authority' MUST NOT include the deprecated userinfo
//	 subcomponent for 'http' or 'https' schemed URIs."
//	RFC 9113 §8.3.1 — "This pseudo-header field MUST NOT be empty for "http"
//	 or "https" URIs"
//	RFC 9113 §8.3.1 — "All HTTP/2 requests MUST include exactly one valid
//	 value for the ":method", ":scheme", and ":path" pseudo-header fields,
//	 unless they are CONNECT requests (Section 8.5)."
//
// RFC 9114 §4.3 and §4.3.1 restate every one of these for HTTP/3 with the same
// pseudo-header set and the same CONNECT exemption (§4.4).
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
// that depend on position and repetition (RFC 9113 §8.3) plus the
// undefined-name rule (also §8.3). Reports false the moment the block is malformed.
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

// ValidRequestPseudoHeaders reports whether a decoded request field block
// satisfies RFC 9113 §8.3 (equivalently RFC 9114 §4.3.1). One pass, no allocation.
func ValidRequestPseudoHeaders(fields []hpack.HeaderField) bool {
	ph, ok := scanRequestPseudoHeaders(fields)
	if !ok {
		return false
	}
	// §8.3.1 — :method is mandatory for every request, CONNECT included.
	if ph.method == nil {
		return false
	}
	// EqualFold, not Equal: RFC 9110 §4.2.3 — "The scheme and
	// host are case-insensitive and normally provided in lowercase". "HTTPS" is
	// the same scheme as "https", so a case-sensitive comparison would let a
	// client opt out of every rule below by uppercasing one header value.
	httpScheme := bytes.EqualFold(ph.scheme, schemeHTTP) || bytes.EqualFold(ph.scheme, schemeHTTPS)
	// §8.3.1 — userinfo is forbidden in :authority for http/https URIs.
	if httpScheme && bytes.IndexByte(ph.authority, '@') >= 0 {
		return false
	}
	// §8.3.1 — the mandatory-:scheme/:path rule exempts CONNECT, which omits
	// both (§8.5; RFC 9114 §4.4 for HTTP/3).
	if bytes.Equal(ph.method, methodCONNECT) { // methods ARE case-sensitive (§9.1)
		return true
	}
	if ph.scheme == nil || !ph.seenPath {
		return false
	}
	// §8.3.1 — :path MUST NOT be empty for http/https URIs. Other schemes are
	// out of that sentence's scope (§8.3.1 — ":scheme" is not restricted to
	// "http" and "https"), so the emptiness rule is not extended to them.
	return !httpScheme || len(ph.path) > 0
}
