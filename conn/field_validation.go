package conn

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
