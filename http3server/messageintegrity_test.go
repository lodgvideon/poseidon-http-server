package http3server

import (
	"errors"
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Two ways a request can claim to be something other than what arrived (#212).
//
// Both were served to the handler as ordinary requests before this. Both are the
// same shape of defect: this server and a conformant intermediary in front of it
// end up disagreeing about where the message ends, which is what a smuggling
// differential is made of.
//
//   A. RFC 9114 §7.1 — a frame truncated by a clean FIN. Connection error,
//      H3_FRAME_ERROR.
//   B. RFC 9114 §4.1 — Content-Length disagreeing with the DATA that arrived.
//      Malformed message, so a stream error of H3_MESSAGE_ERROR per §4.1.2.
//
// The difference in blast radius is the RFC's, not a preference: a broken frame
// layer means the connection can no longer be parsed, a malformed message means
// only that request is bad.
// ---------------------------------------------------------------------------

// validHeaders is a complete, valid request header section, as a frame.
func validHeaders() []byte { return headersFrame(validFields) }

// ---------------------------------------------------------------------------
// A. Truncated trailing frame (RFC 9114 §7.1)
// ---------------------------------------------------------------------------

func TestDecodeRequest_TruncatedTrailingFrameIsConnectionError(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		// The case with teeth: a complete request, then a DATA frame promising
		// 100 octets and delivering 10. Served before this as a finished request
		// with an EMPTY body — the ten delivered octets silently discarded.
		"DATA cut short mid-payload": append(
			append(validHeaders(), http3.AppendFrameHeader(nil, http3.FrameData, 100)...),
			[]byte("0123456789")...,
		),
		// Nothing of the payload arrived, only the promise of it.
		"DATA header with no payload": append(
			validHeaders(), http3.AppendFrameHeader(nil, http3.FrameData, 8)...,
		),
		// A frame header cut off inside its own length varint: no type to name.
		"frame header cut off": append(validHeaders(), 0x00),
		// After a complete DATA frame, so the truncation is genuinely the LAST
		// frame rather than the first thing after the header section.
		"truncation after a complete DATA": append(
			append(http3.AppendData(validHeaders(), []byte("hello")),
				http3.AppendFrameHeader(nil, http3.FrameData, 64)...),
			[]byte("partial")...,
		),
		// A trailer section that was cut off is still a truncated last frame.
		"trailer HEADERS cut short": append(
			append(http3.AppendData(validHeaders(), []byte("hi")),
				http3.AppendFrameHeader(nil, http3.FrameHeaders, 4096)...),
			encodeSection([]hpack.HeaderField{field("x-a", "1")})...,
		),
	}

	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req, err := decodeRequest(stream)
			assertRequestContract(t, req, err)
			if err == nil {
				t.Fatal("a truncated last frame was served as a complete request")
			}
			var cfe *connFrameError
			if !errors.As(err, &cfe) {
				t.Fatalf("err = %v (%T), want a *connFrameError so the CONNECTION is closed; "+
					"RFC 9114 §7.1 makes a truncated last frame a connection error", err, err)
			}
			if cfe.code != http3.H3FrameError {
				t.Errorf("close code = %#x, want H3_FRAME_ERROR %#x", cfe.code, http3.H3FrameError)
			}
			if !strings.Contains(err.Error(), "§7.1") {
				t.Errorf("error %q does not cite the rule it enforces", err)
			}
		})
	}
}

// TestDecodeRequest_TruncationDoesNotSwallowTheCleanCase is the negative control.
// A stream consumed to its last octet must still decode; without this, "always
// return H3_FRAME_ERROR on ErrNeedMore" would pass the table above.
func TestDecodeRequest_TruncationDoesNotSwallowTheCleanCase(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"header section only":     validHeaders(),
		"header section and DATA": http3.AppendData(validHeaders(), []byte("hello")),
		"two DATA frames":         http3.AppendData(http3.AppendData(validHeaders(), []byte("ab")), []byte("cd")),
		"a trailing GREASE frame": append(validHeaders(), http3.AppendFrameHeader(nil, 0x21, 0)...),
	}

	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req, err := decodeRequest(stream)
			assertRequestContract(t, req, err)
			if err != nil {
				t.Fatalf("a complete stream was rejected: %v", err)
			}
		})
	}
}

// TestDecodeRequest_IncompleteStaysStreamLevel pins the boundary between §7.1 and
// #180. A stream that never produced a header section is not a truncated frame
// problem but an incomplete REQUEST, and §8.1 has a code that says exactly that.
// Both verdicts are reachable, and they must not collapse into one another: the
// first closes the connection, the second only resets the stream.
func TestDecodeRequest_IncompleteStaysStreamLevel(t *testing.T) {
	t.Parallel()

	noHeaderSection := map[string][]byte{
		"a truncated frame header":  {0x40},
		"a HEADERS frame cut short": append(http3.AppendFrameHeader(nil, http3.FrameHeaders, 4096), encodeSection(validFields)...),
	}
	for name, stream := range noHeaderSection {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeRequest(stream)
			var cfe *connFrameError
			if errors.As(err, &cfe) {
				t.Fatalf("err = %v: a stream with no header section must NOT close the connection", err)
			}
			if !errors.Is(err, errRequestIncomplete) {
				t.Fatalf("err = %v, want errRequestIncomplete", err)
			}
			if got := requestAbortCode(err); got != h3RequestIncomplete {
				t.Errorf("abort code = %#x, want H3_REQUEST_INCOMPLETE %#x", got, h3RequestIncomplete)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// B. Content-Length against the DATA that arrived (RFC 9114 §4.1)
// ---------------------------------------------------------------------------

// clStream builds a complete request carrying content-length: cl and body.
func clStream(cl string, body []byte) []byte {
	fields := append(append([]hpack.HeaderField{}, validFields...), field("content-length", cl))
	s := http3.AppendHeaders(nil, encodeSection(fields))
	if len(body) > 0 {
		s = http3.AppendData(s, body)
	}
	return s
}

func TestDecodeRequest_ContentLengthMustMatchTheDATAReceived(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cl   string
		body []byte
		ok   bool
	}{
		{"agrees", "5", []byte("hello"), true},
		{"agrees at zero", "0", nil, true},
		{"agrees on a large body", "1024", make([]byte, 1024), true},

		// §4.1: "malformed if the value of the Content-Length header field does
		// not equal the sum of the DATA frame lengths received".
		{"over-declared", "100", []byte("hello"), false},
		{"under-declared", "2", []byte("hello"), false},
		{"declared with no DATA at all", "5", nil, false},
		{"zero declared but a body sent", "0", []byte("hello"), false},

		// §8.6 defines the value as 1*DIGIT.
		{"empty value", "", []byte("hello"), false},
		{"not a number", "abc", []byte("hello"), false},
		{"signed positive", "+5", []byte("hello"), false},
		{"signed negative", "-5", []byte("hello"), false},
		{"hex", "0x5", []byte("hello"), false},
		{"overflows int64", "99999999999999999999", []byte("hello"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := decodeRequest(clStream(tc.cl, tc.body))
			assertRequestContract(t, req, err)
			if tc.ok {
				if err != nil {
					t.Fatalf("content-length %q with %d body bytes rejected: %v", tc.cl, len(tc.body), err)
				}
				// assertRequestContract has already drained req.Body and pinned
				// ContentLength against what it yielded, so this ties that
				// self-consistent pair to the body the peer actually sent.
				if req.ContentLength != int64(len(tc.body)) {
					t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(tc.body))
				}
				return
			}
			if err == nil {
				t.Fatalf("content-length %q with %d body bytes was accepted", tc.cl, len(tc.body))
			}
			if !errors.Is(err, http3.ErrH3Message) {
				t.Fatalf("err = %v, want http3.ErrH3Message", err)
			}
			// A malformed MESSAGE is a stream error (§4.1.2), never a connection one.
			var cfe *connFrameError
			if errors.As(err, &cfe) {
				t.Errorf("a malformed message closed the connection; §4.1.2 makes it a stream error")
			}
			if got := requestAbortCode(err); got != http3.H3MessageError {
				t.Errorf("abort code = %#x, want H3_MESSAGE_ERROR %#x", got, http3.H3MessageError)
			}
		})
	}
}

// TestBuildRequest_RepeatedContentLength covers RFC 9110 §8.6's repeated-field
// rule, which cannot be reached through clStream because it needs two field
// lines of the same name.
func TestBuildRequest_RepeatedContentLength(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		values []string
		ok     bool
	}{
		{"identical values collapse", []string{"5", "5"}, true},
		{"three identical values", []string{"5", "5", "5"}, true},
		{"differing values are unresolvable", []string{"5", "6"}, false},
		{"one good one junk", []string{"5", "abc"}, false},
		{"differing, first one right", []string{"5", "0"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fields := append([]hpack.HeaderField{}, validFields...)
			for _, v := range tc.values {
				fields = append(fields, field("content-length", v))
			}
			req, err := buildRequest(fields, []byte("hello"))
			assertRequestContract(t, req, err)
			if tc.ok && err != nil {
				t.Fatalf("content-length %v rejected: %v", tc.values, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("content-length %v was accepted", tc.values)
				}
				if !errors.Is(err, http3.ErrH3Message) {
					t.Fatalf("err = %v, want http3.ErrH3Message", err)
				}
			}
		})
	}
}

// TestBuildRequest_ContentLengthSurvivesToTheHandler is the reason this matters
// beyond conformance. The disagreeing header used to reach req.Header intact
// while ContentLength was quietly rewritten to the byte count that arrived, so a
// handler proxying req.Header onward forwarded the peer's claim, not the truth.
// Now no such request reaches a handler at all — and for one that does, the two
// agree.
func TestBuildRequest_ContentLengthSurvivesToTheHandler(t *testing.T) {
	t.Parallel()

	req, err := buildRequest(
		append(append([]hpack.HeaderField{}, validFields...), field("content-length", "5")),
		[]byte("hello"),
	)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if got, want := req.Header.Get("Content-Length"), "5"; got != want {
		t.Errorf("forwarded Content-Length = %q, want %q", got, want)
	}
	if req.ContentLength != 5 {
		t.Errorf("req.ContentLength = %d, want 5", req.ContentLength)
	}
}
