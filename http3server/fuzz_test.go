package http3server

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
)

// field is a shorthand for a QPACK/HPACK field.
func field(n, v string) hpack.HeaderField {
	return hpack.HeaderField{Name: []byte(n), Value: []byte(v)}
}

// validFields is a minimal conformant request field section (RFC 9114 §4.3.1).
var validFields = []hpack.HeaderField{
	field(":method", "GET"),
	field(":scheme", "https"),
	field(":authority", "example.com"),
	field(":path", "/"),
}

// encodeSection compresses fields into a QPACK field section under the
// static-table profile the server implements.
func encodeSection(fields []hpack.HeaderField) []byte {
	return qpack.NewEncoder().EncodeFieldSection(nil, fields)
}

// assertRequestContract checks the (*http.Request, error) contract shared by
// decodeRequest and buildRequest: exactly one of the two is non-nil, and a
// returned request is internally consistent. A decoder that hands the handler a
// request with a nil URL or a ContentLength disagreeing with Body would turn a
// peer's bytes into a panic (or a silently truncated body) deeper in the stack,
// so these are asserted rather than merely "it didn't crash".
func assertRequestContract(t *testing.T, req *http.Request, err error) {
	t.Helper()
	if err != nil {
		if req != nil {
			t.Fatalf("returned both a request and an error: %v", err)
		}
		return
	}
	if req == nil {
		t.Fatal("returned a nil request and a nil error")
	}
	// The mandatory pseudo-headers are what make the request routable; empty
	// values here mean the §4.3.1 checks let a malformed message through.
	if req.Method == "" {
		t.Fatal("built a request with an empty Method")
	}
	if req.URL == nil {
		t.Fatal("built a request with a nil URL")
	}
	if req.RequestURI == "" {
		t.Fatal("built a request with an empty RequestURI")
	}
	body, rerr := io.ReadAll(req.Body)
	if rerr != nil {
		t.Fatalf("reading the built request's Body: %v", rerr)
	}
	// A handler that trusts ContentLength over Body (as net/http's own helpers
	// do) must not be able to be lied to by the peer.
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d but Body yielded %d bytes", req.ContentLength, len(body))
	}
}

// FuzzDecodeRequest feeds arbitrary bytes to decodeRequest, the top untrusted
// surface of this package: it is handed a whole request stream read off a QUIC
// connection, so every byte — the HTTP/3 frame headers, the QPACK field section
// inside HEADERS, and the DATA payloads — is chosen by the peer, before any
// authentication. It drives http3.FrameReader, the QPACK decoder, and
// buildRequest in one pass.
//
// Contract: decodeRequest returns either (*http.Request, nil) or (nil, error) —
// never a panic, never a hang, and never unbounded buffering (SetMaxFrameLen
// caps a frame at maxRequestBytes). A returned request must satisfy the
// invariants in assertRequestContract.
func FuzzDecodeRequest(f *testing.F) {
	headers := http3.AppendHeaders(nil, encodeSection(validFields))

	f.Add(headers)                                                // a valid, complete request
	f.Add(http3.AppendData(headers, []byte("body")))              // valid HEADERS + DATA
	f.Add(append(headers, headers...))                            // two HEADERS: the trailers path
	f.Add([]byte(nil))                                            // empty stream: no HEADERS
	f.Add([]byte{0x40})                                           // truncated 2-byte varint frame header
	f.Add(http3.AppendData(nil, []byte("body only")))             // DATA with no HEADERS
	f.Add(http3.AppendHeaders(nil, []byte{0xff, 0xff}))           // HEADERS with a garbage QPACK section
	f.Add(http3.AppendFrameHeader(nil, http3.FrameData, 1<<62-1)) // absurd declared length, no payload
	// A HEADERS frame whose declared length overruns the bytes present.
	f.Add(append(http3.AppendFrameHeader(nil, http3.FrameHeaders, 4096), encodeSection(validFields)...))

	f.Fuzz(func(t *testing.T, stream []byte) {
		req, err := decodeRequest(stream)
		assertRequestContract(t, req, err)
	})
}

// FuzzBuildRequest fuzzes the pseudo-header validation (RFC 9114 §4.3.1) and the
// url.ParseRequestURI call on a peer-controlled :path. These strings arrive
// verbatim from the QPACK field section, so a peer picks every one of them,
// including names that collide with the pseudo-headers.
//
// Contract: buildRequest returns either (*http.Request, nil) or (nil, error)
// without panicking, and a request it accepts satisfies assertRequestContract.
func FuzzBuildRequest(f *testing.F) {
	f.Add("GET", "https", "/", "example.com", "x-a", "1", []byte("hi"))
	f.Add("POST", "http", "/p?q=1#f", "example.com:443", "content-type", "text/plain", []byte(nil))
	f.Add("GET", "https", "://", "", "x", "", []byte(nil))         // an unparseable :path
	f.Add("", "", "", "", ":bogus", "x", []byte(nil))              // an unknown pseudo-header
	f.Add("GET", "https", "*", "example.com", "", "", []byte(nil)) // asterisk-form (OPTIONS)
	f.Add("CONNECT", "https", "/", "example.com", "\x00", "\x7f", []byte("\x00\xff"))

	f.Fuzz(func(t *testing.T, method, scheme, path, authority, name, value string, body []byte) {
		fields := []hpack.HeaderField{
			field(":method", method),
			field(":scheme", scheme),
			field(":path", path),
			field(":authority", authority),
			field(name, value),
		}
		req, err := buildRequest(fields, body)
		assertRequestContract(t, req, err)
	})
}

// FuzzDecodeFields fuzzes the QPACK field-section decoder wrapper with the raw
// bytes a peer puts inside a HEADERS frame: prefixed integers, Huffman-coded
// literals, and static-table references, all attacker-chosen.
//
// Contract: decodeFields returns either fields with a nil error or a nil slice
// with an error, and never panics on a malformed section. Anything it accepts
// must survive a re-encode/re-decode round trip unchanged: the decoder hands the
// callback name/value slices aliasing its own scratch buffer, so a missed copy
// would let a later field silently corrupt an earlier one — which is how a peer
// would smuggle a header past a handler that already inspected it.
func FuzzDecodeFields(f *testing.F) {
	f.Add(encodeSection(validFields))                         // a valid section
	f.Add(encodeSection([]hpack.HeaderField{field("a", "")})) // a single literal, empty value
	f.Add([]byte(nil))                                        // an empty section
	f.Add([]byte{0x00})                                       // prefix only, no fields
	f.Add([]byte{0x00, 0x00, 0xff, 0xff, 0xff, 0xff})         // an unterminated prefixed integer
	f.Add([]byte{0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0x7f})   // an oversized static-table index
	f.Add([]byte{0x00, 0x00, 0x2f, 0x00})                     // a literal claiming a length past the end

	f.Fuzz(func(t *testing.T, section []byte) {
		fields, err := decodeFields(section)
		if err != nil {
			if fields != nil {
				t.Fatalf("decodeFields returned both fields and an error: %v", err)
			}
			return
		}
		// Re-encoding is not byte-identical (the encoder is free to pick literal
		// vs. static-table forms), so the round trip is checked on the fields.
		reenc := encodeSection(fields)
		again, err := decodeFields(reenc)
		if err != nil {
			t.Fatalf("re-decoding a section built from accepted fields: %v (section=%x)", err, reenc)
		}
		if len(again) != len(fields) {
			t.Fatalf("round trip changed the field count: %d, want %d", len(again), len(fields))
		}
		for i := range fields {
			if !bytes.Equal(fields[i].Name, again[i].Name) || !bytes.Equal(fields[i].Value, again[i].Value) {
				t.Fatalf("round trip changed field %d: %q=%q, want %q=%q",
					i, again[i].Name, again[i].Value, fields[i].Name, fields[i].Value)
			}
		}
	})
}
