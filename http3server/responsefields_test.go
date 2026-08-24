package http3server

import (
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
)

// ---------------------------------------------------------------------------
// The HTTP/3 half of #212 group C: what encodeResponse may put on the wire.
//
// The rule itself lives in internal/httpfields and is unit-tested there; these
// assert that this transport actually applies it, by decoding the QPACK section
// encodeResponse produced rather than trusting that the filter was called.
// ---------------------------------------------------------------------------

// decodeResponseFields pulls the field section back out of an encoded response.
func decodeResponseFields(t *testing.T, stream []byte) []hpack.HeaderField {
	t.Helper()
	var fr http3.FrameReader
	fr.SetMaxFrameLen(maxRequestBytes)
	fr.Feed(stream)
	for {
		typ, payload, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no HEADERS frame in the response: %v", err)
		}
		if typ != http3.FrameHeaders {
			continue
		}
		var out []hpack.HeaderField
		if derr := qpack.NewDecoder().DecodeFieldSection(payload, nil, func(n, v []byte) error {
			out = append(out, hpack.HeaderField{
				Name:  append([]byte(nil), n...),
				Value: append([]byte(nil), v...),
			})
			return nil
		}); derr != nil {
			t.Fatalf("decoding the response field section: %v", derr)
		}
		return out
	}
}

func responseNames(t *testing.T, rw *responseWriter) []string {
	t.Helper()
	out, err := encodeResponse(rw, maxFieldSection)
	if err != nil {
		t.Fatalf("encodeResponse: %v", err)
	}
	fields := decodeResponseFields(t, out)
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, string(f.Name))
	}
	return names
}

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestEncodeResponse_DropsForbiddenFields(t *testing.T) {
	t.Parallel()

	rw := &responseWriter{header: http.Header{}, status: 200}
	for _, n := range []string{
		"connection", "keep-alive", "proxy-connection", "transfer-encoding",
		"upgrade", "te", ":authority", ":method", ":path", ":scheme",
	} {
		rw.header.Set(n, "x")
	}
	rw.header.Set("Connection", "close") // canonicalises to "Connection"
	rw.header.Set("Content-Type", "text/plain")

	names := responseNames(t, rw)
	for _, bad := range []string{
		"connection", "keep-alive", "proxy-connection", "transfer-encoding",
		"upgrade", "te", ":authority", ":method", ":path", ":scheme",
	} {
		if hasName(names, bad) {
			t.Errorf("encoded %q into the response; RFC 9114 §4.2/§4.3 forbid it", bad)
		}
	}
	if !hasName(names, ":status") {
		t.Error("dropped :status")
	}
	if !hasName(names, "content-type") {
		t.Error("dropped content-type, an ordinary field the handler set")
	}
}

// TestEncodeResponse_KeepsEverythingLegal is the negative control for the above.
func TestEncodeResponse_KeepsEverythingLegal(t *testing.T) {
	t.Parallel()

	legal := []string{
		"content-type", "cache-control", "etag", "location", "set-cookie",
		"vary", "x-request-id", "server", "upgraded", "x-forwarded-host",
	}
	rw := &responseWriter{header: http.Header{}, status: 200}
	for _, n := range legal {
		rw.header.Set(n, "v")
	}
	names := responseNames(t, rw)
	for _, n := range legal {
		if !hasName(names, n) {
			t.Errorf("dropped legal field %q", n)
		}
	}
}

// TestResponseWriter_InterimIsNotFinal pins the other half. Latching a 1xx put
// `:status: 101` — or 100, or 103 — on the wire as the whole response, with FIN,
// and no final response could follow. RFC 9114 §4.4 additionally leaves HTTP/3
// with no 101 at all.
func TestResponseWriter_InterimIsNotFinal(t *testing.T) {
	t.Parallel()

	for _, interim := range []int{100, 101, 103} {
		t.Run(http.StatusText(interim), func(t *testing.T) {
			t.Parallel()
			rw := &responseWriter{header: http.Header{}, status: http.StatusOK}
			rw.WriteHeader(interim)
			if rw.wroteHeader {
				t.Errorf("WriteHeader(%d) latched the response", interim)
			}
			rw.WriteHeader(http.StatusCreated)
			if rw.status != http.StatusCreated {
				t.Fatalf("status = %d, want 201", rw.status)
			}
			fields := decodeResponseFields(t, mustEncode(t, rw))
			if got := string(fields[0].Value); got != "201" {
				t.Errorf(":status = %q, want 201", got)
			}
		})
	}
}

// TestResponseWriter_WriteAfterInterimStillAnswers covers the likely handler
// shape: an early hint, then a body with no explicit status.
func TestResponseWriter_WriteAfterInterimStillAnswers(t *testing.T) {
	t.Parallel()

	rw := &responseWriter{header: http.Header{}, status: http.StatusOK}
	rw.WriteHeader(103)
	if _, err := rw.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fields := decodeResponseFields(t, mustEncode(t, rw))
	if got := string(fields[0].Value); got != "200" {
		t.Errorf(":status = %q, want the auto-sent 200", got)
	}
	if rw.body.String() != "hello" {
		t.Errorf("body = %q, want %q", rw.body.String(), "hello")
	}
}

func mustEncode(t *testing.T, rw *responseWriter) []byte {
	t.Helper()
	out, err := encodeResponse(rw, maxFieldSection)
	if err != nil {
		t.Fatalf("encodeResponse: %v", err)
	}
	return out
}
