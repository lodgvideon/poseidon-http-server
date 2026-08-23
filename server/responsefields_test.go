package server

import (
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// What a response field section may not carry (#212 group C).
//
// Both write paths built the field section straight out of what the handler
// supplied and validated none of it, so a handler could put connection-specific
// fields or an arbitrary pseudo-header on the wire. The HTTP/3 door had the same
// hole in encodeResponse; the rule now lives in internal/httpfields and both
// call it (ADR-0010).
//
// The pseudo-header half is the one with teeth. http.Header canonicalisation
// leaves a name containing ':' untouched, so w.Header().Set(":authority", …)
// reached the wire verbatim — a handler building a header name out of user input
// could be made to inject a pseudo-header into the response.
// ---------------------------------------------------------------------------

// sentNames returns the field names of the nth HEADERS frame the mock recorded.
func sentNames(t *testing.T, sw *mockStreamWriter, n int) []string {
	t.Helper()
	if len(sw.headersSent) <= n {
		t.Fatalf("only %d HEADERS frames sent, wanted at least %d", len(sw.headersSent), n+1)
	}
	out := make([]string, 0, len(sw.headersSent[n]))
	for _, f := range sw.headersSent[n] {
		out = append(out, string(f.Name))
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// forbidden is the set neither write path may emit.
var forbidden = []string{
	"connection", "keep-alive", "proxy-connection", "transfer-encoding",
	"upgrade", "te", ":authority", ":method", ":path", ":scheme", ":protocol",
}

func TestWriteHeader_DropsForbiddenResponseFields(t *testing.T) {
	w, sw := newTestWriter()
	for _, name := range forbidden {
		w.Header().Set(name, "x")
	}
	// Mixed case, since http.Header canonicalises ordinary names but not the
	// pseudo-header ones.
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	got := sentNames(t, sw, 0)
	for _, bad := range forbidden {
		if contains(got, bad) {
			t.Errorf("emitted %q on the stdlib path; RFC 9113 §8.2.2/§8.3 forbid it in a response", bad)
		}
	}
	if !contains(got, ":status") {
		t.Error("dropped :status, which is the one pseudo-header a response may carry")
	}
	if !contains(got, "content-type") {
		t.Error("dropped content-type, an ordinary field the handler set")
	}
}

func TestWriteHeaders_DropsForbiddenResponseFields(t *testing.T) {
	w, sw := newTestWriter()
	fields := make([]hpack.HeaderField, 0, len(forbidden)+3)
	for _, name := range forbidden {
		fields = append(fields, hpack.HeaderField{Name: []byte(name), Value: []byte("x")})
	}
	// The native path takes names verbatim, so a caller can pass any case.
	fields = append(fields,
		hpack.HeaderField{Name: []byte("Connection"), Value: []byte("close")},
		hpack.HeaderField{Name: []byte("TRANSFER-ENCODING"), Value: []byte("chunked")},
		hpack.HeaderField{Name: []byte("content-type"), Value: []byte("text/plain")},
	)
	if err := w.WriteHeaders(200, fields); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	got := sentNames(t, sw, 0)
	for _, bad := range append(append([]string{}, forbidden...), "Connection", "TRANSFER-ENCODING") {
		if contains(got, bad) {
			t.Errorf("emitted %q on the native path", bad)
		}
	}
	if !contains(got, ":status") || !contains(got, "content-type") {
		t.Errorf("dropped a legal field; sent %v", got)
	}
}

// TestWriteHeaders_KeepsEverythingLegal is the negative control: without it,
// "drop every field" would pass the two tables above.
func TestWriteHeaders_KeepsEverythingLegal(t *testing.T) {
	w, sw := newTestWriter()
	legal := []string{
		"content-type", "content-length", "cache-control", "etag", "location",
		"set-cookie", "vary", "x-request-id", "server", "content-encoding",
		"upgraded", "connexion0", "x-forwarded-host", "x-transfer-encode", "tea",
	}
	fields := make([]hpack.HeaderField, 0, len(legal))
	for _, n := range legal {
		fields = append(fields, hpack.HeaderField{Name: []byte(n), Value: []byte("v")})
	}
	if err := w.WriteHeaders(200, fields); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	got := sentNames(t, sw, 0)
	for _, n := range legal {
		if !contains(got, n) {
			t.Errorf("dropped legal field %q", n)
		}
	}
}

// ---------------------------------------------------------------------------
// A 1xx is not a final status (RFC 9113 §8.1)
// ---------------------------------------------------------------------------

// TestWriteHeader_InterimIsNotFinal pins the fix for the half of #212 group C
// that broke the exchange outright: the first status latched, so a handler
// calling WriteHeader(103) ended the response there and the real status was
// ignored. A response is "zero or more interim responses followed by a single
// final response" — zero is allowed, an interim standing in for the final is not.
func TestWriteHeader_InterimIsNotFinal(t *testing.T) {
	for _, interim := range []int{100, 101, 102, 103} {
		t.Run(http.StatusText(interim), func(t *testing.T) {
			w, sw := newTestWriter()
			w.WriteHeader(interim)
			if w.Written() {
				t.Errorf("WriteHeader(%d) latched the response", interim)
			}
			if w.Status() == interim {
				t.Errorf("Status() = %d: an interim status became the final one", interim)
			}
			w.WriteHeader(http.StatusOK)
			if w.Status() != http.StatusOK {
				t.Errorf("Status() = %d after WriteHeader(200), want 200", w.Status())
			}
			if len(sw.headersSent) != 1 {
				t.Fatalf("%d HEADERS frames sent, want exactly 1 (the final response)", len(sw.headersSent))
			}
			if got := string(sw.headersSent[0][0].Value); got != "200" {
				t.Errorf(":status = %q, want 200", got)
			}
		})
	}
}

// TestWriteHeaders_InterimIsNotFinal is the same rule on the native path.
func TestWriteHeaders_InterimIsNotFinal(t *testing.T) {
	w, sw := newTestWriter()
	if err := w.WriteHeaders(103, []hpack.HeaderField{
		{Name: []byte("link"), Value: []byte("</s.css>; rel=preload")},
	}); err != nil {
		t.Fatalf("WriteHeaders(103): %v", err)
	}
	if w.Written() {
		t.Fatal("WriteHeaders(103) latched the response")
	}
	if err := w.WriteHeaders(201, nil); err != nil {
		t.Fatalf("WriteHeaders(201): %v", err)
	}
	if w.Status() != 201 {
		t.Errorf("Status() = %d, want 201", w.Status())
	}
	if len(sw.headersSent) != 1 {
		t.Fatalf("%d HEADERS frames sent, want exactly 1", len(sw.headersSent))
	}
}

// TestWriteData_AfterInterimStillAutoSends200 covers the path a handler most
// likely takes: an early hint, then a body with no explicit status. The interim
// must not have consumed the response.
func TestWriteData_AfterInterimStillAutoSends200(t *testing.T) {
	w, sw := newTestWriter()
	w.WriteHeader(103)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if w.Status() != http.StatusOK {
		t.Errorf("Status() = %d, want the auto-sent 200", w.Status())
	}
	if len(sw.headersSent) != 1 {
		t.Fatalf("%d HEADERS frames sent, want 1", len(sw.headersSent))
	}
	if got := string(sw.headersSent[0][0].Value); got != "200" {
		t.Errorf(":status = %q, want 200", got)
	}
}
