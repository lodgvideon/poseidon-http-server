package middleware

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for Content-Encoding on the gzip middleware.
//
// RFC 9110 §8.4:
//
//	"If one or more encodings have been applied to a representation, the sender
//	 that applied the encodings MUST generate a Content-Encoding header field
//	 that lists the content codings in the order in which they were applied."
//
// The stdlib flush path called Set("Content-Encoding", "gzip"), replacing
// whatever the handler had already declared. A handler that served an
// already-encoded representation therefore announced only "gzip" for a body
// that had two codings applied — a decoder following the field would recover
// the intermediate bytes, not the representation.
//
// The middleware now declines to compress a representation that already carries
// a content coding. That satisfies the rule on both paths at once and avoids
// double compression, which costs CPU and usually grows the body.

func countField(fields []hpack.HeaderField, name string) (string, int) {
	value, count := "", 0
	for _, f := range fields {
		if string(f.Name) == name {
			value = string(f.Value)
			count++
		}
	}
	return value, count
}

// TestConformance_RFC9110_Sec84_NativePreEncodedNotRecompressed pins
// RFC 9110 §8.4 on the native write path.
func TestConformance_RFC9110_Sec84_NativePreEncodedNotRecompressed(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	_ = gw.WriteHeaders(200, []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("text/plain")},
		{Name: []byte("content-encoding"), Value: []byte("br")},
	})
	_ = gw.WriteData(gzipBigBody)
	if err := gw.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	value, count := countField(under.nativeHeaders, "content-encoding")
	if count != 1 {
		t.Fatalf("content-encoding appeared %d times, want 1", count)
	}
	if value != "br" {
		t.Errorf("content-encoding = %q, want the handler's %q", value, "br")
	}
	if len(under.data) != 1 || len(under.data[0]) != len(gzipBigBody) {
		t.Errorf("body was re-compressed on top of an existing coding: %d bytes, want %d",
			len(under.data[0]), len(gzipBigBody))
	}
}

// TestConformance_RFC9110_Sec84_HTTPPreEncodedNotRecompressed is the same on
// the stdlib path, which is where the field was actually being overwritten.
func TestConformance_RFC9110_Sec84_HTTPPreEncodedNotRecompressed(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	gw.Header().Set("Content-Type", "text/plain")
	gw.Header().Set("Content-Encoding", "br")
	gw.WriteHeader(200)
	_, _ = gw.Write(gzipBigBody)
	if err := gw.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if got := under.header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want the handler's %q — Set() replaced it", got, "br")
	}
	if len(under.data) != 1 || len(under.data[0]) != len(gzipBigBody) {
		t.Errorf("body was re-compressed on top of an existing coding: %d bytes, want %d",
			len(under.data[0]), len(gzipBigBody))
	}
}

// TestConformance_RFC9110_Sec84_UnencodedStillCompressed is the control: the
// ordinary case must be unaffected, or the fix above would just be a way of
// turning the middleware off.
func TestConformance_RFC9110_Sec84_UnencodedStillCompressed(t *testing.T) {
	t.Parallel()

	t.Run("native", func(t *testing.T) {
		under := newFakeRW()
		gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}
		_ = gw.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("text/plain")},
		})
		_ = gw.WriteData(gzipBigBody)
		if err := gw.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		value, count := countField(under.nativeHeaders, "content-encoding")
		if count != 1 || value != "gzip" {
			t.Errorf("content-encoding = %q (count %d), want \"gzip\" once", value, count)
		}
		if len(under.data[0]) >= len(gzipBigBody) {
			t.Error("body was not compressed")
		}
	})

	t.Run("stdlib", func(t *testing.T) {
		under := newFakeRW()
		gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}
		gw.Header().Set("Content-Type", "text/plain")
		gw.WriteHeader(200)
		_, _ = gw.Write(gzipBigBody)
		if err := gw.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if got := under.header.Get("Content-Encoding"); got != "gzip" {
			t.Errorf("Content-Encoding = %q, want gzip", got)
		}
		if len(under.data[0]) >= len(gzipBigBody) {
			t.Error("body was not compressed")
		}
	})
}

// TestConformance_RFC9110_Sec86_HeadContentLengthNotStale pins RFC 9110 §8.6
//
//	"A server MAY send a Content-Length header field in a response to a HEAD
//	 request (Section 9.3.2); a server MUST NOT send Content-Length in such a
//	 response unless its field value equals the decimal number of octets that
//	 would have been sent in the content of a response if the same request had
//	 used the GET method."
//
// A HEAD-aware handler writes no body, so this wrapper has nothing to measure
// and cannot compress. The handler's own Content-Length therefore survives —
// but it describes the UNCOMPRESSED representation, while the same request as a
// GET would have been gzipped to a different octet count. Passing it through is
// the MUST NOT.
//
// Dropping it is what §9.3.2 expressly allows: "a server MAY
// omit header fields for which a value is determined only while generating the
// content", with buffering-for-a-late-content-decision given as the example.
// The missing Content-Encoding on the HEAD response is permitted by that same
// sentence and is deliberately not "fixed".
func TestConformance_RFC9110_Sec86_HeadContentLengthNotStale(t *testing.T) {
	t.Parallel()

	t.Run("native", func(t *testing.T) {
		under := newFakeRW()
		gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig(), head: true}
		_ = gw.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("text/plain")},
			{Name: []byte("content-length"), Value: []byte("5000")},
		})
		if err := gw.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if v, n := countField(under.nativeHeaders, "content-length"); n != 0 {
			t.Errorf("content-length = %q on a HEAD response; the value describes the "+
				"uncompressed body, not what a GET would have sent", v)
		}
		if v, n := countField(under.nativeHeaders, "content-type"); n != 1 || v != "text/plain" {
			t.Errorf("content-type = %q (count %d); only the length is unverifiable", v, n)
		}
	})

	t.Run("stdlib", func(t *testing.T) {
		under := newFakeRW()
		gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig(), head: true}
		gw.Header().Set("Content-Type", "text/plain")
		gw.Header().Set("Content-Length", "5000")
		gw.WriteHeader(200)
		if err := gw.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if got := under.header.Get("Content-Length"); got != "" {
			t.Errorf("Content-Length = %q on a HEAD response, want it dropped", got)
		}
		if got := under.header.Get("Content-Type"); got != "text/plain" {
			t.Errorf("Content-Type = %q, want it preserved", got)
		}
	})

	t.Run("GET keeps its content-length", func(t *testing.T) {
		under := newFakeRW()
		gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}
		_ = gw.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("content-length"), Value: []byte("5")},
		})
		_ = gw.WriteData([]byte("small"))
		if err := gw.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if v, n := countField(under.nativeHeaders, "content-length"); n != 1 || v != "5" {
			t.Errorf("content-length = %q (count %d) on a small GET; want it untouched", v, n)
		}
	})
}

// TestConformance_RFC9110_Sec561_ListGrammar pins the recipient half of the
// list construct, which containsToken implements by hand.
//
//	RFC 9110 §5.6.3 — "OWS = *( SP / HTAB )"
//	RFC 9110 §5.6.1.2 — "A recipient MUST parse and ignore a reasonable number of
//	 empty list elements ... a recipient MUST accept lists that satisfy the
//	 following syntax:  #element => [ element ] *( OWS "," OWS [ element ] )"
//
// The scanner treated only SP as whitespace, so a value separated with HTAB —
// legal OWS — hid the token and silently disabled compression.
func TestConformance_RFC9110_Sec561_ListGrammar(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		val   string
		token string
		want  bool
		why   string
	}{
		{"deflate,\tgzip", "gzip", true, "HTAB is OWS (RFC 9110 §5.6.3)"},
		{"deflate,\t gzip", "gzip", true, "OWS is any run of SP and HTAB"},
		{"gzip\t;q=1.0", "gzip", true, "HTAB before a parameter still ends the token"},
		{",,gzip", "gzip", true, "leading empty elements are ignored (RFC 9110 §5.6.1.2)"},
		{"gzip,,", "gzip", true, "trailing empty elements are ignored"},
		{"deflate,,gzip", "gzip", true, "interior empty elements are ignored"},
		{"\t,\tgzip\t", "gzip", true, "OWS around empty elements and the token"},
		// The other direction: an empty list, and a token that only appears as a
		// substring, must not match.
		{",", "gzip", false, "an empty list contains no element"},
		{",,,", "gzip", false, "only empty elements"},
		{"", "gzip", false, "no value at all"},
		{"gzipper", "gzip", false, "a longer token is not a match"},
		{"x-gzip", "gzip", false, "a different token; see 91108-26 for the SHOULD on x-gzip"},
	} {
		t.Run(tc.val+"/"+tc.token, func(t *testing.T) {
			if got := containsToken(tc.val, tc.token); got != tc.want {
				t.Errorf("containsToken(%q, %q) = %v, want %v — %s", tc.val, tc.token, got, tc.want, tc.why)
			}
		})
	}
}
