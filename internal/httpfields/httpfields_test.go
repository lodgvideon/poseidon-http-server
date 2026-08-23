package httpfields

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

func f(n, v string) hpack.HeaderField {
	return hpack.HeaderField{Name: []byte(n), Value: []byte(v)}
}

// validRequest is the minimal conformant request field section.
func validRequest(extra ...hpack.HeaderField) []hpack.HeaderField {
	out := []hpack.HeaderField{
		f(":method", "GET"),
		f(":scheme", "https"),
		f(":authority", "example.com"),
		f(":path", "/"),
	}
	return append(out, extra...)
}

// ---------------------------------------------------------------------------
// Prohibited — the per-field rules
// ---------------------------------------------------------------------------

func TestProhibited(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		fname     string
		fvalue    string
		isTrailer bool
		want      bool
	}{
		// Field-name character rules (RFC 9113 §8.2.1, RFC 9114 §4.2).
		{"lowercase name", "x-a", "1", false, false},
		{"empty name", "", "1", false, true},
		{"uppercase name", "X-a", "1", false, true},
		{"uppercase at the end", "x-A", "1", false, true},
		{"SP in name", "x a", "1", false, true},
		{"HTAB in name", "x\ta", "1", false, true},
		{"NUL in name", "x\x00a", "1", false, true},
		{"DEL in name", "x\x7f", "1", false, true},
		{"high octet in name", "x\xff", "1", false, true},
		{"interior colon", "x:a", "1", false, true},
		{"trailing colon", "xa:", "1", false, true},
		{"leading colon is a pseudo-header, not an error", ":method", "GET", false, false},
		{"only a colon", ":", "v", false, false},

		// Field-value character rules (RFC 9110 §5.5).
		{"empty value", "x-a", "", false, false},
		{"CR", "x-a", "a\rb", false, true},
		{"LF", "x-a", "a\nb", false, true},
		{"CRLF", "x-a", "a\r\nb", false, true},
		{"NUL", "x-a", "a\x00b", false, true},
		{"CR at the start", "x-a", "\rab", false, true},
		{"LF at the end", "x-a", "ab\n", false, true},
		{"leading SP", "x-a", " a", false, true},
		{"trailing SP", "x-a", "a ", false, true},
		{"leading HTAB", "x-a", "\ta", false, true},
		{"trailing HTAB", "x-a", "a\t", false, true},
		{"a single SP", "x-a", " ", false, true},
		{"interior HTAB stays legal", "x-a", "a\tb", false, false},
		{"interior SP stays legal", "x-a", "a b", false, false},
		{"obs-text stays legal", "x-a", "caf\xc3\xa9", false, false},

		// Connection-specific fields (RFC 9113 §8.2.2, RFC 9114 §4.2).
		{"connection", "connection", "keep-alive", false, true},
		{"keep-alive", "keep-alive", "timeout=5", false, true},
		{"proxy-connection", "proxy-connection", "keep-alive", false, true},
		{"transfer-encoding", "transfer-encoding", "chunked", false, true},
		{"upgrade", "upgrade", "h2c", false, true},
		// Same length as a banned name, but not one of them — the length-first
		// switch must not over-match.
		{"connexion (10 octets, not banned)", "connexion0", "x", false, false},
		{"upgraded (8 octets)", "upgraded", "x", false, false},
		{"x-forwarded-host (16 octets, not banned)", "x-forwarded-host", "x", false, false},
		{"x-transfer-encode (17 octets, not banned)", "x-transfer-encode", "x", false, false},

		// TE (RFC 9113 §8.2.2, RFC 9114 §4.2).
		{"te: trailers", "te", "trailers", false, false},
		{"te: TRAILERS is case-insensitive", "te", "TRAILERS", false, false},
		{"te: Trailers", "te", "Trailers", false, false},
		{"te: gzip", "te", "gzip", false, true},
		{"te: trailers, gzip", "te", "trailers, gzip", false, true},
		{"te empty", "te", "", false, true},

		// Trailer sections (RFC 9113 §8.1).
		{"pseudo-header in a trailer", ":method", "GET", true, true},
		{"regular field in a trailer", "x-a", "1", true, false},
		{"connection-specific in a trailer", "connection", "x", true, true},
		{"bad value in a trailer", "x-a", "a\rb", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Prohibited([]byte(tc.fname), []byte(tc.fvalue), tc.isTrailer)
			if got != tc.want {
				t.Errorf("Prohibited(%q, %q, isTrailer=%v) = %v, want %v",
					tc.fname, tc.fvalue, tc.isTrailer, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidRequestPseudoHeaders — the section rules
// ---------------------------------------------------------------------------

func TestValidRequestPseudoHeaders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		fields []hpack.HeaderField
		want   bool
	}{
		{"the minimal section", validRequest(), true},
		{"with regular fields after", validRequest(f("x-a", "1"), f("x-b", "2")), true},
		{"no :authority", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "https"), f(":path", "/"),
		}, true},

		// §8.3 — presence.
		{"no :method", []hpack.HeaderField{
			f(":scheme", "https"), f(":path", "/"),
		}, false},
		{"no :scheme", []hpack.HeaderField{
			f(":method", "GET"), f(":path", "/"),
		}, false},
		{"no :path", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "https"),
		}, false},
		{"empty field list", nil, false},

		// §8.3 — uniqueness.
		{"duplicate :method", validRequest(f(":method", "POST")), false},
		{"duplicate :scheme", validRequest(f(":scheme", "http")), false},
		{"duplicate :path", validRequest(f(":path", "/x")), false},
		{"duplicate :authority", validRequest(f(":authority", "other")), false},

		// §8.3 — ordering.
		{"pseudo-header after a regular field", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "https"),
			f("x-a", "1"),
			f(":path", "/"),
		}, false},

		// §8.3 — undefined names.
		{"undefined pseudo-header", validRequest(f(":protocol", "websocket")), false},
		{"a response pseudo-header on a request", validRequest(f(":status", "200")), false},
		{"empty field name", validRequest(f("", "v")), false},

		// §8.3.1 — :authority userinfo.
		{"userinfo in :authority", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "https"),
			f(":authority", "user@example.com"), f(":path", "/"),
		}, false},
		{"userinfo with a password", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "http"),
			f(":authority", "u:p@example.com"), f(":path", "/"),
		}, false},
		{"an @ under a non-http scheme is out of scope", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "ftp"),
			f(":authority", "user@example.com"), f(":path", "/"),
		}, true},

		// §8.3.1 — case-insensitivity of the scheme must not be an escape hatch.
		{"HTTPS uppercase still bans userinfo", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "HTTPS"),
			f(":authority", "user@example.com"), f(":path", "/"),
		}, false},
		{"HTTPS uppercase still bans an empty path", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "HtTpS"),
			f(":authority", "example.com"), f(":path", ""),
		}, false},

		// §8.3.1 — :path emptiness.
		{"empty :path under https", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "https"),
			f(":authority", "example.com"), f(":path", ""),
		}, false},
		{"empty :path under a non-http scheme is permitted", []hpack.HeaderField{
			f(":method", "GET"), f(":scheme", "ftp"),
			f(":authority", "example.com"), f(":path", ""),
		}, true},

		// §8.5 — CONNECT omits :scheme and :path.
		{"CONNECT without :scheme or :path", []hpack.HeaderField{
			f(":method", "CONNECT"), f(":authority", "example.com:443"),
		}, true},
		{"connect lowercase is a different method (§9.1)", []hpack.HeaderField{
			f(":method", "connect"), f(":authority", "example.com:443"),
		}, false},
		{"CONNECT still needs a unique :method", []hpack.HeaderField{
			f(":method", "CONNECT"), f(":method", "CONNECT"),
			f(":authority", "example.com:443"),
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidRequestPseudoHeaders(tc.fields); got != tc.want {
				t.Errorf("ValidRequestPseudoHeaders = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The allocation contract (ADR-0001)
// ---------------------------------------------------------------------------

// TestProhibited_NoAllocations pins the reason these comparisons are written the
// way they are. Prohibited runs once per decoded field inside the HTTP/2 decode
// callback, so a single allocation here is one per header on every request.
// string(b) == "lit" is the comparison the compiler does not allocate for;
// rewriting the length-first switch as a map lookup or a strings.ToLower would
// fail this.
func TestProhibited_NoAllocations(t *testing.T) {
	names := [][]byte{
		[]byte("x-request-id"), []byte("te"), []byte("connection"),
		[]byte("transfer-encoding"), []byte(":method"), []byte("user-agent"),
	}
	values := [][]byte{
		[]byte("abc123"), []byte("trailers"), []byte("keep-alive"),
		[]byte("chunked"), []byte("GET"), []byte("curl/8.0"),
	}
	got := testing.AllocsPerRun(200, func() {
		for i := range names {
			_ = Prohibited(names[i], values[i], false)
		}
	})
	if got != 0 {
		t.Errorf("Prohibited allocated %v times per run, want 0 (ADR-0001)", got)
	}
}

// TestValidRequestPseudoHeaders_NoAllocations pins the same contract on the
// section scan, which runs once per request field block.
func TestValidRequestPseudoHeaders_NoAllocations(t *testing.T) {
	fields := validRequest(f("user-agent", "curl/8.0"), f("accept", "*/*"))
	got := testing.AllocsPerRun(200, func() {
		_ = ValidRequestPseudoHeaders(fields)
	})
	if got != 0 {
		t.Errorf("ValidRequestPseudoHeaders allocated %v times per run, want 0 (ADR-0001)", got)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — the numbers bench-gate watches
// ---------------------------------------------------------------------------

func BenchmarkProhibited(b *testing.B) {
	name, value := []byte("x-request-id"), []byte("0123456789abcdef")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = Prohibited(name, value, false)
	}
}

func BenchmarkValidRequestPseudoHeaders(b *testing.B) {
	fields := validRequest(f("user-agent", "curl/8.0"), f("accept", "*/*"))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = ValidRequestPseudoHeaders(fields)
	}
}
