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
// ProhibitedInResponse — the sender-side rule
// ---------------------------------------------------------------------------

func TestProhibitedInResponse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		fname string
		want  bool
	}{
		// Ordinary response fields.
		{"content-type", "content-type", false},
		{"date", "date", false},
		{"set-cookie", "set-cookie", false},
		{"server", "server", false},
		{"empty name", "", true},

		// The one pseudo-header a response may carry.
		{":status", ":status", false},
		// Pseudo-headers are case-sensitive, so this is not :status.
		{":STATUS", ":STATUS", true},
		{":authority", ":authority", true},
		{":method", ":method", true},
		{":path", ":path", true},
		{":scheme", ":scheme", true},
		{"an invented pseudo-header", ":x-anything", true},
		{"a bare colon", ":", true},

		// Connection-specific (RFC 9113 §8.2.2, RFC 9114 §4.2).
		{"connection", "connection", true},
		{"keep-alive", "keep-alive", true},
		{"proxy-connection", "proxy-connection", true},
		{"transfer-encoding", "transfer-encoding", true},
		{"upgrade", "upgrade", true},

		// The native write path takes names from the caller, so the check cannot
		// assume they were lowercased.
		{"Connection", "Connection", true},
		{"TRANSFER-ENCODING", "TRANSFER-ENCODING", true},
		{"Keep-Alive", "Keep-Alive", true},
		{"Upgrade", "Upgrade", true},
		{"Proxy-Connection", "Proxy-Connection", true},

		// TE is a request-only field: §4.2 permits it "in an HTTP/3 request
		// header", and a response is not a request, so no value rescues it.
		{"te", "te", true},
		{"TE", "TE", true},
		{"tE", "tE", true},

		// Length-first matching must not over-match neighbours.
		{"upgraded (8)", "upgraded", false},
		{"connexion0 (10)", "connexion0", false},
		{"x-forwarded-host (16)", "x-forwarded-host", false},
		{"x-transfer-encode (17)", "x-transfer-encode", false},
		{"te-like but longer", "tea", false},
		{"single t", "t", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ProhibitedInResponse([]byte(tc.fname)); got != tc.want {
				t.Errorf("ProhibitedInResponse(%q) = %v, want %v", tc.fname, got, tc.want)
			}
		})
	}
}

func TestInterimStatus(t *testing.T) {
	t.Parallel()

	interim := []int{100, 101, 102, 103, 150, 199}
	final := []int{0, 99, 200, 201, 204, 301, 400, 404, 500, 503, 599, 600}

	for _, s := range interim {
		if !InterimStatus(s) {
			t.Errorf("InterimStatus(%d) = false, want true", s)
		}
	}
	for _, s := range final {
		if InterimStatus(s) {
			t.Errorf("InterimStatus(%d) = true, want false", s)
		}
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

// TestProhibitedInResponse_NoAllocations holds the sender-side check to the same
// contract as the receiver-side one: it runs once per response field, so an
// allocation here is one per header on every response. EqualFold is used instead
// of a plain compare because the native path's names may be any case — it does
// not allocate, and rewriting it as strings.ToLower would.
func TestProhibitedInResponse_NoAllocations(t *testing.T) {
	names := [][]byte{
		[]byte("content-type"), []byte("date"), []byte(":status"),
		[]byte("connection"), []byte("Transfer-Encoding"), []byte("te"),
		[]byte("x-request-id"),
	}
	got := testing.AllocsPerRun(200, func() {
		for i := range names {
			_ = ProhibitedInResponse(names[i])
		}
	})
	if got != 0 {
		t.Errorf("ProhibitedInResponse allocated %v times per run, want 0 (ADR-0001)", got)
	}
}

func BenchmarkProhibitedInResponse(b *testing.B) {
	name := []byte("content-type")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = ProhibitedInResponse(name)
	}
}

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
