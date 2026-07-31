package middleware

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for Content-Encoding on the gzip middleware.
//
// RFC 9110 §8.4 (rfc9110.txt:3059):
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
// rfc9110.txt:3059 on the native write path.
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
