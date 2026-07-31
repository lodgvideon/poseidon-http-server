package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Benchmarks for the native ResponseWriter write path.
//
// ADR-0001 scopes the zero-allocation contract to WriteHeaders / WriteData /
// WriteTrailers, but the server package had no benchmark at all, so nothing
// guarded that end of it — the alloc-counting benchmarks live in conn/ and
// measure the layer below. These exist so the HEAD content-suppression check
// added for RFC 9110 §9.3.2, and anything else that lands on this path later,
// has to prove it stays allocation-free.

// benchDiscardWriter is a streamWriter that does nothing, so a benchmark
// measures the ResponseWriter path and not the transport.
type benchDiscardWriter struct{}

func (benchDiscardWriter) sendHeaders(context.Context, []hpack.HeaderField, bool) error { return nil }
func (benchDiscardWriter) sendData(context.Context, []byte, bool) error                 { return nil }
func (benchDiscardWriter) streamID() uint32                                             { return 1 }

func benchWriter(method string) *responseWriter {
	w := newResponseWriterWithSW(benchDiscardWriter{})
	w.req = &Request{Method: method, Path: "/", Scheme: "https", Authority: "example.com"}
	_ = w.WriteHeaders(200, nil)
	return w
}

// BenchmarkResponseWriter_WriteData_GET is the ordinary content path.
func BenchmarkResponseWriter_WriteData_GET(b *testing.B) {
	w := benchWriter(http.MethodGet)
	payload := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = w.WriteData(payload)
	}
}

// BenchmarkResponseWriter_WriteData_HEAD covers the suppressed path: it must
// stay allocation-free too, and must not become the slower branch.
func BenchmarkResponseWriter_WriteData_HEAD(b *testing.B) {
	w := benchWriter(http.MethodHead)
	payload := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = w.WriteData(payload)
	}
}
