package server

// Parallel benchmark for the native ResponseWriter write path (issue #95).
//
// This is the CONTROL for the conn/ measurements. The server-layer write path
// holds no connection-wide lock: each stream has its own responseWriter and the
// only shared state on the path is the per-second Date cache. So it is expected
// to scale close to linearly with cores, and if it does NOT, the flat lines in
// conn/bench_parallel_test.go cannot be attributed to wmu — they would be the
// machine or the harness.
//
//	go test -run='^$' -bench='Parallel' -benchmem \
//	        -benchtime=500ms -count=10 -cpu=1,2,4,8,16 ./server

import (
	"context"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// benchParDiscardWriter is a streamWriter that does nothing, so the benchmark
// measures the ResponseWriter path and not the transport. Deliberately its own
// type rather than a reuse of bench_test.go's, so the two files stay
// independent.
type benchParDiscardWriter struct{}

func (benchParDiscardWriter) sendHeaders(context.Context, []hpack.HeaderField, bool) error {
	return nil
}
func (benchParDiscardWriter) sendData(context.Context, []byte, bool) error { return nil }
func (benchParDiscardWriter) streamID() uint32                             { return 1 }

// BenchmarkResponseWriter_WriteData_Parallel gives every goroutine its own
// writer, the way a real server gives every stream its own.
func BenchmarkResponseWriter_WriteData_Parallel(b *testing.B) {
	payload := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := newResponseWriterWithSW(benchParDiscardWriter{})
		w.req = &Request{Method: http.MethodGet, Path: "/", Scheme: "https", Authority: "example.com"}
		if err := w.WriteHeaders(200, nil); err != nil {
			b.Error(err)
			return
		}
		for pb.Next() {
			if err := w.WriteData(payload); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkResponseWriter_WriteHeaders_Parallel covers the header path, which
// touches the shared per-second Date cache on every call.
func BenchmarkResponseWriter_WriteHeaders_Parallel(b *testing.B) {
	hdrs := []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("application/json")},
		{Name: []byte("content-length"), Value: []byte("1024")},
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := newResponseWriterWithSW(benchParDiscardWriter{})
			if err := w.WriteHeaders(200, hdrs); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
