package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// BenchmarkOnHeaders measures the inbound header-decode hot path: HPACK decode
// plus the per-request slab copy and event push. The slab previously came from a
// Get-only sync.Pool (pure overhead, never recycled); it now allocates a
// right-sized backing per request. This benchmark gates that path's cost.
func BenchmarkOnHeaders(b *testing.B) {
	mock := &mockConnOps{streams: make(map[uint32]*ServerStream)}
	h := newServerConnHandler(mock, hpack.NewDecoder(), 0)
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("example.test")},
		{Name: []byte(":path"), Value: []byte("/api/v1/resource")},
		{Name: []byte("accept"), Value: []byte("application/json")},
		{Name: []byte("user-agent"), Value: []byte("poseidon-bench/1.0")},
	})

	b.ReportAllocs()
	b.ResetTimer()
	var id uint32 = 1
	for range b.N {
		fh := frame.FrameHeader{StreamID: id, Flags: frame.FlagHeadersEndHeaders | frame.FlagHeadersEndStream}
		if err := h.OnHeaders(fh, block, nil, 0); err != nil {
			b.Fatal(err)
		}
		mock.markStreamDone(id) // keep the streams map small across iterations
		id += 2
	}
}
