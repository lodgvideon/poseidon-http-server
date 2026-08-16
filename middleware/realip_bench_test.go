package middleware

import (
	"context"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// Per-request cost of RealIP now that the server actually populates the peer
// address (issue #87). Before the fix resolveClientIP saw an empty peer and
// returned on its first branch, so this cost was zero — and so was the feature.
// The address itself is attached once per CONNECTION by server.Serve, so these
// benchmarks seed the context outside the loop to measure exactly the part that
// repeats per request: host/port split, CIDR membership, header scan.
//
// The parallel variants exist because RealIP must stay lock-free: it reads an
// immutable []*net.IPNet built once at construction plus an immutable context
// value, and writes only a new derived context. Sharing one server.Middleware
// across the goroutines is the point — if a future change puts shared mutable
// state behind it, ns/op here diverges from the serial figure.

var benchXFF = []hpack.HeaderField{
	{Name: []byte("x-forwarded-for"), Value: []byte("203.0.113.7, 10.0.0.1")},
}

// benchRealIP runs the RealIP middleware b.N times over one request.
func benchRealIP(b *testing.B, cfg RealIPConfig, peer string, headers []hpack.HeaderField) {
	b.Helper()
	mw := RealIP(cfg)
	ctx := WithPeerAddr(context.Background(), peer)
	req := &server.Request{Method: "GET", Path: "/", Headers: headers}

	var sink string
	h := mw(server.HandlerFunc(func(ctx context.Context, _ *server.Request, _ server.ResponseWriter) error {
		sink = ClientIP(ctx)
		return nil
	}))
	w := newNoopWriter()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := h.ServeHTTP(ctx, req, w); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink == "\x00" { // keep the resolved value observable
		b.Fatal("unreachable")
	}
}

// benchRealIPParallel is benchRealIP over GOMAXPROCS goroutines sharing one
// middleware instance. Each goroutine keeps its own sink and response writer so
// the benchmark measures RealIP, not a synthetic write conflict.
func benchRealIPParallel(b *testing.B, cfg RealIPConfig, peer string, headers []hpack.HeaderField) {
	b.Helper()
	mw := RealIP(cfg)
	ctx := WithPeerAddr(context.Background(), peer)
	req := &server.Request{Method: "GET", Path: "/", Headers: headers}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink string
		h := mw(server.HandlerFunc(func(ctx context.Context, _ *server.Request, _ server.ResponseWriter) error {
			sink = ClientIP(ctx)
			return nil
		}))
		w := newNoopWriter()
		for pb.Next() {
			if err := h.ServeHTTP(ctx, req, w); err != nil {
				b.Error(err)
				return
			}
		}
		if sink == "\x00" {
			b.Error("unreachable")
		}
	})
}

// BenchmarkRealIP_UntrustedPeer is the secure default: no trusted proxies, so
// forwarding headers are ignored and the peer address is used verbatim.
func BenchmarkRealIP_UntrustedPeer(b *testing.B) {
	benchRealIP(b, RealIPConfig{}, "198.51.100.23:44321", nil)
}

// BenchmarkRealIP_TrustedProxyXFF is the deployed-behind-a-proxy shape: the
// peer is inside a trusted CIDR, so X-Forwarded-For is parsed and honoured.
func BenchmarkRealIP_TrustedProxyXFF(b *testing.B) {
	benchRealIP(b, RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}, "10.0.0.1:44321", benchXFF)
}

func BenchmarkRealIP_UntrustedPeer_Parallel(b *testing.B) {
	benchRealIPParallel(b, RealIPConfig{}, "198.51.100.23:44321", nil)
}

func BenchmarkRealIP_TrustedProxyXFF_Parallel(b *testing.B) {
	benchRealIPParallel(b, RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}, "10.0.0.1:44321", benchXFF)
}
