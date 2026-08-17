package conn

// Accept-path benchmarks (issue #134).
//
// BenchmarkOnHeaders (conn/bench_headers_test.go) reads like it covers stream
// admission and does not: its handler is bound to mockConnOps, whose
// registerStream is a map insert (conn/server_handler_test.go). Everything the
// real accept path does is therefore absent from that number —
// streamTable.admitClient under the table's own lock, the per-stream
// context.WithCancel(sc.connCtx), the non-blocking acceptCh send and its
// REFUSED_STREAM branch, and the StreamsAccepted increment at delivery.
//
// The benchmarks below are the same entry points bound to a REAL *ServerConn, so
// the gap between them and BenchmarkOnHeaders is exactly what the mock hides.
// Both are worth keeping: the mock one isolates HPACK decode plus pseudo-header
// parsing, this file measures the per-request cost the server actually pays.
//
// Why the sequential and the parallel benchmark do not call the same function.
// BenchmarkAcceptStreamServerConn goes through serverConnHandler.OnHeaders,
// which is the whole path; the parallel pair calls ServerConn.registerStream
// directly. That is not a shortcut, it is forced: OnHeaders runs
// validateClientStreamID, and RFC 9113 §5.1.1 requires each new client stream
// identifier to be numerically greater than every previous one
// (conn/stream_table.go:109). That invariant is a single-goroutine one — two
// goroutines drawing identifiers cannot guarantee the one that reaches the check
// first holds the larger value — so OnHeaders cannot be driven concurrently on
// one connection at all, by construction. In production it never is: admission
// runs on the single frame-reader goroutine. registerStream itself imposes no
// ordering, so the parallel pair below measures the connection-wide state the
// accept path touches, which is what issue #95 asks about, without pretending
// the server admits from many goroutines.

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// benchAcceptFields is the request field section the accept benchmarks decode.
// It matches BenchmarkOnHeaders' fixture field for field, so the two numbers are
// comparable and their difference is attributable to the connection rather than
// to a different header set.
var benchAcceptFields = []hpack.HeaderField{
	{Name: []byte(":method"), Value: []byte("GET")},
	{Name: []byte(":scheme"), Value: []byte("https")},
	{Name: []byte(":authority"), Value: []byte("example.test")},
	{Name: []byte(":path"), Value: []byte("/api/v1/resource")},
	{Name: []byte("accept"), Value: []byte("application/json")},
	{Name: []byte("user-agent"), Value: []byte("poseidon-bench/1.0")},
}

// benchAcceptConn builds a real *ServerConn over bench_parallel_test.go's
// scripted transport with no streams open, plus a handler bound to it.
//
// The handler is a private one carrying its OWN hpack.Decoder rather than
// sc.handler: the connection's handler and decoder belong to its reader
// goroutine, which is parked in benchScriptConn.Read for the life of the
// benchmark but is still their owner. Constructing a second one keeps the
// benchmark off state it does not own, which is what lets this file run clean
// under -race.
func benchAcceptConn(b *testing.B) (*ServerConn, *serverConnHandler) {
	b.Helper()
	sc, _, _ := benchParConn(b, 0)
	return sc, newServerConnHandler(sc, hpack.NewDecoder(), 0, 0, 0)
}

// BenchmarkAcceptStreamServerConn measures one complete stream admission against
// a real connection: HPACK decode, pseudo-header parse, streamTable.admitClient
// (table lock, peer window, MaxConcurrentStreams), context.WithCancel per
// stream, the acceptCh handoff, AcceptStream's delivery and StreamsAccepted, and
// the markStreamDone that releases the table slot.
//
// It allocates, and that is the point rather than a defect: ADR-0001's
// zero-allocation contract is scoped to the native WRITE path, and the accept
// path deliberately allocates a *ServerStream, its event channel and a cancel
// context per request. What was missing was any number at all — `make
// bench-gate` gates allocs/op exactly (BENCH_ALLOC_THRESHOLD=0), so with this
// benchmark recorded a change that adds a per-stream allocation is a gate
// failure instead of an invisible drift.
func BenchmarkAcceptStreamServerConn(b *testing.B) {
	sc, h := benchAcceptConn(b)
	block := hpack.NewEncoder().EncodeBlock(nil, benchAcceptFields)
	ctx := context.Background()

	// Identifiers must strictly increase (§5.1.1), so this loop consumes the odd
	// identifier space at two per iteration and is bounded by it. Said out loud
	// rather than left to wrap: past the bound OnHeaders would start returning
	// PROTOCOL_ERROR and the benchmark would fail rather than mis-measure, but the
	// failure would look like a server defect. At ~1us/op the bound is ~35 minutes
	// of -benchtime, far beyond bench-gate's 2s.
	if uint64(b.N) > uint64(1<<31-1) {
		b.Fatalf("b.N=%d exceeds the odd stream-identifier space (RFC 9113 §5.1.1)", b.N)
	}

	b.ReportAllocs()
	b.ResetTimer()
	var id uint32 = 1
	for range b.N {
		fh := frame.FrameHeader{
			StreamID: id,
			Flags:    frame.FlagHeadersEndHeaders | frame.FlagHeadersEndStream,
		}
		if err := h.OnHeaders(fh, block, nil, 0); err != nil {
			b.Fatal(err)
		}
		// Draining is not bookkeeping — it is half the path. AcceptStream is what
		// increments StreamsAccepted, and without it the 512-deep queue fills and
		// every later iteration measures the REFUSED_STREAM branch instead.
		ss, err := sc.AcceptStream(ctx)
		if err != nil {
			b.Fatal(err)
		}
		sc.markStreamDone(ss.id)
		id += 2
	}
	b.StopTimer()

	// Proof the measured work was the real path and not a short-circuit: every
	// iteration must have reached delivery. StreamsAccepted is incremented in
	// ServerConn.deliver, which only AcceptStream reaches.
	if got := sc.Stats().StreamsAccepted; got != uint32(b.N) { //nolint:gosec // G115: bounded by the §5.1.1 guard above
		b.Fatalf("accept path not reached: StreamsAccepted=%d for %d iterations", got, b.N)
	}
}

// benchAcceptRegisterLoop is the body both parallel benchmarks run, so that the
// shared-connection measurement and its control differ in exactly one thing: the
// connection. Returns the number of streams it admitted.
//
// The blocking receive from acceptCh cannot deadlock even though goroutines may
// take one another's streams. Each goroutine strictly alternates send (inside
// registerStream) and receive, so at any instant the number of goroutines
// waiting to receive equals the number of streams still queued — every waiter
// has an item. The queue therefore never holds more than one stream per
// goroutine either, which is why no iteration can hit the REFUSED_STREAM branch
// against benchParConn's MaxConcurrentStreams of 512.
func benchAcceptRegisterLoop(b *testing.B, pb *testing.PB, sc *ServerConn, first, stride uint32) int64 {
	b.Helper()
	var admitted int64
	id := first
	for pb.Next() {
		s := newServerStream(id, defaultStreamEventBuffer, nil, connInitialRecvWindow)
		if !sc.registerStream(id, s) {
			// Only two things return false — the concurrency limit and a full accept
			// queue — and the argument above says neither can happen here. If one
			// does, the benchmark is measuring the refusal path, so say so instead of
			// reporting the number.
			b.Error("registerStream refused: benchmark is measuring the REFUSED_STREAM branch, not admission")
			return admitted
		}
		admitted++
		ss, ok := <-sc.acceptCh
		if !ok {
			b.Error("acceptCh closed mid-run")
			return admitted
		}
		sc.markStreamDone(ss.id)
		id += stride
	}
	return admitted
}

// BenchmarkParallelRegisterStream_SharedConn is the measurement: N goroutines
// admitting and releasing streams on ONE connection, so every iteration touches
// the connection-wide state the accept path serialises on — streamTable.mu in
// admitClient and release, the acceptCh channel, and sc.connCtx's own mutex,
// which context.WithCancel takes to attach the child and cancel takes again to
// detach it (two acquisitions of a connection-wide lock per stream that
// CLAUDE.md's list of contention sites does not name).
//
// Read it against _PerConn below, never on its own: the pair is the measurement.
func BenchmarkParallelRegisterStream_SharedConn(b *testing.B) {
	n := benchParStreams()
	sc, _, _ := benchParConn(b, 0)
	var next atomic.Int64
	var admitted atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// A private identifier stride per goroutine, so no two ever name the same
		// stream. registerStream imposes no ordering (validateClientStreamID, which
		// does, is not on this path — see the file comment), so disjointness is all
		// this needs.
		g := uint32(next.Add(1) - 1)                                         //nolint:gosec // G115: bounded by GOMAXPROCS
		admitted.Add(benchAcceptRegisterLoop(b, pb, sc, 2*g+1, 2*uint32(n))) //nolint:gosec // G115: n ≤ benchParMaxStreams
	})
	b.StopTimer()
	if got := admitted.Load(); got != int64(b.N) {
		b.Fatalf("accept path not reached: %d admissions for %d iterations", got, b.N)
	}
}

// BenchmarkParallelRegisterStream_PerConn is the control. Identical work, one
// connection per goroutine, so no two share a stream table, an accept queue or a
// connection context. The gap against _SharedConn at the same -cpu is what the
// accept path's connection-wide state costs.
func BenchmarkParallelRegisterStream_PerConn(b *testing.B) {
	n := benchParStreams()
	conns := make([]*ServerConn, n)
	for i := range n {
		sc, _, _ := benchParConn(b, 0)
		conns[i] = sc
	}
	var next atomic.Int64
	var admitted atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Same identifier scheme as _SharedConn, so the two loops differ in the
		// connection and in nothing else. Disjointness is redundant here (each
		// goroutine owns its connection) and kept anyway for that reason.
		g := uint32(next.Add(1) - 1)                                                      //nolint:gosec // G115: bounded by GOMAXPROCS
		admitted.Add(benchAcceptRegisterLoop(b, pb, conns[int(g)%n], 2*g+1, 2*uint32(n))) //nolint:gosec // G115: n ≤ benchParMaxStreams
	})
	b.StopTimer()
	if got := admitted.Load(); got != int64(b.N) {
		b.Fatalf("accept path not reached: %d admissions for %d iterations", got, b.N)
	}
}
