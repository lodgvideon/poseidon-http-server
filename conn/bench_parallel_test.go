package conn

// Parallel (contention-visible) benchmarks for the connection write path.
//
// Why this file exists (issue #95): every benchmark in the repo before it was
// single-goroutine, and a single-goroutine benchmark cannot observe a mutex. The
// design rule in CLAUDE.md ("locks cost more than allocations") is in direct
// tension with ADR-0003, which records that "all writes to the framer are
// serialized under a single mutex (wmu)". This file produces the measurement
// that tension has to be resolved with; it changes no production locking.
//
// The shape that matters is MANY STREAMS ON ONE CONNECTION. A benchmark where
// each goroutine owns its own connection measures nothing about a
// connection-wide mutex — so every _SharedConn benchmark here is paired with a
// _PerConn control that does identical work with the lock removed from the
// picture. The pair is the measurement: if both scale, wmu is not the limit; if
// only _PerConn scales, it is.
//
// Sweep them with -cpu to get the curve:
//
//	go test -run='^$' -bench='Parallel' -benchmem \
//	        -benchtime=500ms -count=10 -cpu=1,2,4,8,16 ./conn
//
// and confirm the lock is actually reached with -mutexprofile/-blockprofile.
//
// Which pair answers which question — measured, not assumed. A 15 ns spin was
// injected into bumpFramesSent, which every write path calls while HOLDING wmu,
// so the injection is a regression in the critical section itself. Two rounds,
// -benchtime=400ms -count=8, alternating against an unmodified binary:
//
//	                             round 1            round 2
//	_SharedConn (scripted)       +13.03% p=0.000    +16.79% p=0.000
//	_PerConn    (scripted)       +26.33% p=0.000    +17.56% p=0.007
//	_SharedConnTCP               ~       p=0.130     -5.22% p=0.010
//	_PerConnTCP                  ~       p=0.328     +8.18% p=0.000
//
// So: a change to what wmu protects is resolvable on the SCRIPTED pair and is
// NOT resolvable on the TCP pair, whose two rounds disagree in sign on the same
// injected slowdown. That follows from what each pair is for — the TCP variants
// put the write(2) back inside the critical section, and at ~10.5 us/op a 15 ns
// change is 0.14% of the number. Read the TCP pair for "does the syscall
// dominate the lock", and the scripted pair for "did this change the lock".
//
// Both pairs do resolve a large regression: a spin sized to be a real ~2x was
// caught on every benchmark in this file in both rounds at p=0.000, the TCP
// pair included (+37.8%/+48.5% and +78.2%/+110.0%).
//
// Harness note (issue #99): conn/bench_test.go's harness allocates a 1 MiB drain
// buffer in a goroutine that races b.ResetTimer, charging it to the measured
// work. Nothing here allocates after ResetTimer: the client byte script, the
// streams and the header fixtures are all built during setup.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Scripted transport: a net.Conn with no syscalls
// ---------------------------------------------------------------------------

// benchScriptConn is a net.Conn that replays a fixed client-side byte script and
// discards everything the server writes.
//
// It exists to take the write(2) syscall OUT of the critical section, so what
// remains under wmu is only what the server itself does there: the HPACK encode
// and the frame serialisation. That makes this the LOWER BOUND on wmu's cost —
// production holds wmu across the real transport write as well (see the _TCP
// variants below, which put it back).
//
// Reads are served by one goroutine only (the handshake on the constructing
// goroutine, then readerLoop), so the cursor needs no lock. Once the script is
// exhausted Read blocks rather than returning EOF: an EOF would end readerLoop,
// close the connection, and turn every subsequent write into ErrConnClosed.
type benchScriptConn struct {
	script []byte
	off    int
	closed chan struct{}
	once   sync.Once

	// writeCalls counts transport writes. Used to prove a benchmark actually
	// reached the write path rather than short-circuiting somewhere above it.
	writeCalls atomic.Int64
}

func newBenchScriptConn(script []byte) *benchScriptConn {
	return &benchScriptConn{script: script, closed: make(chan struct{})}
}

func (c *benchScriptConn) Read(p []byte) (int, error) {
	if c.off < len(c.script) {
		n := copy(p, c.script[c.off:])
		c.off += n
		return n, nil
	}
	<-c.closed
	return 0, io.EOF
}

func (c *benchScriptConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.writeCalls.Add(1)
	return len(p), nil
}

func (c *benchScriptConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *benchScriptConn) LocalAddr() net.Addr             { return benchScriptAddr{} }
func (c *benchScriptConn) RemoteAddr() net.Addr            { return benchScriptAddr{} }
func (c *benchScriptConn) SetDeadline(time.Time) error     { return nil }
func (c *benchScriptConn) SetReadDeadline(time.Time) error { return nil }
func (c *benchScriptConn) SetWriteDeadline(time.Time) error {
	return nil
}

type benchScriptAddr struct{}

func (benchScriptAddr) Network() string { return "bench" }
func (benchScriptAddr) String() string  { return "bench" }

// ---------------------------------------------------------------------------
// Client-side byte script
// ---------------------------------------------------------------------------

// benchMaxWindowIncrement brings a flow-control window from its 64 KiB protocol
// default to exactly the RFC 9113 §6.9.1 maximum of 2^31-1, so a long benchmark
// never blocks on credit and never has to fake a refund inside the measured
// region (a refund takes fcOutMu and would show up as contention the server
// never actually pays).
const benchMaxWindowIncrement = uint32(1<<31-1) - 65535

// benchClientScript builds the bytes a client would send to open nStreams
// request streams and grant them the maximum flow-control credit.
func benchClientScript(nStreams int) []byte {
	var buf bytes.Buffer
	buf.Write(clientPreface)

	fr := frame.NewFramer(&buf, bytes.NewReader(nil))
	defer fr.Close()
	_ = fr.WriteSettings(frame.SettingsParams{N: 0})
	_ = fr.WriteSettingsAck()
	_ = fr.WriteWindowUpdate(0, benchMaxWindowIncrement)

	enc := hpack.NewEncoder()
	fields := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/bench.Svc/Method")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}
	for i := range nStreams {
		id := uint32(2*i + 1) //nolint:gosec // bounded by nStreams
		block := enc.EncodeBlock(nil, fields)
		_ = fr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      id,
			BlockFragment: block,
			EndHeaders:    true,
		})
		_ = fr.WriteWindowUpdate(id, benchMaxWindowIncrement)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// benchParConn builds a ServerConn over a scripted transport with nStreams open,
// fully credited streams. Everything it returns is allocated before the caller
// resets the timer.
func benchParConn(b *testing.B, nStreams int) (*ServerConn, []*ServerStream, *benchScriptConn) {
	b.Helper()

	nc := newBenchScriptConn(benchClientScript(nStreams))
	sc, err := NewServerConn(context.Background(), nc, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{
			MaxFrameSize:         1 << 20,
			MaxConcurrentStreams: 512,
		},
	})
	if err != nil {
		b.Fatalf("NewServerConn: %v", err)
	}
	b.Cleanup(func() {
		_ = sc.Close()
		_ = nc.Close()
	})

	streams := make([]*ServerStream, 0, nStreams)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range nStreams {
		ss, aerr := sc.AcceptStream(ctx)
		if aerr != nil {
			b.Fatalf("AcceptStream: %v", aerr)
		}
		streams = append(streams, ss)
	}
	benchParWaitCredit(b, sc, streams)
	return sc, streams, nc
}

// benchParWaitCredit blocks until the reader goroutine has applied the script's
// WINDOW_UPDATE frames. Without it a benchmark can start before the credit
// lands and spend its first iterations blocked in acquireSendCredits.
//
// It polls rather than taking the PING/PING-ACK barrier #124 gave the sibling
// harness in conn/bench_test.go, and issue #164 records why it cannot: the
// barrier needs the client to READ the server's ACK, and benchScriptConn
// replays a fixed pre-built script and drops every write (see Read/Write above),
// so there is no channel for an ACK to arrive on. That much is a fact about the
// transport.
//
// What #164 then calls "the real fix" — giving benchScriptConn a readable
// write-back path so both harnesses can take the barrier — would make the
// postcondition WEAKER, not stronger, so it is deliberately not done. A PING ACK
// proves the server processed every frame written before the PING; it says
// nothing about the resulting flow-control state, which is what the benchmark
// actually needs and what the sibling harness has to infer. This loop reads that
// state directly, under the very locks acquireSendCredits reads it under, and
// the script's LAST frame is the final WINDOW_UPDATE — so "every window is
// credited" already implies "the whole script has been applied". A barrier would
// buy back the 1 ms sleep, which lands entirely in setup, before b.ResetTimer,
// and costs the measurement nothing.
//
// The 5s deadline is a setup guard, not a measurement constant: nothing it
// bounds scales with -benchtime, exactly as benchSetupTimeout does not.
func benchParWaitCredit(b *testing.B, sc *ServerConn, streams []*ServerStream) {
	b.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sc.fcOutMu.Lock()
		connOK := sc.peerConnSendWindow > 1<<20
		sc.fcOutMu.Unlock()
		allOK := connOK
		for _, ss := range streams {
			ss.mu.Lock()
			ok := ss.sendWindow > 1<<20
			ss.mu.Unlock()
			if !ok {
				allOK = false
				break
			}
		}
		if allOK {
			return
		}
		if time.Now().After(deadline) {
			b.Fatal("flow-control credit never arrived")
		}
		time.Sleep(time.Millisecond)
	}
}

// benchParMaxStreams caps how many streams one harness connection opens.
//
// It is not arbitrary: ServerConn.acceptCh is a 64-deep buffered channel and
// registerStream (conn/server_ops.go:53) does a NON-BLOCKING send into it,
// closing the stream when it is full. Opening more than 64 streams before
// draining any therefore loses streams and hangs AcceptStream — which is how
// this constant came to exist (a 65-stream harness flaked once in 40 runs).
const benchParMaxStreams = 64

// benchParStreams is how many streams (and, for the control, how many
// connections) a parallel benchmark needs: one per goroutine RunParallel will
// start, since a ServerStream is single-goroutine by contract.
func benchParStreams() int {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	if n > benchParMaxStreams {
		n = benchParMaxStreams
	}
	return n
}

// benchParHeaders is the response field section every header benchmark writes.
var benchParHeaders = []hpack.HeaderField{
	{Name: []byte(":status"), Value: []byte("200")},
	{Name: []byte("content-type"), Value: []byte("application/grpc")},
}

// benchParAssertWrites fails the benchmark unless the connection actually put
// frames on its transport. A parallel benchmark that quietly stops reaching the
// write path would otherwise report a flat, contention-free line — the answer
// everyone wants to believe — while measuring nothing.
func benchParAssertWrites(b *testing.B, got, want int64) {
	b.Helper()
	if got < want {
		b.Fatalf("write path not reached: %d transport writes for %d iterations", got, want)
	}
}

// ---------------------------------------------------------------------------
// HEADERS: one connection (contends wmu) vs one connection per goroutine
// ---------------------------------------------------------------------------

// BenchmarkParallelWriteHeaders_SharedConn is the measurement: N goroutines,
// each with its own stream, all writing through the ONE wmu of a single
// connection. This is the sidecar shape — few connections, many streams.
func BenchmarkParallelWriteHeaders_SharedConn(b *testing.B) {
	n := benchParStreams()
	sc, streams, nc := benchParConn(b, n)
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ss := streams[int(next.Add(1)-1)%len(streams)]
		ctx := context.Background()
		for pb.Next() {
			if err := sc.writeServerHeaders(ctx, ss, benchParHeaders, false, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	benchParAssertWrites(b, nc.writeCalls.Load(), int64(b.N))
}

// BenchmarkParallelWriteHeaders_PerConn is the control. Identical work, but each
// goroutine drives its own connection, so no two share a wmu. The gap between
// this and _SharedConn at the same -cpu is the connection-wide write lock.
func BenchmarkParallelWriteHeaders_PerConn(b *testing.B) {
	n := benchParStreams()
	conns := make([]*ServerConn, n)
	streams := make([]*ServerStream, n)
	transports := make([]*benchScriptConn, n)
	for i := range n {
		sc, ss, nc := benchParConn(b, 1)
		conns[i], streams[i], transports[i] = sc, ss[0], nc
	}
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)-1) % n
		sc, ss := conns[i], streams[i]
		ctx := context.Background()
		for pb.Next() {
			if err := sc.writeServerHeaders(ctx, ss, benchParHeaders, false, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	var total int64
	for _, nc := range transports {
		total += nc.writeCalls.Load()
	}
	benchParAssertWrites(b, total, int64(b.N))
}

// ---------------------------------------------------------------------------
// DATA: adds fcOutMu (acquireSendCredits) on top of wmu
// ---------------------------------------------------------------------------

// benchParDataPayload is deliberately small: the point is lock traffic per
// frame, not bytes moved.
var benchParDataPayload = make([]byte, 64)

// benchParCreditRefreshMask makes each goroutine restore its flow-control credit
// once every 65536 iterations.
//
// It is not optional. The script grants the RFC 9113 §6.9.1 maximum window of
// 2^31-1 octets, which at 64 bytes a frame is 33.5M writes — and `bench-gate`
// runs `-benchtime=2s`, which reaches that on this path. Without the top-up the
// benchmark exhausts its credit, every goroutine parks in acquireSendCredits
// waiting for a WINDOW_UPDATE that the exhausted script will never send, and the
// run dies with "all goroutines are asleep - deadlock". (Found exactly that way:
// the 500 ms sweep passed with a 4x margin and the 2 s gate run did not.)
//
// 65536 iterations is 4 MiB of credit per goroutine between top-ups, a 500x
// margin, at a cost of one fcOutMu/ss.mu pair per 65536 writes — under a
// thousandth of a nanosecond per op, and far too rare to colour the contention
// being measured.
const benchParCreditRefreshMask = 0xFFFF

// benchParTopUpCredit restores both send windows to the §6.9.1 maximum. Lock
// order is fcOutMu then ss.mu, matching acquireSendCredits.
func benchParTopUpCredit(sc *ServerConn, ss *ServerStream) {
	const maxWindow = int32(1<<31 - 1)
	sc.fcOutMu.Lock()
	sc.peerConnSendWindow = maxWindow
	ss.mu.Lock()
	ss.sendWindow = maxWindow
	ss.mu.Unlock()
	sc.fcOutMu.Unlock()
}

// BenchmarkParallelWriteData_SharedConn walks the full DATA path: fcOutMu for
// credit, then wmu for the frame — two connection-wide locks per write.
func BenchmarkParallelWriteData_SharedConn(b *testing.B) {
	n := benchParStreams()
	sc, streams, nc := benchParConn(b, n)
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ss := streams[int(next.Add(1)-1)%len(streams)]
		ctx := context.Background()
		var n uint64
		for pb.Next() {
			if n&benchParCreditRefreshMask == 0 {
				benchParTopUpCredit(sc, ss)
			}
			n++
			if err := sc.writeServerData(ctx, ss, benchParDataPayload, false); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	benchParAssertWrites(b, nc.writeCalls.Load(), int64(b.N))
}

// BenchmarkParallelWriteData_PerConn is the DATA control: same two locks, but
// uncontended because each goroutine owns its connection.
func BenchmarkParallelWriteData_PerConn(b *testing.B) {
	n := benchParStreams()
	conns := make([]*ServerConn, n)
	streams := make([]*ServerStream, n)
	transports := make([]*benchScriptConn, n)
	for i := range n {
		sc, ss, nc := benchParConn(b, 1)
		conns[i], streams[i], transports[i] = sc, ss[0], nc
	}
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)-1) % n
		sc, ss := conns[i], streams[i]
		ctx := context.Background()
		var iter uint64
		for pb.Next() {
			if iter&benchParCreditRefreshMask == 0 {
				benchParTopUpCredit(sc, ss)
			}
			iter++
			if err := sc.writeServerData(ctx, ss, benchParDataPayload, false); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	var total int64
	for _, nc := range transports {
		total += nc.writeCalls.Load()
	}
	benchParAssertWrites(b, total, int64(b.N))
}

// ---------------------------------------------------------------------------
// The same pair over a real socket: wmu held across write(2)
// ---------------------------------------------------------------------------

// benchParTCPConn is benchParConn over TCP loopback: the production shape, in
// which wmu is held across a real transport write. Slower and noisier than the
// scripted transport, and that is the finding — the syscall is inside the
// critical section, not beside it.
func benchParTCPConn(b *testing.B, nStreams int) (*ServerConn, []*ServerStream) {
	b.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Allocated before the client goroutine starts, not inside it — see #99.
	script := benchClientScript(nStreams)
	drain := make([]byte, 1<<16)

	// armed gates the hang guard in the drain loop below. It is set at the very
	// end of this helper, once setup is complete, and it is what makes the guard
	// safe for a benchmark that legitimately writes nothing.
	//
	// The drain loop here consumes the server's HANDSHAKE output — the SETTINGS
	// and SETTINGS ACK NewServerConn writes — because unlike the sibling harness
	// in conn/bench_test.go this one has no framer-driven credit barrier reading
	// those bytes first. So without this gate the guard is armed before the
	// caller has run a single iteration, and "this benchmark produced output" is
	// true for a benchmark that never touches the socket at all. Measured, with
	// the gate stubbed to true from byte one: a TCP-harness benchmark doing
	// write-free work (onWindowUpdate in a loop) panicked at 30.0s claiming a
	// wedge, having written nothing it could wedge on.
	var armed atomic.Bool

	scCh := make(chan *ServerConn, 1)
	errCh := make(chan error, 1)
	go func() {
		nc, aerr := ln.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		sc, cerr := NewServerConn(context.Background(), nc, ServerConnOptions{
			AdvertisedSettings: AdvertisedSettings{
				MaxFrameSize:         1 << 20,
				MaxConcurrentStreams: 512,
			},
		})
		if cerr != nil {
			errCh <- cerr
			return
		}
		scCh <- sc
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = clientConn.Close() })

	go func() {
		if _, werr := clientConn.Write(script); werr != nil {
			return
		}
		// Drain server output for as long as the connection lives. The lifetime
		// is still the connection's — the b.Cleanup above closes clientConn and
		// sc.Close() closes the server end, either of which ends this loop — and
		// the reason is still the one this loop was written with: the 5s
		// one-shot read deadline conn/bench_test.go used to set here silently
		// stopped draining part-way through a long benchmark and let the socket
		// buffer become the thing being measured (#122).
		//
		// What that shape had no answer for is a WEDGE (#159). `go test
		// -timeout` does not cover benchmarks: testing.(*M).Run calls
		// m.stopAlarm() (src/testing/testing.go:2446) before runBenchmarks
		// (:2459). Verified on go1.26.6 — the identical infinite block dies with
		// `panic: test timed out after 10s` inside a Test and was still running
		// at 45s inside a Benchmark under the same -test.timeout=10s. With THIS
		// goroutine parked in a socket read the runtime's deadlock detector
		// cannot fire either, which is exactly the difference between this
		// file's two transports: a wedged benchScriptConn benchmark still dies
		// with "all goroutines are asleep" (see benchParCreditRefreshMask), a
		// wedged TCP one hangs until CI kills the job. Measured before this
		// guard existed: the wedge below ran the full 60s under
		// -test.timeout=10s and had to be SIGKILLed.
		//
		// The guard is the one #123 landed in the sibling harness: re-arm the
		// read deadline PER READ, and trip only on silence that FOLLOWS observed
		// output. It bounds the gap between consecutive server writes, not total
		// connection life, so no value of -benchtime can make it fire on a
		// healthy run — both TCP benchmarks write every iteration, microseconds
		// apart, against a 30s constant.
		//
		// b.Fatal is unavailable here (only the goroutine running the benchmark
		// may call it), and b.Error is unusable too because this goroutine can
		// outlive the benchmark, at which point logging panics. So every
		// non-guard error path simply returns and the guard panics — after
		// debug.SetTraceback("all"), because GOTRACEBACK defaults to "single"
		// and would dump only this goroutine, hiding the wedged one that is the
		// entire point of the dump.
		progressed := false
		for {
			if derr := clientConn.SetReadDeadline(time.Now().Add(benchDrainIdleTimeout)); derr != nil {
				return // closed by a b.Cleanup
			}
			n, rerr := clientConn.Read(drain)
			if n > 0 && armed.Load() {
				progressed = true
			}
			if rerr == nil {
				continue
			}
			if errors.Is(rerr, os.ErrDeadlineExceeded) {
				if progressed {
					debug.SetTraceback("all")
					panic("bench harness (conn/bench_parallel_test.go): the server produced no output for " +
						benchDrainIdleTimeout.String() + " after this benchmark had been writing — the " +
						"benchmark goroutine is wedged. `go test -timeout` does not cover benchmarks, so " +
						"this panic is the only thing that will end the run; the stacks below name the " +
						"blocked frame.")
				}
				continue // a benchmark that never writes: keep the connection up
			}
			return // connection closed
		}
	}()

	var sc *ServerConn
	select {
	case sc = <-scCh:
	case err = <-errCh:
		b.Fatalf("server conn: %v", err)
	case <-time.After(10 * time.Second):
		b.Fatal("timeout waiting for ServerConn")
	}
	b.Cleanup(func() { _ = sc.Close() })

	streams := make([]*ServerStream, 0, nStreams)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range nStreams {
		ss, aerr := sc.AcceptStream(ctx)
		if aerr != nil {
			b.Fatalf("AcceptStream: %v", aerr)
		}
		streams = append(streams, ss)
	}
	benchParWaitCredit(b, sc, streams)

	// Setup is done: every byte the drain sees from here on was produced by the
	// caller's own iterations, so from here on silence means the caller stopped.
	armed.Store(true)
	return sc, streams
}

// BenchmarkParallelWriteHeaders_SharedConnTCP is _SharedConn with the syscall
// put back inside wmu.
func BenchmarkParallelWriteHeaders_SharedConnTCP(b *testing.B) {
	n := benchParStreams()
	sc, streams := benchParTCPConn(b, n)
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ss := streams[int(next.Add(1)-1)%len(streams)]
		ctx := context.Background()
		for pb.Next() {
			if err := sc.writeServerHeaders(ctx, ss, benchParHeaders, false, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	benchParAssertWrites(b, sc.Stats().FramesSent, int64(b.N))
}

// BenchmarkParallelWriteHeaders_PerConnTCP is the control for the above: one
// socket AND one wmu per goroutine.
func BenchmarkParallelWriteHeaders_PerConnTCP(b *testing.B) {
	n := benchParStreams()
	conns := make([]*ServerConn, n)
	streams := make([]*ServerStream, n)
	for i := range n {
		sc, ss := benchParTCPConn(b, 1)
		conns[i], streams[i] = sc, ss[0]
	}
	var next atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)-1) % n
		sc, ss := conns[i], streams[i]
		ctx := context.Background()
		for pb.Next() {
			if err := sc.writeServerHeaders(ctx, ss, benchParHeaders, false, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	var total int64
	for _, sc := range conns {
		total += sc.Stats().FramesSent
	}
	benchParAssertWrites(b, total, int64(b.N))
}

// ---------------------------------------------------------------------------
// fcOutCond: what one WINDOW_UPDATE costs as the waiter population grows
// ---------------------------------------------------------------------------

// BenchmarkFCOutCondBroadcast measures a single connection-level WINDOW_UPDATE
// against the number of streams parked in acquireSendCredits.
//
// sc.fcOutCond.Broadcast() wakes EVERY waiter (there is no Signal() anywhere in
// conn/). Each one re-acquires fcOutMu, re-reads its own window, finds it still
// empty and parks again — so the cost of one WINDOW_UPDATE is expected to grow
// with the waiter count. The waiters here hold a zero stream send window, which
// is exactly the state a real stream is in when it is waiting for credit.
func BenchmarkFCOutCondBroadcast(b *testing.B) {
	for _, waiters := range []int{0, 1, 8, 64} {
		b.Run(fmt.Sprintf("waiters=%d", waiters), func(b *testing.B) {
			// One stream per waiter, and never more than acceptCh can hold. The
			// measured operation is a CONNECTION-level WINDOW_UPDATE, so it needs no
			// stream of its own.
			nStreams := waiters
			if nStreams < 1 {
				nStreams = 1
			}
			sc, streams, _ := benchParConn(b, nStreams)

			// The script credited the connection window to its 2^31-1 maximum, which
			// a WINDOW_UPDATE of any size would overflow. Start it from zero instead.
			sc.fcOutMu.Lock()
			sc.peerConnSendWindow = 0
			sc.fcOutMu.Unlock()

			var started, finished atomic.Int64
			var wg sync.WaitGroup
			for i := range waiters {
				ss := streams[i]
				ss.mu.Lock()
				ss.sendWindow = 0 // no stream credit => park in fcOutCond.Wait
				ss.mu.Unlock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					started.Add(1)
					_, _ = sc.acquireSendCredits(context.Background(), ss, 1)
					finished.Add(1)
				}()
			}
			for started.Load() < int64(waiters) {
				time.Sleep(time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond) // let them reach Wait()

			b.ResetTimer()
			b.ReportAllocs()
			for i := range b.N {
				if i&0xFFFFF == 0 {
					// Keep the window far from 2^31-1 without paying for a reset per op.
					sc.fcOutMu.Lock()
					sc.peerConnSendWindow = 0
					sc.fcOutMu.Unlock()
				}
				if err := sc.onWindowUpdate(0, 1); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			// Proof the waiters were parked for the whole measured region: the only
			// exits from acquireSendCredits are credit, context, or a closed
			// connection, and none of those happened.
			if got := finished.Load(); got != 0 {
				b.Fatalf("%d of %d waiters left acquireSendCredits during the run", got, waiters)
			}
			_ = sc.Close() // wakes them with ErrConnClosed
			wg.Wait()
		})
	}
}
