package conn

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Benchmark: writeServerHeaders (HPACK encoding + HEADERS frame write)
// ---------------------------------------------------------------------------

func BenchmarkWriteServerHeaders(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	headers := []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := sc.writeServerHeaders(context.Background(), stream, headers, false, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: writeServerData (DATA frame write with flow control)
// ---------------------------------------------------------------------------

func BenchmarkWriteServerData_Small(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	payload := make([]byte, 100)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := sc.writeServerData(context.Background(), stream, payload, false); err != nil {
			b.Fatal(err)
		}
		// Refund windows to avoid exhaustion, as the two siblings below do.
		// A seeded send window is a budget, not a watermark: RFC 9113 §6.9.1
		// replenishes it only from the peer's WINDOW_UPDATE, and the harness
		// client sends exactly two, both before this loop starts. Unrefunded,
		// 100 octets per iteration exhausts the 65535+2^30 it grants at
		// b.N = 10738074, where writeServerData blocks forever in
		// acquireSendCredits' fcOutCond.Wait — the context is Background, so
		// there is no cancellation to break it, and `go test -timeout` does not
		// cover benchmarks (testing.M.Run stops the alarm before runBenchmarks).
		sc.fcOutMu.Lock()
		sc.peerConnSendWindow += 100
		stream.mu.Lock()
		stream.sendWindow += 100
		stream.mu.Unlock()
		sc.fcOutMu.Unlock()
	}
}

// BenchmarkWriteServerData_16K measures 16KB payload write.
func BenchmarkWriteServerData_16K(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	// Write exactly one 16KB frame per iteration, refund window after.
	payload := make([]byte, 16384)
	const size = int32(16384)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := sc.writeServerData(ctx, stream, payload, false); err != nil {
			b.Fatal(err)
		}
		// Refund windows to avoid exhaustion.
		sc.fcOutMu.Lock()
		sc.peerConnSendWindow += size //nolint:gosec // G115: controlled refund ≤ initial
		stream.mu.Lock()
		stream.sendWindow += size //nolint:gosec // G115: controlled refund ≤ initial
		stream.mu.Unlock()
		sc.fcOutMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Benchmark: acquireSendCredits (flow control)
// ---------------------------------------------------------------------------

func BenchmarkAcquireSendCredits(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	// Background context — should use fast path (no watchdog goroutine).
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		// Consume and refund to keep the window available.
		n, err := sc.acquireSendCredits(ctx, stream, 1024)
		if err != nil {
			b.Fatal(err)
		}
		// Refund the window for next iteration.
		sc.fcOutMu.Lock()
		sc.peerConnSendWindow += int32(n) //nolint:gosec // G115: refund ≤ consumed amount
		stream.mu.Lock()
		stream.sendWindow += int32(n) //nolint:gosec // G115: refund ≤ consumed amount
		stream.mu.Unlock()
		sc.fcOutMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Benchmark: onWindowUpdate
// ---------------------------------------------------------------------------

func BenchmarkOnWindowUpdate(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	// Reset window to small value so we don't overflow.
	stream.mu.Lock()
	stream.sendWindow = 0
	stream.mu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := sc.onWindowUpdate(stream.id, 1024); err != nil {
			b.Fatal(err)
		}
		// Debit back to avoid overflow.
		stream.mu.Lock()
		stream.sendWindow -= 1024
		stream.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Benchmark: onDataReceived
// ---------------------------------------------------------------------------

func BenchmarkOnDataReceived(b *testing.B) {
	sc := benchmarkServerConn(b)
	defer sc.Close()

	stream, err := sc.AcceptStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	// Seed both receive windows well above the per-iteration debit.
	stream.mu.Lock()
	stream.recvWindow = 1 << 20
	stream.mu.Unlock()
	sc.fcMu.Lock()
	sc.connRecvWindow = 1 << 20
	sc.fcMu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if err := sc.onDataReceived(stream, 100); err != nil {
			b.Fatal(err)
		}
		// Refund the per-stream window, as the send-side siblings above do.
		// onDataReceived only debits it: the per-stream refund belongs to
		// ServerStream.creditConsumed, which runs when the application takes
		// delivery via Recv — a call this benchmark deliberately does not make.
		// Without this the seed above is a budget of 1<<20/100 = 10485 iterations
		// and any -benchtime past ~1ms fails, which is what kept `make bench-gate`
		// (-benchtime=2s -count=10) red on ./conn. The connection window needs no
		// help; onDataReceived still self-refunds that half at
		// recvWindowRefundThreshold.
		stream.mu.Lock()
		stream.recvWindow += 100
		stream.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Helpers: create a real ServerConn over net.Pipe
// ---------------------------------------------------------------------------

// benchCreditPing is the opaque payload of the barrier PING below. Its only job
// is to be recognisable in a packet capture.
var benchCreditPing = [8]byte{'b', 'e', 'n', 'c', 'h', 'c', 'r', 'd'}

// benchCreditProbe is a client-side frame.Handler that records the arrival of
// the barrier PING's ACK. ReadFrame dispatches synchronously on the calling
// goroutine, so the plain bool needs no synchronisation.
type benchCreditProbe struct{ acked bool }

func (p *benchCreditProbe) OnPing(fh frame.FrameHeader, _ [8]byte) error {
	if fh.Flags&frame.FlagPingAck != 0 {
		p.acked = true
	}
	return nil
}

func (p *benchCreditProbe) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (p *benchCreditProbe) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (p *benchCreditProbe) OnPriority(frame.FrameHeader, frame.Priority) error { return nil }
func (p *benchCreditProbe) OnRSTStream(frame.FrameHeader, frame.ErrCode) error { return nil }
func (p *benchCreditProbe) OnSettings(frame.FrameHeader, frame.SettingsParams) error {
	return nil
}
func (p *benchCreditProbe) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (p *benchCreditProbe) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}
func (p *benchCreditProbe) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (p *benchCreditProbe) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (p *benchCreditProbe) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (p *benchCreditProbe) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }

func benchmarkServerConn(b *testing.B) *ServerConn {
	// Use TCP loopback instead of net.Pipe to avoid synchronous deadlocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept server connection in background.
	scCh := make(chan *ServerConn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			b.Error(err)
			return
		}
		opts := ServerConnOptions{
			AdvertisedSettings: AdvertisedSettings{
				MaxFrameSize: 1 << 20,
			},
		}
		sc, err := NewServerConn(context.Background(), conn, opts)
		if err != nil {
			b.Error(err)
			return
		}
		scCh <- sc
	}()

	// Client dials and performs HTTP/2 handshake.
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}

	// The drain buffer belongs to the goroutine below, but is allocated here so
	// that it cannot be charged to the caller's benchmark. Go measures benchmark
	// allocations off runtime.ReadMemStats — a whole-process counter that
	// B.ResetTimer snapshots — so a heap allocation on ANY goroutine inside the
	// measured region lands in B/op; there is no per-goroutine attribution to
	// move it out of. At its point of use it is sequenced after the HEADERS
	// write that releases the caller's AcceptStream, so it raced b.ResetTimer
	// and was charged to roughly a third of all samples as 1048576/N B/op with
	// 0 allocs/op — noise a benchstat gate reads as an unbounded 0 → 8 swing.
	// Allocated here it happens-before the select at the end of this function,
	// hence before every caller's b.ResetTimer.
	drain := make([]byte, 1<<20)

	// Closed once the server has demonstrably applied the two WINDOW_UPDATEs
	// below; see the barrier at the end of the client goroutine.
	credited := make(chan struct{})

	go func() {
		defer clientConn.Close()

		// Every frame below is load-bearing for the benchmark that follows, so
		// report rather than drop a write error: an unreported failure here
		// resurfaces later as an unrelated-looking error inside the code under
		// test. b.Error is legal from a non-benchmark goroutine; b.Fatal is not.
		fail := func(what string, err error) {
			b.Errorf("bench harness client: %s: %v", what, err)
		}

		// Send client preface.
		if _, err := clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
			fail("write preface", err)
			return
		}

		// Send client SETTINGS (empty) and immediately ACK the server's. The
		// server's OnSettings returns nil for an ACK without matching it against
		// an outstanding SETTINGS (conn/server_handler.go), so the ACK need not
		// wait for the server's SETTINGS to arrive — which lets every byte the
		// server sends be consumed by the framer below, in frame alignment. The
		// raw 4096-byte Read this replaces could split a frame and leave any
		// later parse misaligned.
		fr := frame.NewFramer(clientConn, clientConn)
		if err := fr.WriteSettings(frame.SettingsParams{N: 0}); err != nil {
			fail("write SETTINGS", err)
			return
		}
		if err := fr.WriteSettingsAck(); err != nil {
			fail("write SETTINGS ACK", err)
			return
		}

		// Send HEADERS to open stream 1.
		enc := hpack.NewEncoder()
		hf := []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":path"), Value: []byte("/test.Svc/Method")},
			{Name: []byte(":scheme"), Value: []byte("http")},
			{Name: []byte("content-type"), Value: []byte("application/grpc")},
		}
		block := enc.EncodeBlock(nil, hf)
		if err := fr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      1,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     false,
		}); err != nil {
			fail("write HEADERS", err)
			return
		}

		// Send WINDOW_UPDATE for stream + connection so server can write.
		if err := fr.WriteWindowUpdate(0, 1<<30); err != nil { // 1GB window
			fail("write connection WINDOW_UPDATE", err)
			return
		}
		if err := fr.WriteWindowUpdate(1, 1<<30); err != nil {
			fail("write stream WINDOW_UPDATE", err)
			return
		}

		// Credit barrier. AcceptStream returns as soon as the HEADERS above is
		// decoded, which says nothing about the two WINDOW_UPDATEs written after
		// it — so without this the benchmark loop could start against the 65535
		// a connection begins with rather than 65535+2^30, and measure its first
		// iterations under a flow-control state the rest of the run does not
		// share. Measured before this barrier existed, 497 of 600 runs started
		// with at least one window still at 65535.
		//
		// The server processes frames in receipt order on its single reader
		// goroutine, so an ACK for a PING written after the WINDOW_UPDATEs proves
		// both have already been applied. Everything here — including whatever
		// the framer allocates while parsing — completes before the helper
		// returns, hence before any caller's b.ResetTimer (see #99 on why the
		// process-wide allocation counter makes that ordering matter).
		if err := fr.WritePing(false, benchCreditPing); err != nil {
			fail("write barrier PING", err)
			return
		}
		if err := clientConn.SetReadDeadline(time.Now().Add(benchSetupTimeout)); err != nil {
			fail("set handshake read deadline", err)
			return
		}
		probe := &benchCreditProbe{}
		for !probe.acked {
			if _, err := fr.ReadFrame(context.Background(), probe); err != nil {
				fail("read frame awaiting barrier PING ACK", err)
				return
			}
		}
		close(credited)

		// Drain server output for as long as the connection lives.
		//
		// This loop used to run under a single `SetReadDeadline(now+5s)` set here
		// and never refreshed. The drain is the only consumer of the server's
		// output, so when that deadline elapsed the goroutine returned, the
		// deferred Close() shut the client end, and every subsequent write from
		// the benchmark failed — surfacing as a socket error raised inside
		// writeServerData or writeServerHeaders, which reads like a server defect
		// and is not one. That made the harness valid only for runs shorter than
		// a wall-clock constant nobody set in relation to -benchtime:
		// BenchmarkWriteServerHeaders passed at -benchtime=2s and failed at 4s;
		// BenchmarkWriteServerData_Small passed at 200000x and failed at 300000x,
		// a boundary that had already moved down from the 400000x recorded in
		// #123 as this host's per-op cost drifted from ~17us to ~21us.
		//
		// The correct lifetime for a drain is the connection's, so the
		// benchmark's `defer sc.Close()` ends it — the same shape
		// benchParTCPConn already uses.
		//
		// The deadline that remains is a hang guard, and it is re-armed per read
		// rather than set once. Removing the one-shot deadline removed the only
		// thing that terminated a wedged benchmark in this package: `go test
		// -timeout` does not cover benchmarks, because testing.(*M).Run calls
		// m.stopAlarm() (src/testing/testing.go:2446) before runBenchmarks
		// (:2459). Verified on go1.26.6 — the identical infinite block dies with
		// `panic: test timed out after 10s` inside a Test, and was still running
		// at 45s inside a Benchmark under the same -timeout=10s. With this
		// goroutine alive on a socket read the runtime's deadlock detector cannot
		// fire either, so a wedge would hang until CI kills the job.
		//
		// The guard is progress-based, not elapsed-based, so no value of
		// -benchtime can make it fire on a healthy run: it trips only when the
		// server has gone silent for benchDrainIdleTimeout *after having produced
		// output*, i.e. a writing benchmark that stopped writing. A benchmark
		// that never writes to the socket (AcquireSendCredits, OnWindowUpdate,
		// OnDataReceived) never arms it and is re-armed past; those cannot wedge
		// on the socket. The wedge this catches is the one #123 names:
		// writeServerData blocking in acquireSendCredits' fcOutCond.Wait, whose
		// context here is Background and so has no cancellation.
		//
		// b.Fatal is unavailable here — only the goroutine running the benchmark
		// may call it — so fail by panicking, which dumps every goroutine stack
		// (naming the blocked frame) and exits non-zero instead of hanging.
		progressed := false
		for {
			if err := clientConn.SetReadDeadline(time.Now().Add(benchDrainIdleTimeout)); err != nil {
				fail("arm drain read deadline", err)
				return
			}
			n, err := clientConn.Read(drain)
			if n > 0 {
				progressed = true
			}
			if err == nil {
				continue
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if progressed {
					// The useful stack is the wedged benchmark's, not this
					// goroutine's, and GOTRACEBACK defaults to "single" — which
					// would dump only the panicking goroutine and hide it.
					debug.SetTraceback("all")
					panic("bench harness: the server produced no output for " +
						benchDrainIdleTimeout.String() + " after this benchmark had been writing — " +
						"the benchmark goroutine is wedged. `go test -timeout` does not cover " +
						"benchmarks, so this panic is the only thing that will end the run; the " +
						"stacks below name the blocked frame.")
				}
				continue // a benchmark that never writes: keep the connection up
			}
			return // connection closed by the benchmark's defer sc.Close()
		}
	}()

	var sc *ServerConn
	select {
	case sc = <-scCh:
	case <-time.After(benchSetupTimeout):
		b.Fatal("timeout waiting for ServerConn")
		return nil
	}

	// The helper's postcondition is "stream open AND credit granted", not just
	// "stream open": waiting only on scCh returns while the WINDOW_UPDATEs are
	// still in flight.
	select {
	case <-credited:
	case <-time.After(benchSetupTimeout):
		b.Fatal("timeout waiting for the harness WINDOW_UPDATEs to be applied")
		return nil
	}
	return sc
}

// benchSetupTimeout bounds each step of the harness handshake. It is a function
// of loopback round-trip latency (sub-millisecond here), not of -benchtime: no
// part of the setup it guards scales with the benchmark's iteration count.
const benchSetupTimeout = 5 * time.Second

// benchDrainIdleTimeout is the hang guard in the drain loop. It is deliberately
// NOT a bigger version of the 5s deadline #122 removed, which would only move
// the cliff: that one bounded total connection life, so it scaled against
// -benchtime. This one bounds the gap between consecutive server writes, and is
// a function of the interval at which a progressing writer produces output —
// ~21us/op for BenchmarkWriteServerData_Small on this host, so 30s is roughly a
// million times the healthy gap. A run stays valid however long it takes, as
// long as it is still making progress.
const benchDrainIdleTimeout = 30 * time.Second
