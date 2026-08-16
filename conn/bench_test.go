package conn

import (
	"context"
	"net"
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

	go func() {
		defer clientConn.Close()

		// Send client preface.
		clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

		// Send client SETTINGS (empty).
		fr := frame.NewFramer(clientConn, clientConn)
		fr.WriteSettings(frame.SettingsParams{N: 0})

		// Read server SETTINGS + SETTINGS ACK.
		buf := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		clientConn.Read(buf)

		// Send SETTINGS ACK.
		fr.WriteSettingsAck()

		// Send HEADERS to open stream 1.
		enc := hpack.NewEncoder()
		hf := []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":path"), Value: []byte("/test.Svc/Method")},
			{Name: []byte(":scheme"), Value: []byte("http")},
			{Name: []byte("content-type"), Value: []byte("application/grpc")},
		}
		block := enc.EncodeBlock(nil, hf)
		fr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      1,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     false,
		})

		// Send WINDOW_UPDATE for stream + connection so server can write.
		fr.WriteWindowUpdate(0, 1<<30) // 1GB window
		fr.WriteWindowUpdate(1, 1<<30)

		// Keep reading to drain server output.
		clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			_, err := clientConn.Read(drain)
			if err != nil {
				return
			}
		}
	}()

	select {
	case sc := <-scCh:
		return sc
	case <-time.After(3 * time.Second):
		b.Fatal("timeout waiting for ServerConn")
		return nil
	}
}
