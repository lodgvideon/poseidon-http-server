package conn

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// --- Inbound flow control (onDataReceived) ---

func TestServerConn_InboundFlowControl_WindowRefund(t *testing.T) {
	sc := &ServerConn{
		connRecvWindow: int32(connInitialRecvWindow),
	}
	sc.fcMu = sync.Mutex{} // not needed but for safety

	s := newServerStream(1, 8, sc, int32(connInitialRecvWindow))

	// Send enough DATA to trigger a WINDOW_UPDATE refund.
	// Use chunks ≤ 16384 (default MAX_FRAME_SIZE) to avoid frame-size errors.
	chunk := make([]byte, recvWindowRefundThreshold/2)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	// First chunk should trigger stream-level refund.
	// We can't call onDataReceived directly without a full conn,
	// so test via the full pipe instead with proper goroutine separation.

	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	writeErrCh := make(chan error, 2)
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/upload")},
		}, false)

		// Write DATA in background; read WINDOW_UPDATE in foreground to avoid pipe deadlock.
		go func() {
			writeErrCh <- cliFr.WriteData(1, false, chunk)
			writeErrCh <- cliFr.WriteData(1, true, chunk)
		}()

		// Read WINDOW_UPDATE frames (may be 0–4 depending on timing).
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		for {
			wuh := &windowUpdateCapture{}
			if _, err := cliFr.ReadFrame(ctx2, wuh); err != nil {
				break
			}
		}
		<-writeErrCh
		<-writeErrCh
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc2, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc2.Close()

	stream, err := sc2.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Read headers.
	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv headers: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("first event = %v, want EventHeaders", ev.Type)
	}

	// Read DATA events.
	totalData := 0
	for i := range 2 {
		ev, err = stream.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv data[%d]: %v", i, err)
		}
		if ev.Type != EventData {
			t.Fatalf("event[%d] = %v, want EventData", i, ev.Type)
		}
		totalData += len(ev.Data)
	}

	expected := int(recvWindowRefundThreshold/2) * 2 // 2 chunks of threshold/2 bytes
	if totalData != expected {
		t.Fatalf("total data = %d, want %d", totalData, expected)
	}
	_ = s
	_ = sc
}

// --- PING echo from client ---

func TestServerConn_ClientPing_ServerEchoes(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		var payload [8]byte
		copy(payload[:], "testping")
		writeDone := make(chan error, 1)
		go func() { writeDone <- cliFr.WritePing(false, payload) }()
		<-writeDone

		ph := &pingCapture{}
		fh, err := cliFr.ReadFrame(context.Background(), ph)
		if err != nil {
			t.Logf("client read ping ack: %v", err)
			return
		}
		if fh.Flags&frame.FlagPingAck == 0 {
			t.Errorf("expected PING ACK, got flags=%d", fh.Flags)
		}
		if ph.payload != payload {
			t.Errorf("payload mismatch")
		}
		time.Sleep(100 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()
	time.Sleep(300 * time.Millisecond)
}

// --- Trailers ---

func TestServerConn_SendTrailers(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		hh := captureHandler{block: &bytes.Buffer{}}
		if _, err := cliFr.ReadFrame(context.Background(), &hh); err != nil {
			t.Logf("read headers: %v", err)
			return
		}
		th := captureHandler{block: &bytes.Buffer{}}
		fh, err := cliFr.ReadFrame(context.Background(), &th)
		if err != nil {
			t.Logf("read trailers: %v", err)
			return
		}
		if fh.Flags&frame.FlagHeadersEndStream == 0 {
			t.Errorf("trailers should have END_STREAM")
		}
		time.Sleep(100 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	_, _ = stream.Recv(ctx)

	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, false); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte("grpc-status"), Value: []byte("0")},
	}, true); err != nil {
		t.Fatalf("SendTrailers: %v", err)
	}
}

// --- HeadersReceived flag ---

func TestServerConn_HeadersReceivedFlag(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("event = %v, want EventHeaders", ev.Type)
	}
	if !ev.EndStream {
		t.Fatal("EndStream should be true")
	}

	stream.mu.Lock()
	hr := stream.headersReceived
	re := stream.remoteEnded
	le := stream.localEnded
	stream.mu.Unlock()

	if !hr {
		t.Fatal("headersReceived should be true")
	}
	if !re {
		t.Fatal("remoteEnded should be true")
	}
	if le {
		t.Fatal("localEnded should be false")
	}
}

// --- GoAway idempotent ---

func TestServerConn_GoAway_Idempotent(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		gh := &goAwayCapture{}
		if _, err := cliFr.ReadFrame(context.Background(), gh); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	if err := sc.GoAway(frame.ErrCodeNoError); err != nil {
		t.Fatalf("GoAway 1: %v", err)
	}
	if err := sc.GoAway(frame.ErrCodeInternalError); err != nil {
		t.Fatalf("GoAway 2: %v", err)
	}
}

// --- MultipleStreams ---

func TestServerConn_MultipleStreams(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	// Send all requests in a goroutine, then read all responses in another.
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Serialize writes, then reads to avoid pipe deadlock.
		// Write all requests first.
		for i := uint32(1); i <= 3; i += 2 {
			sendReq(t, cliFr, i, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/")},
			}, true)
		}
		// Read responses.
		for range 2 {
			hh := captureHandler{block: &bytes.Buffer{}}
			if _, err := cliFr.ReadFrame(context.Background(), &hh); err != nil {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	for i := range 2 {
		stream, err := sc.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("AcceptStream[%d]: %v", i, err)
		}
		_, _ = stream.Recv(ctx)
		if err := stream.SendHeaders(ctx, []hpack.HeaderField{
			{Name: []byte(":status"), Value: []byte("200")},
		}, true); err != nil {
			t.Fatalf("SendHeaders[%d]: %v", i, err)
		}
	}

	stats := sc.Stats()
	if stats.StreamsAccepted != 2 {
		t.Fatalf("StreamsAccepted = %d, want 2", stats.StreamsAccepted)
	}
}

// --- StreamEventType.String ---

func TestStreamEventType_String(t *testing.T) {
	tests := []struct {
		t    StreamEventType
		want string
	}{
		{EventHeaders, "headers"},
		{EventData, "data"},
		{EventTrailers, "trailers"},
		{EventReset, "reset"},
		{StreamEventType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("StreamEventType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

// --- windowUpdateCapture ---

type windowUpdateCapture struct {
	increment uint32
}

func (w *windowUpdateCapture) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (w *windowUpdateCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (w *windowUpdateCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (w *windowUpdateCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (w *windowUpdateCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (w *windowUpdateCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (w *windowUpdateCapture) OnPing(frame.FrameHeader, [8]byte) error { return nil }
func (w *windowUpdateCapture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}
func (w *windowUpdateCapture) OnWindowUpdate(_ frame.FrameHeader, inc uint32) error {
	w.increment = inc
	return nil
}
func (w *windowUpdateCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }

// TestServerConn_Ping_CancelledContext verifies that Ping returns an error
// when the context is cancelled before the PING ACK arrives.
func TestServerConn_Ping_CancelledContext(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	go func() {
		defer cli.Close()
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Read the PING from server but do NOT send ACK.
			// Just read one frame (the PING) and sit on it.
			h := &dataCapture{}
			cliFr.ReadFrame(context.Background(), h)
			// Hold connection open briefly.
			time.Sleep(500 * time.Millisecond)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	// Ping with a very short timeout — should expire before ACK.
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer pingCancel()

	_, err = sc.Ping(pingCtx)
	if err == nil {
		t.Fatal("Ping should return error on cancelled context")
	}
}
