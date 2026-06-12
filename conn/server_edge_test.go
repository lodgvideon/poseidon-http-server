package conn

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// --- onWindowUpdate (outbound window replenishment) ---

func TestServerConn_WindowUpdate_IncreasesSendWindow(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Write WINDOW_UPDATE in background; read response in foreground.
		writeDone := make(chan error, 2)
		go func() {
			writeDone <- cliFr.WriteWindowUpdate(1, 8192)
			writeDone <- cliFr.WriteWindowUpdate(0, 8192)
		}()

		// Read response headers.
		hh := captureHandler{block: &bytes.Buffer{}}
		cliFr.ReadFrame(context.Background(), &hh)
		<-writeDone
		<-writeDone
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

	// Wait for WINDOW_UPDATE to be processed.
	time.Sleep(200 * time.Millisecond)

	// Send response — verifies stream still works.
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}
}

// --- onWindowUpdate overflow ---

func TestServerConn_WindowUpdate_OverflowReturnsError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Send malicious WINDOW_UPDATE that overflows.
		writeDone := make(chan error, 1)
		go func() { writeDone <- cliFr.WriteWindowUpdate(0, 0x7FFFFFFF) }()
		<-writeDone

		// Connection should be closed by server; read will fail.
		time.Sleep(500 * time.Millisecond)
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

	// Connection should close due to WINDOW_UPDATE overflow.
	time.Sleep(300 * time.Millisecond)
}

// --- OnContinuation (multi-frame header block) ---

func TestServerConn_ContinuationFrame(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Send HEADERS without END_HEADERS, then CONTINUATION.
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		})

		// Split into two: first part in HEADERS (no END_HEADERS), rest in CONTINUATION.
		writeDone := make(chan error, 2)
		go func() {
			writeDone <- cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block[:len(block)/2],
				EndHeaders:    false,
				EndStream:     false,
			})
		}()
		<-writeDone
		go func() {
			writeDone <- cliFr.WriteContinuation(1, true, block[len(block)/2:])
		}()
		<-writeDone

		// Read response.
		hh := captureHandler{block: &bytes.Buffer{}}
		cliFr.ReadFrame(context.Background(), &hh)
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

	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("event type = %v, want EventHeaders", ev.Type)
	}

	// Verify headers were decoded correctly.
	if len(ev.Headers) < 3 {
		t.Fatalf("expected at least 3 headers, got %d", len(ev.Headers))
	}

	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}
}

// --- writeServerData chunking (large body) ---

func TestServerConn_SendData_LargeBody(t *testing.T) {
	// Body larger than default frame size forces chunking.
	body := make([]byte, 32768)
	for i := range body {
		body[i] = byte(i % 256)
	}

	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/big")},
		}, true)

		// Read response headers.
		hh := captureHandler{block: &bytes.Buffer{}}
		cliFr.ReadFrame(context.Background(), &hh)

		// Read all DATA frames.
		total := 0
		for total < len(body) {
			dh := &dataCapture{}
			fh, err := cliFr.ReadFrame(context.Background(), dh)
			if err != nil {
				return
			}
			total += len(dh.data)
			if fh.Flags&frame.FlagDataEndStream != 0 {
				break
			}
		}
		if total != len(body) {
			t.Errorf("received %d bytes, want %d", total, len(body))
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

	if err := stream.SendData(ctx, body, true); err != nil {
		t.Fatalf("SendData: %v", err)
	}
}

// --- SendData empty with END_STREAM ---

func TestServerConn_SendData_EmptyEndStream(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/empty")},
		}, true)

		// Read headers.
		hh := captureHandler{block: &bytes.Buffer{}}
		cliFr.ReadFrame(context.Background(), &hh)

		// Read empty DATA with END_STREAM.
		dh := &dataCapture{}
		fh, err := cliFr.ReadFrame(context.Background(), dh)
		if err != nil {
			t.Logf("read data: %v", err)
			return
		}
		if len(dh.data) != 0 {
			t.Errorf("expected empty data, got %d bytes", len(dh.data))
		}
		if fh.Flags&frame.FlagDataEndStream == 0 {
			t.Errorf("expected END_STREAM")
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
		{Name: []byte(":status"), Value: []byte("204")},
	}, false); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}

	if err := stream.SendData(ctx, nil, true); err != nil {
		t.Fatalf("SendData empty END_STREAM: %v", err)
	}
}

// --- SendHeaders after stream closed returns error ---

func TestServerConn_SendHeaders_AfterClosed(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Keep pipe alive — read RST_STREAM from server.
		rst := &rstCapture{}
		cliFr.ReadFrame(context.Background(), rst)
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

	// Close stream — sends RST_STREAM.
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// SendHeaders should fail.
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); err != ErrStreamClosed {
		t.Fatalf("SendHeaders after Close: err = %v, want ErrStreamClosed", err)
	}
}

// --- SendData after local ended returns error ---

func TestServerConn_SendData_AfterEndStream(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Read response headers with END_STREAM.
		hh := captureHandler{block: &bytes.Buffer{}}
		cliFr.ReadFrame(context.Background(), &hh)
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

	// SendHeaders with END_STREAM.
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}

	// SendData should fail because localEnded = true.
	if err := stream.SendData(ctx, []byte("x"), false); err != ErrStreamClosed {
		t.Fatalf("SendData after END_STREAM: err = %v, want ErrStreamClosed", err)
	}
}
