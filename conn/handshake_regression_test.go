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

// TestServerConn_HeadersDuringHandshake is a regression test for a bug where
// HEADERS frames sent in the same TCP segment as SETTINGS+ACK during the
// HTTP/2 handshake were silently discarded by settingsRecorder.
//
// Real-world clients (curl, Chrome, Firefox) commonly batch SETTINGS+ACK+HEADERS
// into a single TCP segment, so the server would accept the connection but never
// deliver the request stream.
//
// Fix: settingsRecorder now forwards non-SETTINGS frames to serverConnHandler.
func TestServerConn_HeadersDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// --- Server side ---
	type result struct {
		stream *ServerStream
		err    error
	}
	resultCh := make(chan result, 1)

	go func() {
		nc, err := ln.Accept()
		if err != nil {
			resultCh <- result{nil, err}
			return
		}
		sc, err := NewServerConn(context.Background(), nc, ServerConnOptions{})
		if err != nil {
			resultCh <- result{nil, err}
			return
		}
		stream, err := sc.AcceptStream(context.Background())
		resultCh <- result{stream, err}
	}()

	// --- Client side: send preface + SETTINGS + SETTINGS.ACK + HEADERS in ONE write ---
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close()

	var buf bytes.Buffer

	// 1. Client preface
	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	// 2. Client SETTINGS (empty)
	fr := frame.NewFramer(&buf, nc)
	fr.WriteSettings(frame.SettingsParams{N: 0})

	// 3. Client SETTINGS ACK (ACK the server's settings we'll receive)
	// We read server frames first, then batch the ACK with HEADERS.
	// But to trigger the bug, we need SETTINGS + ACK + HEADERS in one buffer.
	// Since server sends its SETTINGS after reading preface, we must read them first.
	// So the flow is: write preface+SETTINGS → read server SETTINGS → write ACK+HEADERS.

	// Write preface + SETTINGS
	if _, err := nc.Write(buf.Bytes()); err != nil {
		t.Fatalf("write preface+settings: %v", err)
	}

	// Read server SETTINGS + our ACK for server SETTINGS
	srvFr := frame.NewFramer(nc, nc)
	srvHandler := &collectSettings{}
	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Read server SETTINGS
	if err := readOneFrameRaw(readCtx, srvFr, srvHandler); err != nil {
		t.Fatalf("read server settings: %v", err)
	}
	// Read server SETTINGS.ACK
	if err := readOneFrameRaw(readCtx, srvFr, srvHandler); err != nil {
		t.Fatalf("read server settings ack: %v", err)
	}

	// Now write SETTINGS.ACK + HEADERS in a SINGLE buffer (this is the bug trigger)
	var batch bytes.Buffer
	batchFr := frame.NewFramer(&batch, nc)

	// SETTINGS ACK
	batchFr.WriteSettingsAck()

	// HEADERS frame for stream 1
	enc := hpack.NewEncoder()
	hdrs := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	block := enc.EncodeBlock(nil, hdrs)
	batchFr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     true,
	})

	// Send ACK + HEADERS atomically
	if _, err := nc.Write(batch.Bytes()); err != nil {
		t.Fatalf("write batch: %v", err)
	}

	// --- Verify server received the stream ---
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("AcceptStream error: %v", res.err)
		}
		if res.stream == nil {
			t.Fatal("AcceptStream returned nil stream")
		}
		if res.stream.ID() != 1 {
			t.Errorf("stream ID = %d, want 1", res.stream.ID())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: AcceptStream never returned — HEADERS frame was lost during handshake")
	}
}

// readOneFrameRaw reads one frame using the given handler.
func readOneFrameRaw(ctx context.Context, fr *frame.Framer, h frame.Handler) error {
	_, err := fr.ReadFrame(ctx, h)
	return err
}

// collectSettings is a frame.Handler that records SETTINGS frames.
type collectSettings struct {
	settingsSeen bool
	ackSeen      bool
}

func (c *collectSettings) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (c *collectSettings) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (c *collectSettings) OnPriority(frame.FrameHeader, frame.Priority) error    { return nil }
func (c *collectSettings) OnRSTStream(frame.FrameHeader, frame.ErrCode) error    { return nil }
func (c *collectSettings) OnSettings(fh frame.FrameHeader, _ frame.SettingsParams) error {
	if fh.Flags&frame.FlagSettingsAck != 0 {
		c.ackSeen = true
	} else {
		c.settingsSeen = true
	}
	return nil
}
func (c *collectSettings) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error { return nil }
func (c *collectSettings) OnPing(frame.FrameHeader, [8]byte) error                                  { return nil }
func (c *collectSettings) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error          { return nil }
func (c *collectSettings) OnWindowUpdate(frame.FrameHeader, uint32) error                           { return nil }
func (c *collectSettings) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error                { return nil }

func (c *collectSettings) OnOrigin(frame.FrameHeader, []string) error { return nil }
func (c *collectSettings) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }
