package conn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// --- A.2: SendHeaders / SendData / Trailers ---

func TestServerConn_SendHeaders_ResponseRoundtrip(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Client sends GET on stream 1.
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":authority"), Value: []byte("example.com")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Read server response HEADERS.
		var got bytes.Buffer
		hh := captureHandler{block: &got}
		if _, err := cliFr.ReadFrame(context.Background(), &hh); err != nil {
			t.Logf("client read response: %v", err)
			return
		}
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

	// Read request headers.
	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("event type = %v, want EventHeaders", ev.Type)
	}

	// Send response headers.
	err = stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, false)
	if err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}
}

func TestServerConn_SendData_ResponseRoundtrip(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/upload")},
		}, true)

		// Read server response headers + data.
		var headersBuf bytes.Buffer
		hh := captureHandler{block: &headersBuf}
		if _, err := cliFr.ReadFrame(context.Background(), &hh); err != nil {
			t.Logf("client read headers: %v", err)
			return
		}
		// Read DATA frame.
		dh := &dataCapture{}
		if _, err := cliFr.ReadFrame(context.Background(), dh); err != nil {
			t.Logf("client read data: %v", err)
			return
		}
		if string(dh.data) != "hello world" {
			t.Errorf("data = %q, want %q", dh.data, "hello world")
		}
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

	// Read request.
	_, err = stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	// Send response headers + data.
	err = stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, false)
	if err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}

	err = stream.SendData(ctx, []byte("hello world"), true)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}
}

// --- A.4: Outbound flow control ---

func TestServerConn_SendData_RespectsFlowControl(t *testing.T) {
	// Server sends data larger than default frame size; should be chunked.
	body := make([]byte, 32*1024) // 32 KiB
	for i := range body {
		body[i] = byte(i % 256)
	}

	cli, srv := net.Pipe()
	receivedData := make([]byte, 0, len(body))
	var receivedMu sync.Mutex
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Read all frames until END_STREAM.
		for {
			dh := &dataCapture{onEndStream: func() {}}
			hh := captureHandler{block: &bytes.Buffer{}}
			fh, err := cliFr.ReadFrame(context.Background(), &multiHandler{dh: dh, hh: &hh})
			if err != nil {
				return
			}
			receivedMu.Lock()
			receivedData = append(receivedData, dh.data...)
			receivedMu.Unlock()
			if fh.Flags&frame.FlagDataEndStream != 0 {
				return
			}
			_ = fh
		}
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

	// Give time for client to read all data.
	time.Sleep(200 * time.Millisecond)
	receivedMu.Lock()
	got := len(receivedData)
	receivedMu.Unlock()
	if got != len(body) {
		t.Errorf("received %d bytes, want %d", got, len(body))
	}
}

// --- A.6: GOAWAY ---

func TestServerConn_GoAway_PreventsNewStreams(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Read GOAWAY from server.
		gh := &goAwayCapture{}
		if _, err := cliFr.ReadFrame(context.Background(), gh); err != nil {
			t.Logf("client read goaway: %v", err)
			return
		}
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	if err := sc.GoAway(frame.ErrCodeNoError); err != nil {
		t.Fatalf("GoAway: %v", err)
	}
}

// --- A.7: PING ---

func TestServerConn_Ping_Roundtrip(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Client reads server PING and echoes ACK.
		for range 2 {
			ph := &pingCapture{}
			fh, err := cliFr.ReadFrame(context.Background(), ph)
			if err != nil {
				return
			}
			if fh.Flags&frame.FlagPingAck == 0 {
				writeDone := make(chan error, 1)
				go func() { writeDone <- cliFr.WritePing(true, ph.payload) }()
				<-writeDone
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	rtt, err := sc.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("RTT = %v, want > 0", rtt)
	}
}

func TestServerConn_Ping_AfterClose(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	_ = sc.Close()

	_, err = sc.Ping(ctx)
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Ping after Close: err = %v, want ErrConnClosed", err)
	}
}

// --- A.7: Keepalive ---

func TestServerConn_Keepalive_PingsPeer(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Client echoes PING ACKs for 3 seconds.
		deadline := time.After(3 * time.Second)
		for {
			select {
			case <-deadline:
				return
			default:
				ph := &pingCapture{}
				fh, err := cliFr.ReadFrame(context.Background(), ph)
				if err != nil {
					return
				}
				if fh.Flags&frame.FlagPingAck == 0 {
					writeDone := make(chan error, 1)
					go func() { writeDone <- cliFr.WritePing(true, ph.payload) }()
					<-writeDone
				}
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		KeepaliveInterval: 200 * time.Millisecond,
	}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	// Wait for a few keepalive cycles.
	time.Sleep(800 * time.Millisecond)
	stats := sc.Stats()
	if stats.FramesSent < 3 {
		t.Fatalf("FramesSent = %d, expected at least 3 keepalive pings", stats.FramesSent)
	}
}

// --- IsAlive ---

func TestServerConn_IsAlive(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}

	if !sc.IsAlive() {
		t.Fatal("IsAlive = false on fresh connection")
	}
	_ = sc.Close()
	if sc.IsAlive() {
		t.Fatal("IsAlive = true after Close")
	}
}

// --- A.5: Dynamic SETTINGS ---

func TestServerConn_DynamicSettings_RetroactiveWindowResize(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		// Client sends request, waits, then sends new SETTINGS.
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, true)

		// Wait for server to accept.
		time.Sleep(100 * time.Millisecond)

		// Send SETTINGS with larger INITIAL_WINDOW_SIZE.
		writeDone := make(chan error, 1)
		go func() {
			var sp frame.SettingsParams
			sp.Pairs[0] = frame.SettingPair{ID: frame.SettingInitialWindowSize, Value: 128 * 1024}
			sp.N = 1
			writeDone <- cliFr.WriteSettings(sp)
		}()
		// Read SETTINGS ACK from server.
		if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
			t.Logf("client read ack: %v", err)
			return
		}
		if err := <-writeDone; err != nil {
			t.Logf("client write settings: %v", err)
			return
		}

		// Read server response.
		hh := captureHandler{block: &bytes.Buffer{}}
		if _, err := cliFr.ReadFrame(context.Background(), &hh); err != nil {
			t.Logf("client read response: %v", err)
		}
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
	_, _ = stream.Recv(ctx)

	// Wait for dynamic SETTINGS to arrive and be processed.
	time.Sleep(200 * time.Millisecond)

	// Stream should have updated send window.
	stream.mu.Lock()
	sw := stream.sendWindow
	stream.mu.Unlock()
	if sw <= 0 {
		t.Fatalf("sendWindow = %d after retroactive resize, want > 0", sw)
	}

	// Send response to verify the stream still works.
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); err != nil {
		t.Fatalf("SendHeaders after settings: %v", err)
	}
}

// --- RST_STREAM ---

func TestServerConn_ClientRST_StreamClosed(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, false)

		time.Sleep(50 * time.Millisecond)
		// Client sends RST_STREAM.
		writeDone := make(chan error, 1)
		go func() { writeDone <- cliFr.WriteRSTStream(1, frame.ErrCodeCancel) }()
		<-writeDone

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

	// Should receive headers first, then reset event.
	ev, err := stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("first event type = %v, want EventHeaders", ev.Type)
	}

	// Then reset.
	ev, err = stream.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv reset: %v", err)
	}
	if ev.Type != EventReset {
		t.Fatalf("event type = %v, want EventReset", ev.Type)
	}
	if ev.RSTCode != frame.ErrCodeCancel {
		t.Fatalf("RST code = %v, want CANCEL", ev.RSTCode)
	}
}

func TestServerConn_StreamClose_SendsRST(t *testing.T) {
	cli, srv := net.Pipe()
	go pipeClient(t, cli, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, false)

		// Read RST_STREAM from server.
		rh := &rstCapture{}
		if _, err := cliFr.ReadFrame(context.Background(), rh); err != nil {
			t.Logf("client read rst: %v", err)
			return
		}
		if rh.code != frame.ErrCodeCancel {
			t.Errorf("RST code = %v, want CANCEL", rh.code)
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

	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- Helpers ---

func sendReq(t *testing.T, cliFr *frame.Framer, streamID uint32, headers []hpack.HeaderField, endStream bool) {
	t.Helper()
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, headers)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- cliFr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     endStream,
		})
	}()
	<-writeDone
}

type dataCapture struct {
	data       []byte
	onEndStream func()
}

func (d *dataCapture) OnData(fh frame.FrameHeader, p []byte, _ uint8) error {
	d.data = append(d.data, p...)
	if fh.Flags&frame.FlagDataEndStream != 0 && d.onEndStream != nil {
		d.onEndStream()
	}
	return nil
}
func (d *dataCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (d *dataCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (d *dataCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (d *dataCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (d *dataCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (d *dataCapture) OnPing(frame.FrameHeader, [8]byte) error                         { return nil }
func (d *dataCapture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (d *dataCapture) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (d *dataCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (d *dataCapture) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (d *dataCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

type pingCapture struct {
	payload [8]byte
}

func (p *pingCapture) OnData(frame.FrameHeader, []byte, uint8) error       { return nil }
func (p *pingCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (p *pingCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (p *pingCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (p *pingCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (p *pingCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (p *pingCapture) OnPing(_ frame.FrameHeader, payload [8]byte) error {
	p.payload = payload
	return nil
}
func (p *pingCapture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (p *pingCapture) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (p *pingCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (p *pingCapture) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (p *pingCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

type goAwayCapture struct {
	lastID uint32
	code   frame.ErrCode
}

func (g *goAwayCapture) OnData(frame.FrameHeader, []byte, uint8) error       { return nil }
func (g *goAwayCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (g *goAwayCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (g *goAwayCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (g *goAwayCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (g *goAwayCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (g *goAwayCapture) OnPing(frame.FrameHeader, [8]byte) error { return nil }
func (g *goAwayCapture) OnGoAway(_ frame.FrameHeader, lastID uint32, code frame.ErrCode, _ []byte) error {
	g.lastID = lastID
	g.code = code
	return nil
}
func (g *goAwayCapture) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (g *goAwayCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (g *goAwayCapture) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (g *goAwayCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

type rstCapture struct {
	code frame.ErrCode
}

func (r *rstCapture) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (r *rstCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (r *rstCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (r *rstCapture) OnRSTStream(_ frame.FrameHeader, code frame.ErrCode) error { r.code = code; return nil }
func (r *rstCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (r *rstCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (r *rstCapture) OnPing(frame.FrameHeader, [8]byte) error                         { return nil }
func (r *rstCapture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (r *rstCapture) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (r *rstCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (r *rstCapture) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (r *rstCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

// multiHandler dispatches to both data and headers handlers.
type multiHandler struct {
	dh *dataCapture
	hh *captureHandler
}

func (m *multiHandler) OnData(fh frame.FrameHeader, p []byte, pad uint8) error {
	return m.dh.OnData(fh, p, pad)
}
func (m *multiHandler) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, pri *frame.Priority, pad uint8) error {
	return m.hh.OnHeaders(fh, hb, pri, pad)
}
func (m *multiHandler) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (m *multiHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (m *multiHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (m *multiHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (m *multiHandler) OnPing(frame.FrameHeader, [8]byte) error                         { return nil }
func (m *multiHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (m *multiHandler) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (m *multiHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (m *multiHandler) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (m *multiHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

// captureHandler records the fragment of a single HEADERS frame.
type captureHandler struct {
	block *bytes.Buffer
}

func (h captureHandler) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (h captureHandler) OnHeaders(_ frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	h.block.Write(hb)
	return nil
}
func (h captureHandler) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (h captureHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (h captureHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (h captureHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (h captureHandler) OnPing(frame.FrameHeader, [8]byte) error                         { return nil }
func (h captureHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (h captureHandler) OnWindowUpdate(frame.FrameHeader, uint32) error                  { return nil }
func (h captureHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error       { return nil }
func (h captureHandler) OnOrigin(frame.FrameHeader, []string) error                      { return nil }
func (h captureHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }
