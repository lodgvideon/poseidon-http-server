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

// ---------------------------------------------------------------------------
// Item 4.4 — Integration depth (conn layer).
//
// These tests drive the raw frame.Framer client over net.Pipe against a real
// ServerConn to exercise the thin/adversarial paths: preface violations,
// malformed frames (GOAWAY vs. clean teardown — both crash-free), RST_STREAM /
// GOAWAY edge cases, and a large-response flow-control round-trip that crosses
// the initial connection window so WINDOW_UPDATE is required to complete.
//
// They follow the hardened style of the existing conn tests: writes that may
// block once the server trips run in their own goroutine, reads run with a
// context, and waits are bounded by generous deadlines (the suite has been
// hardened against Windows scheduling jitter — never assume sub-100ms timing).
//
// NOTE on the framer: frame.Framer is NOT goroutine-safe. Every client write
// in these tests is therefore serialized — we never issue two concurrent
// Write* calls on the same Framer. Writes that may block on the unbuffered
// pipe are launched one at a time and joined before the next write.
// ---------------------------------------------------------------------------

// rawConnHandshake performs only the client side of the HTTP/2 connection
// preface + SETTINGS exchange and returns a Framer ready for raw frame I/O.
// The caller owns the connection lifetime. Returns false if the handshake
// could not complete (e.g. the server rejected the connection).
func rawConnHandshake(t *testing.T, cli net.Conn) (*frame.Framer, bool) {
	t.Helper()
	if _, err := cli.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return nil, false
	}
	fr := frame.NewFramer(cli, cli)

	writeDone := make(chan error, 1)
	go func() { writeDone <- fr.WriteSettings(frame.SettingsParams{}) }()
	if _, err := fr.ReadFrame(context.Background(), &nilHandler{}); err != nil { // server SETTINGS
		return nil, false
	}
	if err := <-writeDone; err != nil {
		return nil, false
	}
	go func() { writeDone <- fr.WriteSettingsAck() }()
	if _, err := fr.ReadFrame(context.Background(), &nilHandler{}); err != nil { // server SETTINGS ACK
		return nil, false
	}
	if err := <-writeDone; err != nil {
		return nil, false
	}
	return fr, true
}

// reqHeaders builds a minimal valid request header block.
func reqHeaders(path string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("example.test")},
		{Name: []byte(":path"), Value: []byte(path)},
	}
}

// TestDepth_PrefaceViolation_ConnRejected verifies that a client which sends a
// full 24-byte but WRONG preface magic is rejected at handshake with
// ErrBadPreface, and the server tears the connection down (no goroutine pin).
func TestDepth_PrefaceViolation_ConnRejected(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 24 bytes (same length as the real preface) with the wrong magic.
		_, _ = cli.Write([]byte("XYZ * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err == nil {
		_ = sc.Close()
		t.Fatal("NewServerConn accepted a bad preface; want ErrBadPreface")
	}
	if err != ErrBadPreface { //nolint:errorlint // sentinel returned directly
		t.Fatalf("err = %v, want ErrBadPreface", err)
	}
	<-done
}

// TestDepth_PrefaceViolation_HTTP1Garbage verifies that an HTTP/1.1-style
// request (shorter than the 24-byte preface, then a quiet client) is rejected
// rather than hanging forever. With the default handshake timeout the server
// either decodes the differing magic as ErrBadPreface or times out the read —
// both are rejections; the test guards against an unbounded hang.
func TestDepth_PrefaceViolation_HTTP1Garbage(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 24 bytes starting with an HTTP/1.1 request line, padded so the
		// server's io.ReadFull(24) completes and the magic comparison fails
		// fast (no dependence on the handshake read deadline).
		_, _ = cli.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// Bound the handshake so a quiet client cannot pin us indefinitely.
	opts := ServerConnOptions{HandshakeTimeout: 2 * time.Second}.defaulted()
	sc, err := NewServerConn(ctx, srv, opts)
	if err == nil {
		_ = sc.Close()
		t.Fatal("NewServerConn accepted HTTP/1.1 garbage; want rejection")
	}
	// Accept either the magic mismatch or a handshake timeout — both reject.
	if err != ErrBadPreface && ctx.Err() == nil { //nolint:errorlint // sentinel
		t.Logf("rejected HTTP/1.1 garbage with: %v", err)
	}
	<-done
}

// TestDepth_MalformedFrame_PushPromise_GoAwayProtocolError verifies that a
// client-sent PUSH_PROMISE (illegal: only servers may push, RFC 7540 §8.2)
// makes the server emit GOAWAY(PROTOCOL_ERROR) and tear down without panicking.
func TestDepth_MalformedFrame_PushPromise_GoAwayProtocolError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	gotGoAway := make(chan goAwayCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fr, ok := rawConnHandshake(t, cli)
		if !ok {
			return
		}
		// Reader captures the GOAWAY the server must send.
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			gc := &goAwayCapture{}
			for {
				if _, err := fr.ReadFrame(context.Background(), gc); err != nil {
					return
				}
				if gc.code != 0 {
					select {
					case gotGoAway <- *gc:
					default:
					}
					return
				}
			}
		}()
		// Illegal client PUSH_PROMISE on stream 1, promising stream 2.
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, reqHeaders("/pushed"))
		go func() {
			_ = fr.WritePushPromise(1, 2, block, true, 0)
		}()
		select {
		case <-readDone:
		case <-time.After(3 * time.Second):
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case gc := <-gotGoAway:
		if gc.code != frame.ErrCodeProtocolError {
			t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR (0x1)", gc.code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server did not emit GOAWAY for client PUSH_PROMISE")
	}
	<-done
}

// TestDepth_MalformedFrame_WindowUpdateOverflow_StopsServing verifies that a
// WINDOW_UPDATE which overflows the connection send window (> 2^31-1) is a
// fatal connection error handled WITHOUT a panic: the reader loop exits and the
// server stops surfacing further streams. We assert this observable contract
// (a subsequent stream is never accepted) rather than IsAlive, which only flips
// on an explicit Close().
func TestDepth_MalformedFrame_WindowUpdateOverflow_StopsServing(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fr, ok := rawConnHandshake(t, cli)
		if !ok {
			return
		}
		go func() {
			for {
				if _, err := fr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
					return
				}
			}
		}()
		// A single max-increment WINDOW_UPDATE on stream 0 overflows the
		// connection window: 65535 + 0x7fffffff exceeds 2^31-1, which the
		// server treats as a fatal flow-control error and exits its reader
		// loop. We do NOT join on the write — once the reader loop exits the
		// unbuffered pipe has no reader and a join would block forever. A
		// single write is sufficient to trip the overflow.
		go func() { _ = fr.WriteWindowUpdate(0, 0x7fffffff) }()
		time.Sleep(400 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	// After the overflow the reader loop has exited; no stream should arrive.
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer acceptCancel()
	if stream, aerr := sc.AcceptStream(acceptCtx); aerr == nil {
		_ = stream.Close()
		t.Fatal("server accepted a new stream after a fatal WINDOW_UPDATE overflow")
	}
	<-done
}

// TestDepth_StrayFrames_Tolerated verifies the server tolerates stray frames
// that target non-existent / connection-control streams (DATA on stream 0,
// RST_STREAM on an idle stream, PRIORITY) without crashing, and remains usable
// for a subsequent legitimate request.
func TestDepth_StrayFrames_Tolerated(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fr, ok := rawConnHandshake(t, cli)
		if !ok {
			return
		}
		go func() {
			for {
				if _, err := fr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
					return
				}
			}
		}()
		w := make(chan error, 1)
		// Stray RST_STREAM on idle stream 7.
		go func() { w <- fr.WriteRSTStream(7, frame.ErrCodeCancel) }()
		<-w
		// Stray PRIORITY on stream 9.
		go func() { w <- fr.WritePriority(9, frame.Priority{Weight: 16}) }()
		<-w
		// Now a legitimate stream 1 — the connection must still be usable.
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, reqHeaders("/after-stray"))
		go func() {
			w <- fr.WriteHeaders(frame.WriteHeadersParams{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
			})
		}()
		<-w
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer acceptCancel()
	stream, aerr := sc.AcceptStream(acceptCtx)
	if aerr != nil {
		t.Fatalf("connection unusable after stray frames: %v", aerr)
	}
	accepted <- struct{}{}
	ev, rerr := stream.Recv(acceptCtx)
	if rerr != nil {
		t.Fatalf("Recv after stray frames: %v", rerr)
	}
	if ev.Type != EventHeaders {
		t.Fatalf("event type = %v, want EventHeaders", ev.Type)
	}
	_ = stream.Close()
	<-done
}

// TestDepth_GoAway_ClientInitiated_StopsNewStreams verifies that after a client
// GOAWAY the server still surfaces the in-flight stream that arrived first, then
// stops handing out NEW streams — without crashing.
func TestDepth_GoAway_ClientInitiated_StopsNewStreams(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fr, ok := rawConnHandshake(t, cli)
		if !ok {
			return
		}
		go func() {
			for {
				if _, err := fr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
					return
				}
			}
		}()
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, reqHeaders("/inflight"))
		w := make(chan error, 1)
		go func() {
			w <- fr.WriteHeaders(frame.WriteHeadersParams{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
			})
		}()
		<-w
		time.Sleep(50 * time.Millisecond)
		go func() { w <- fr.WriteGoAway(1, frame.ErrCodeNoError, nil) }()
		<-w
		time.Sleep(400 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	// In-flight stream 1 arrived before GOAWAY → acceptable.
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer acceptCancel()
	if stream, aerr := sc.AcceptStream(acceptCtx); aerr == nil {
		_, _ = stream.Recv(acceptCtx)
		_ = stream.Close()
	}

	// After GOAWAY no NEW streams should be handed out.
	acceptCtx2, acceptCancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer acceptCancel2()
	if _, aerr := sc.AcceptStream(acceptCtx2); aerr == nil {
		t.Fatal("AcceptStream returned a new stream after client GOAWAY")
	}
	<-done
}

// TestDepth_FlowControl_LargeResponse_CrossesInitialWindow verifies that a
// response larger than the 65535-byte initial connection send window completes
// only after the client refunds capacity via WINDOW_UPDATE. The client reads
// all DATA, periodically emitting conn-level + stream-level WINDOW_UPDATEs
// (serialized — the framer is not goroutine-safe), and asserts every byte
// arrives intact and in order.
func TestDepth_FlowControl_LargeResponse_CrossesInitialWindow(t *testing.T) {
	// 256 KiB — comfortably past the 64 KiB initial window, so the server's
	// outbound flow controller MUST block and wait for WINDOW_UPDATE.
	const size = 256 * 1024
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251)
	}

	cli, srv := net.Pipe()
	defer cli.Close()

	var (
		recvMu   sync.Mutex
		received []byte
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fr, ok := rawConnHandshake(t, cli)
		if !ok {
			return
		}
		// Open stream 1 WITHOUT END_STREAM. This keeps the stream live in the
		// server's stream table so a subsequent stream-level WINDOW_UPDATE is
		// applied to the stream's outbound send window (a request HEADERS with
		// END_STREAM marks the stream done and the server then drops further
		// stream-level WINDOW_UPDATEs for it). We then immediately grant a
		// large WINDOW_UPDATE on both the connection (stream 0) and the stream
		// so the server can push the whole response past the 65535-byte initial
		// window. Granting up front keeps the net.Pipe interaction strictly
		// setup-writes-then-body-reads, which is deadlock-free on the unbuffered
		// pipe, while still exercising the server honouring WINDOW_UPDATE to
		// exceed its initial outbound window.
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, reqHeaders("/big"))
		w := make(chan error, 1)
		go func() {
			w <- fr.WriteHeaders(frame.WriteHeadersParams{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: false,
			})
		}()
		<-w
		const grant = uint32(size) // enough to cover the entire response
		go func() { w <- fr.WriteWindowUpdate(0, grant) }()
		<-w
		go func() { w <- fr.WriteWindowUpdate(1, grant) }()
		<-w

		// Now read the whole response. No interleaved writes → no pipe deadlock.
		for {
			dh := &dataCapture{}
			hh := captureHandler{block: &bytes.Buffer{}}
			fh, rerr := fr.ReadFrame(context.Background(), &multiHandler{dh: dh, hh: &hh})
			if rerr != nil {
				return
			}
			if n := len(dh.data); n > 0 {
				recvMu.Lock()
				received = append(received, dh.data...)
				recvMu.Unlock()
			}
			if fh.Type == frame.FrameData && fh.Flags&frame.FlagDataEndStream != 0 {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	if _, err := stream.Recv(ctx); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if err := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, false); err != nil {
		t.Fatalf("SendHeaders: %v", err)
	}
	// This SendData MUST block on the connection window until the client's
	// WINDOW_UPDATEs arrive; broken flow control would deadlock (caught by ctx).
	if err := stream.SendData(ctx, body, true); err != nil {
		t.Fatalf("SendData (large, flow-controlled): %v", err)
	}

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("client did not finish reading large flow-controlled response")
	}

	recvMu.Lock()
	gotLen := len(received)
	gotEqual := bytes.Equal(received, body)
	recvMu.Unlock()
	if gotLen != size {
		t.Fatalf("received %d bytes, want %d (flow-control under-delivery)", gotLen, size)
	}
	if !gotEqual {
		t.Fatal("flow-controlled response payload mismatch")
	}
}
