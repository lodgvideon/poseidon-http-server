package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for connection and stream shutdown.
//
//	§6.8 (rfc9113.txt:2029) — "Endpoints MUST NOT increase the value they send in
//	the last stream identifier, since the peers might already have retried
//	unprocessed requests on another connection."
//
//	§6.8 (rfc9113.txt:1990) — "Receivers of a GOAWAY frame MUST NOT open
//	additional streams on the connection".
//
//	§5.4.2 (rfc9113.txt:1197) — "To avoid looping, an endpoint MUST NOT send a
//	RST_STREAM in response to a RST_STREAM frame."
//
//	§8.7 (rfc9113.txt:2977) — REFUSED_STREAM means "the stream is being closed
//	prior to any processing having occurred. Any request that was sent on the
//	reset stream can be safely retried."
//
//	§6.6 (rfc9113.txt:1899) — "PUSH_PROMISE frames MUST only be sent on a
//	peer-initiated stream that is in either the 'open' or 'half-closed (remote)'
//	state."

// goAwayLog records every GOAWAY, in order, with its last-stream-id.
type goAwayLog struct {
	fieldRSTCapture
	ids   []uint32
	codes []frame.ErrCode
}

func (g *goAwayLog) OnGoAway(_ frame.FrameHeader, lastID uint32, code frame.ErrCode, _ []byte) error {
	g.ids = append(g.ids, lastID)
	g.codes = append(g.codes, code)
	return nil
}

// TestConformance_RFC9113_Sec68_GracefulShutdownIsTwoPhase pins rfc9113.txt:2035
// and :2029 together, because the second only makes sense once the first holds.
//
//	:2035 — "A server that is attempting to gracefully shut down a connection
//	SHOULD send an initial GOAWAY frame with the last stream identifier set to
//	2^31-1 and a NO_ERROR code... After allowing time for any in-flight stream
//	creation (at least one round-trip time), the server can send another GOAWAY
//	frame with an updated last stream identifier."
//
// Announcing the real last-stream-id in one shot makes every stream the client
// still had in flight look unprocessed, so a conformant client replays requests
// this server was about to serve.
func TestConformance_RFC9113_Sec68_GracefulShutdownIsTwoPhase(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := &goAwayLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), true)
			for {
				if _, err := cliFr.ReadFrame(context.Background(), seen); err != nil {
					return
				}
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	if _, err := sc.AcceptStream(ctx); err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if err := sc.GoAwayGraceful(); err != nil {
		t.Fatalf("GoAwayGraceful: %v", err)
	}
	_ = sc.Close()
	<-done

	if len(seen.ids) < 2 {
		t.Fatalf("saw %d GOAWAY frames (%v), want the two phases of §6.8", len(seen.ids), seen.ids)
	}
	if seen.ids[0] != maxStreamID {
		t.Errorf("first GOAWAY last-stream-id = %d, want %d (2^31-1): the advance warning "+
			"must not yet claim any stream unprocessed", seen.ids[0], uint32(maxStreamID))
	}
	if seen.codes[0] != frame.ErrCodeNoError {
		t.Errorf("first GOAWAY code = %v, want NO_ERROR", seen.codes[0])
	}
	for i := 1; i < len(seen.ids); i++ {
		if seen.ids[i] > seen.ids[i-1] {
			t.Errorf("GOAWAY last-stream-id rose from %d to %d; §6.8 forbids increasing it, "+
				"because the peer may already have replayed the streams in between",
				seen.ids[i-1], seen.ids[i])
		}
	}
}

// TestConformance_RFC9113_Sec68_PushRefusedAfterPeerGoAway pins
// rfc9113.txt:1990. Server push is the only way a server opens a stream, so it
// is the only thing this rule can bind here.
func TestConformance_RFC9113_Sec68_PushRefusedAfterPeerGoAway(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sent := make(chan struct{})
	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			w := make(chan error, 1)
			go func() { w <- cliFr.WriteGoAway(1, frame.ErrCodeNoError, nil) }()
			<-w
			close(sent)
			for {
				if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
					return
				}
			}
		})
	}()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	<-sent
	// The GOAWAY is processed by the reader goroutine; give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	var pushErr error
	for time.Now().Before(deadline) {
		_, pushErr = stream.Push(ctx, goodHeaders("/asset.css"))
		if pushErr != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !errors.Is(pushErr, ErrPeerGoAway) {
		t.Errorf("Push after the client's GOAWAY returned %v, want ErrPeerGoAway; "+
			"§6.8 forbids opening further streams once the peer has announced shutdown", pushErr)
	}
}

// TestConformance_RFC9113_Sec66_PushPreconditions pins rfc9113.txt:1899 and the
// §8.4 requirement that a promise carry a complete, well-formed request.
func TestConformance_RFC9113_Sec66_PushPreconditions(t *testing.T) {
	withStream := func(t *testing.T, body func(*ServerStream, context.Context)) {
		t.Helper()
		cli, srv := net.Pipe()
		defer cli.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			pipeClient(t, cli, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, goodHeaders("/"), false)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
						return
					}
				}
			})
		}()
		sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
		if err != nil {
			t.Fatalf("NewServerConn: %v", err)
		}
		defer sc.Close()
		stream, err := sc.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("AcceptStream: %v", err)
		}
		body(stream, ctx)
	}

	t.Run("malformed_promise_is_refused", func(t *testing.T) {
		withStream(t, func(s *ServerStream, ctx context.Context) {
			// No :method — §8.3 requires exactly one, and §8.4 judges a promise by
			// the same rules as a request.
			_, err := s.Push(ctx, []hpack.HeaderField{
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/asset.css")},
			})
			if !errors.Is(err, ErrPushMalformedPromise) {
				t.Errorf("Push with an incomplete promise returned %v, want ErrPushMalformedPromise", err)
			}
		})
	})

	t.Run("push_from_a_pushed_stream_is_refused", func(t *testing.T) {
		withStream(t, func(s *ServerStream, ctx context.Context) {
			pushed, err := s.Push(ctx, goodHeaders("/asset.css"))
			if err != nil {
				t.Fatalf("first Push: %v", err)
			}
			// §6.6: a PUSH_PROMISE may only travel on a peer-initiated stream.
			_, err = pushed.Push(ctx, goodHeaders("/nested.css"))
			if !errors.Is(err, ErrPushOnServerStream) {
				t.Errorf("Push from a server-initiated stream returned %v, want ErrPushOnServerStream", err)
			}
		})
	})

	t.Run("well_formed_push_still_works", func(t *testing.T) {
		withStream(t, func(s *ServerStream, ctx context.Context) {
			if _, err := s.Push(ctx, goodHeaders("/asset.css")); err != nil {
				t.Errorf("a well-formed push was refused: %v", err)
			}
		})
	})
}

// TestConformance_RFC9113_Sec542_NoResetInResponseToReset pins rfc9113.txt:1197
// and, with it, §5.1's "An endpoint MUST NOT send frames other than PRIORITY on
// a closed stream" (:1082).
//
// A received RST_STREAM closes the stream in both directions. The server used to
// record only that the client's half had ended, so a handler reacting to the
// reset event — which is exactly what a handler is supposed to do — sent a
// second RST_STREAM back, the loop the rule exists to prevent.
func TestConformance_RFC9113_Sec542_NoResetInResponseToReset(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := &fieldRSTCapture{}
	rstCount := make(chan int, 1)
	done := make(chan struct{})
	// Closed once the application has taken delivery of stream 1. The reset must
	// not be written before that: as of #133 AcceptStream skips streams that were
	// reset while they sat in the accept queue, so a RST_STREAM racing the accept
	// decided whether a handler existed to react to it at all. The rule under
	// test is about what a HANDLER does on a reset, so the handler has to have the
	// stream first. No assertion below changed.
	accepted := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			select {
			case <-accepted:
			case <-time.After(5 * time.Second):
				t.Error("server never accepted stream 1")
				return
			}
			w := make(chan error, 1)
			go func() { w <- cliFr.WriteRSTStream(1, frame.ErrCodeCancel) }()
			<-w
			n := 0
			counter := &rstCounter{n: &n, inner: seen}
			deadline := time.Now().Add(700 * time.Millisecond)
			for time.Now().Before(deadline) {
				_ = cli.SetReadDeadline(deadline)
				if _, err := cliFr.ReadFrame(context.Background(), counter); err != nil {
					break
				}
			}
			rstCount <- n
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		close(accepted)
		t.Fatalf("AcceptStream: %v", err)
	}
	close(accepted)
	// Drain until the reset arrives, then do what a handler does on a reset.
	for {
		ev, rerr := stream.Recv(ctx)
		if rerr != nil {
			break
		}
		if ev.Type == EventReset {
			break
		}
	}
	if cerr := stream.Close(); cerr != nil {
		t.Errorf("Close after a peer reset returned %v; the stream is already closed", cerr)
	}
	// Writing must be refused too — §5.1 permits nothing but PRIORITY.
	if werr := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, true); !errors.Is(werr, ErrStreamClosed) {
		t.Errorf("SendHeaders after a peer reset returned %v, want ErrStreamClosed", werr)
	}

	select {
	case n := <-rstCount:
		if n != 0 {
			t.Errorf("server sent %d RST_STREAM frames in response to the client's RST_STREAM; "+
				"§5.4.2 forbids answering a reset with a reset", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
	}
	<-done
}

// rstCounter counts RST_STREAM frames and forwards everything to inner.
type rstCounter struct {
	n     *int
	inner *fieldRSTCapture
}

func (c *rstCounter) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	*c.n++
	return c.inner.OnRSTStream(fh, code)
}
func (c *rstCounter) OnGoAway(fh frame.FrameHeader, id uint32, code frame.ErrCode, d []byte) error {
	return c.inner.OnGoAway(fh, id, code, d)
}
func (c *rstCounter) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (c *rstCounter) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (c *rstCounter) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (c *rstCounter) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (c *rstCounter) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (c *rstCounter) OnPing(frame.FrameHeader, [8]byte) error                   { return nil }
func (c *rstCounter) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (c *rstCounter) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (c *rstCounter) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (c *rstCounter) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }
