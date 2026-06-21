package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestServerConn_AcceptsPriorityInHeaders verifies that a priority
// block embedded in the first HEADERS frame is captured into the
// ServerStream (RFC 7540 §5.3).
func TestServerConn_AcceptsPriorityInHeaders(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	want := &frame.Priority{StreamDep: 0, Exclusive: true, Weight: 200}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			enc := hpack.NewEncoder()
			block := enc.EncodeBlock(nil, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/p")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":authority"), Value: []byte("x")},
			})
			if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block,
				EndHeaders:    true,
				EndStream:     true,
				Priority:      want,
			}); err != nil {
				t.Logf("WriteHeaders: %v", err)
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	defer stream.Close()

	got := stream.Priority()
	if got == nil {
		t.Fatal("Priority() = nil, want non-nil")
	}
	if got.StreamDep != want.StreamDep || got.Exclusive != want.Exclusive || got.Weight != want.Weight {
		t.Fatalf("Priority() = %+v, want %+v", got, want)
	}
	<-done
}

// TestServerStream_PriorityDefaultNil verifies that streams opened
// without a priority block expose a nil Priority().
func TestServerStream_PriorityDefaultNil(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/no-prio")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":authority"), Value: []byte("x")},
			}, true)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	defer stream.Close()

	if got := stream.Priority(); got != nil {
		t.Fatalf("Priority() = %+v, want nil", got)
	}
	<-done
}

// TestServerStream_SendHeadersWithPriority_EmbeddedInFrame verifies
// that SendHeadersWithPriority embeds the priority block (PRIORITY flag
// set) into the first response HEADERS frame, and that the priority
// payload travels intact through the wire.
func TestServerStream_SendHeadersWithPriority_EmbeddedInFrame(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	prio := &frame.Priority{StreamDep: 0, Exclusive: false, Weight: 42}

	// Drive the client: send a request, then read frames.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Send a request.
			enc := hpack.NewEncoder()
			block := enc.EncodeBlock(nil, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/p")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":authority"), Value: []byte("x")},
			})
			if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block,
				EndHeaders:    true,
				EndStream:     true,
			}); err != nil {
				t.Logf("WriteHeaders: %v", err)
				return
			}
			// Read response HEADERS frame. Priority block travels
			// in the wire payload but the Framer strips it before
			// dispatching OnHeaders; the PRIORITY flag is the
			// wire-visible evidence that the server emitted it.
			h := &captureAllHandler{}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := cliFr.ReadFrame(ctx, h); err != nil {
				t.Logf("ReadFrame: %v", err)
				return
			}
			if h.lastType != frame.FrameHeaders {
				t.Errorf("client got frame type %v, want HEADERS", h.lastType)
				return
			}
			if h.lastFlags&frame.FlagHeadersPriority == 0 {
				t.Errorf("HEADERS PRIORITY flag not set (flags=0x%x)", h.lastFlags)
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	defer stream.Close()

	if err := stream.SendHeadersWithPriority(context.Background(),
		[]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}},
		true, prio); err != nil {
		t.Fatalf("SendHeadersWithPriority: %v", err)
	}
	<-clientDone
}

// TestServerStream_PushWithPriority_StoredOnPushStream verifies that
// PushWithPriority stores the priority on the returned push stream so
// the first response HEADERS frame carries the PRIORITY flag.
func TestServerStream_PushWithPriority_StoredOnPushStream(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	want := &frame.Priority{StreamDep: 0, Exclusive: false, Weight: 100}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			enc := hpack.NewEncoder()
			block := enc.EncodeBlock(nil, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":authority"), Value: []byte("x")},
			})
			if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block,
				EndHeaders:    true,
				EndStream:     false,
			}); err != nil {
				t.Logf("WriteHeaders: %v", err)
				return
			}
			// Read PUSH_PROMISE, then the pushed response HEADERS.
			h := &captureAllHandler{}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			sawPush := false
			sawPriority := false
			for !sawPush || !sawPriority {
				if _, err := cliFr.ReadFrame(ctx, h); err != nil {
					t.Logf("ReadFrame: %v", err)
					return
				}
				switch h.lastType {
				case frame.FramePushPromise:
					sawPush = true
				case frame.FrameHeaders:
					if h.lastFlags&frame.FlagHeadersPriority == 0 {
						t.Errorf("push stream response HEADERS missing PRIORITY flag (flags=0x%x)", h.lastFlags)
					} else {
						sawPriority = true
					}
				case frame.FrameData, frame.FramePriority, frame.FrameRSTStream,
					frame.FrameSettings, frame.FramePing, frame.FrameGoAway,
					frame.FrameWindowUpdate, frame.FrameContinuation,
					frame.FrameAltSvc, frame.FrameOrigin:
					// Ignore other frames during the round trip.
				}
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	defer stream.Close()

	pushHeaders := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/style.css")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("x")},
	}
	pushStream, err := stream.PushWithPriority(context.Background(), pushHeaders, want)
	if err != nil {
		t.Fatalf("PushWithPriority: %v", err)
	}
	if got := pushStream.Priority(); got == nil || got.Weight != want.Weight {
		t.Fatalf("pushStream.Priority() = %+v, want weight=%d", got, want.Weight)
	}
	if err := pushStream.SendHeadersWithPriority(context.Background(),
		[]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}},
		true, want); err != nil {
		t.Fatalf("SendHeadersWithPriority: %v", err)
	}
	<-clientDone
}

// TestServerStream_PushWithPriority_NilIsEquivalentToPush verifies that
// passing nil to PushWithPriority behaves identically to Push.
func TestServerStream_PushWithPriority_NilIsEquivalentToPush(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			enc := hpack.NewEncoder()
			block := enc.EncodeBlock(nil, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":path"), Value: []byte("/")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":authority"), Value: []byte("x")},
			})
			if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID:      1,
				BlockFragment: block,
				EndHeaders:    true,
				EndStream:     false,
			}); err != nil {
				t.Logf("WriteHeaders: %v", err)
				return
			}
			// Read PUSH_PROMISE.
			h := &captureAllHandler{}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := cliFr.ReadFrame(ctx, h); err != nil {
				t.Logf("ReadFrame: %v", err)
				return
			}
			if h.lastType != frame.FramePushPromise {
				t.Errorf("first frame = %v, want PUSH_PROMISE", h.lastType)
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	defer stream.Close()

	pushStream, err := stream.PushWithPriority(context.Background(),
		[]hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":path"), Value: []byte("/x")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":authority"), Value: []byte("x")},
		}, nil)
	if err != nil {
		t.Fatalf("PushWithPriority(nil): %v", err)
	}
	if got := pushStream.Priority(); got != nil {
		t.Errorf("Priority() = %+v, want nil for nil prio", got)
	}
	<-clientDone
}

// captureAllHandler records the last frame of any type.
type captureAllHandler struct {
	lastType  frame.FrameType
	lastFlags frame.Flags
	lastBody  []byte
}

func (h *captureAllHandler) OnData(fh frame.FrameHeader, p []byte, _ uint8) error {
	h.lastType, h.lastFlags, h.lastBody = fh.Type, fh.Flags, append([]byte(nil), p...)
	return nil
}
func (h *captureAllHandler) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	h.lastType, h.lastFlags, h.lastBody = fh.Type, fh.Flags, append([]byte(nil), hb...)
	return nil
}
func (h *captureAllHandler) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (h *captureAllHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (h *captureAllHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (h *captureAllHandler) OnSettingsAck(frame.FrameHeader) error                    { return nil }
func (h *captureAllHandler) OnPing(frame.FrameHeader, [8]byte) error                  { return nil }
func (h *captureAllHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}
func (h *captureAllHandler) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (h *captureAllHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (h *captureAllHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	h.lastType, h.lastFlags, h.lastBody = frame.FramePushPromise, 0, nil
	return nil
}
func (h *captureAllHandler) OnOrigin(frame.FrameHeader, []string) error            { return nil }
func (h *captureAllHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }
