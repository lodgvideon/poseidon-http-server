package conn

import (
	"context"
	"sync"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ServerStream is a single server-side HTTP/2 stream.
// Single-goroutine: the handler owns the stream after AcceptStream.
type ServerStream struct {
	id     uint32
	sc     *ServerConn
	events chan StreamEvent

	mu            sync.Mutex
	localEnded    bool
	remoteEnded   bool
	closed        bool
	headersSent   bool
	headersReceived bool

	// Flow control.
	recvWindow         int32
	recvRefundPending  uint32
	sendWindow         int32
}

// StreamEventType discriminates the StreamEvent variants.
type StreamEventType uint8

const (
	EventHeaders  StreamEventType = iota + 1
	EventData
	EventTrailers
	EventReset
)

// String returns the name of t.
func (t StreamEventType) String() string {
	switch t {
	case EventHeaders:
		return "headers"
	case EventData:
		return "data"
	case EventTrailers:
		return "trailers"
	case EventReset:
		return "reset"
	default:
		return "unknown"
	}
}

// StreamEvent is one observation about an in-flight stream.
type StreamEvent struct {
	Type      StreamEventType
	Headers   []hpack.HeaderField
	Data      []byte
	EndStream bool
	RSTCode   frame.ErrCode
	Slab      *[]byte
}

// ID returns the HTTP/2 stream identifier.
func (ss *ServerStream) ID() uint32 { return ss.id }

// SendHeaders sends a response HEADERS frame with the given fields.
// The first call on a stream seeds the per-stream send window from
// the peer's SETTINGS_INITIAL_WINDOW_SIZE. Always sets END_HEADERS.
func (ss *ServerStream) SendHeaders(ctx context.Context, fields []hpack.HeaderField, endStream bool) error {
	ss.mu.Lock()
	if ss.closed || ss.localEnded {
		ss.mu.Unlock()
		return ErrStreamClosed
	}
	ss.mu.Unlock()
	if err := ss.sc.writeServerHeaders(ctx, ss, fields, endStream); err != nil {
		return err
	}
	ss.mu.Lock()
	ss.headersSent = true
	if endStream {
		ss.localEnded = true
	}
	ss.mu.Unlock()
	if endStream {
		ss.sc.markStreamDone(ss.id)
	}
	return nil
}

// SendData sends a DATA frame, automatically chunking to the peer's
// MAX_FRAME_SIZE and respecting both per-stream and connection-level
// outbound flow control (RFC 7540 §6.9). Blocks until enough send-window
// credit is available.
func (ss *ServerStream) SendData(ctx context.Context, p []byte, endStream bool) error {
	ss.mu.Lock()
	if ss.closed || ss.localEnded {
		ss.mu.Unlock()
		return ErrStreamClosed
	}
	ss.mu.Unlock()
	if err := ss.sc.writeServerData(ctx, ss, p, endStream); err != nil {
		return err
	}
	if endStream {
		ss.mu.Lock()
		ss.localEnded = true
		ss.mu.Unlock()
		ss.sc.markStreamDone(ss.id)
	}
	return nil
}

// Recv blocks until the next event is ready.
func (ss *ServerStream) Recv(ctx context.Context) (StreamEvent, error) {
	select {
	case e, ok := <-ss.events:
		if !ok {
			return StreamEvent{}, ErrStreamClosed
		}
		return e, nil
	case <-ctx.Done():
		return StreamEvent{}, ctx.Err()
	}
}

// Close sends RST_STREAM(CANCEL) if neither side has ended. Idempotent.
func (ss *ServerStream) Close() error {
	ss.mu.Lock()
	already := ss.closed
	bothEnded := ss.localEnded && ss.remoteEnded
	ss.closed = true
	ss.mu.Unlock()
	if already {
		return nil
	}
	if bothEnded {
		return nil
	}
	return ss.sc.writeServerRSTStream(ss, frame.ErrCodeCancel)
}

// markRemoteEnd marks the remote side as closed.
func (ss *ServerStream) markRemoteEnd() {
	ss.mu.Lock()
	ss.remoteEnded = true
	ss.mu.Unlock()
}

// push delivers an event from the reader goroutine. Non-blocking;
// on overflow marks stream closed and sends RST.
func (ss *ServerStream) push(e StreamEvent) {
	select {
	case ss.events <- e:
		return
	default:
	}
	ss.mu.Lock()
	already := ss.closed
	ss.closed = true
	ss.mu.Unlock()
	if already {
		return
	}
	go func() {
		_ = ss.sc.writeServerRSTStream(ss, frame.ErrCodeRefusedStream)
	}()
	select {
	case ss.events <- StreamEvent{Type: EventReset, RSTCode: frame.ErrCodeRefusedStream, EndStream: true}:
	default:
	}
}

func newServerStream(id uint32, eventBuf int, sc *ServerConn, recvWindow int32) *ServerStream {
	return &ServerStream{
		id:         id,
		sc:         sc,
		events:     make(chan StreamEvent, eventBuf),
		recvWindow: recvWindow,
	}
}
