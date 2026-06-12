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

	mu           sync.Mutex
	localEnded   bool
	remoteEnded  bool
	closed       bool
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

// Close sends RST_STREAM if the stream is still open. Idempotent.
func (ss *ServerStream) Close() error {
	ss.mu.Lock()
	already := ss.closed
	ss.closed = true
	ss.mu.Unlock()
	if already {
		return nil
	}
	// TODO: send RST_STREAM if needed (A.2).
	return nil
}

// markRemoteEnd marks the remote side as closed.
func (ss *ServerStream) markRemoteEnd() {
	ss.mu.Lock()
	ss.remoteEnded = true
	ss.mu.Unlock()
}

// push delivers an event from the reader goroutine.
func (ss *ServerStream) push(e StreamEvent) {
	select {
	case ss.events <- e:
		return
	default:
		// Channel full — drop and mark closed.
		ss.mu.Lock()
		ss.closed = true
		ss.mu.Unlock()
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
