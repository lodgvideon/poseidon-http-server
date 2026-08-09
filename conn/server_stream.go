package conn

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ServerStream is a single server-side HTTP/2 stream.
// Single-goroutine: the handler owns the stream after AcceptStream.
type ServerStream struct {
	id     uint32
	sc     *ServerConn
	events chan StreamEvent

	// ctx is cancelled when the stream is reset by the client, completes, or its
	// connection closes. Set by registerStream; nil for unregistered or pushed
	// streams (Context() then falls back to context.Background()).
	ctx    context.Context
	cancel context.CancelFunc

	// st is the RFC §5.1 state, packed. It replaced five booleans; see
	// conn/stream_state.go for why none of them is separately settable.
	st atomic.Uint32

	mu sync.Mutex
	// priority stores the RFC 7540 §5.3 priority payload received in
	// the first HEADERS frame (or set by PushWithPriority), if any.
	// nil if no priority was specified. Accessed atomically: written
	// once by the reader goroutine (OnHeaders or PushWithPriority),
	// read by handler goroutines.
	priority atomic.Pointer[frame.Priority]

	// Flow control.
	recvWindow        int32
	recvRefundPending uint32
	sendWindow        int32
}

// Priority returns the RFC 7540 §5.3 priority payload extracted from
// the request's first HEADERS frame, or nil if the client did not
// include a priority block. Useful for handlers that want to propagate
// the client's priority hint into the response HEADERS, or into a
// server-pushed PUSH_PROMISE.
func (ss *ServerStream) Priority() *frame.Priority { return ss.priority.Load() }

// setPriority stores the request's priority payload. Called by
// serverConnHandler.OnHeaders exactly once, on the first HEADERS frame
// of the stream, or by PushWithPriority for pushed streams.
func (ss *ServerStream) setPriority(p *frame.Priority) {
	if p == nil {
		return
	}
	ss.priority.Store(p)
}

// StreamEventType discriminates the StreamEvent variants.
type StreamEventType uint8

const (
	EventHeaders StreamEventType = iota + 1
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
}

// ID returns the HTTP/2 stream identifier.
func (ss *ServerStream) ID() uint32 { return ss.id }

// Context returns a context that is cancelled when the stream is reset by the
// client (RST_STREAM), completes, or the underlying connection closes. Handlers
// should select on its Done channel (or pass it to blocking calls) to abort
// work promptly when the client goes away. It is never nil and is safe to call
// on a nil stream (returns a background context) so constructors that tolerate
// a nil stream — e.g. server.NewResponseWriter(nil) in tests — do not panic.
func (ss *ServerStream) Context() context.Context {
	if ss == nil || ss.ctx == nil {
		return context.Background()
	}
	return ss.ctx
}

// SendHeaders sends a response HEADERS frame with the given fields.
// The first call on a stream seeds the per-stream send window from
// the peer's SETTINGS_INITIAL_WINDOW_SIZE. Always sets END_HEADERS.
func (ss *ServerStream) SendHeaders(ctx context.Context, fields []hpack.HeaderField, endStream bool) error {
	return ss.SendHeadersWithPriority(ctx, fields, endStream, nil)
}

// SendHeadersWithPriority is like SendHeaders but embeds an RFC 7540
// §5.3 priority block (E + StreamDep + Weight) into the first HEADERS
// frame via the PRIORITY flag. Pass nil to omit the priority block
// (equivalent to SendHeaders).
func (ss *ServerStream) SendHeadersWithPriority(ctx context.Context, fields []hpack.HeaderField, endStream bool, prio *frame.Priority) error {
	if !ss.state().Writable() {
		return ErrStreamClosed
	}
	if err := ss.sc.writeServerHeaders(ctx, ss, fields, endStream, prio); err != nil {
		return err
	}
	ss.advance(stSentFields)
	if endStream && ss.markLocalEnd() {
		// Fully closed (both halves ended): release the stream.
		ss.sc.markStreamDone(ss.id)
	}
	return nil
}

// SendData sends a DATA frame, automatically chunking to the peer's
// MAX_FRAME_SIZE and respecting both per-stream and connection-level
// outbound flow control (RFC 7540 §6.9). Blocks until enough send-window
// credit is available.
func (ss *ServerStream) SendData(ctx context.Context, p []byte, endStream bool) error {
	if !ss.state().Writable() {
		return ErrStreamClosed
	}
	if err := ss.sc.writeServerData(ctx, ss, p, endStream); err != nil {
		return err
	}
	if endStream && ss.markLocalEnd() {
		// Fully closed (both halves ended): release the stream.
		ss.sc.markStreamDone(ss.id)
	}
	return nil
}

// Recv blocks until the next event is ready. A buffered event is always returned
// in preference to context cancellation, so a final event delivered in the same
// step as the stream's completion or reset (markStreamDone cancels the context)
// is never dropped.
func (ss *ServerStream) Recv(ctx context.Context) (StreamEvent, error) {
	select {
	case e, ok := <-ss.events:
		if !ok {
			return StreamEvent{}, ErrStreamClosed
		}
		ss.creditConsumed(e)
		return e, nil
	default:
	}
	select {
	case e, ok := <-ss.events:
		if !ok {
			return StreamEvent{}, ErrStreamClosed
		}
		ss.creditConsumed(e)
		return e, nil
	case <-ctx.Done():
		return StreamEvent{}, ctx.Err()
	}
}

// creditConsumed returns per-stream flow-control credit for body bytes the
// application has now taken delivery of, emitting a WINDOW_UPDATE once enough
// has accumulated to be worth a frame.
//
// Refunding on CONSUMPTION rather than on receipt is what makes
// SETTINGS_INITIAL_WINDOW_SIZE mean what it advertises. Refunding the moment a
// DATA frame arrived handed the peer fresh credit for bytes that were only
// buffered, so the window bounded nothing and a fast uploader could outrun a
// briefly descheduled handler until the per-stream event channel overflowed and
// the stream was reset. RFC 9113 §5.2.1 (rfc9113.txt:1274) is explicit that this
// is what the window is for: "The sender of a flow-controlled frame MUST NOT
// send more than the receiver allows", and a receiver that always allows more
// has opted out of the mechanism.
//
// Called on the handler goroutine, which already writes under wmu elsewhere.
// The connection-level window keeps its receipt-time refund: §6.9.1 requires
// every flow-controlled frame be counted there whatever becomes of its stream,
// and gating it on one application's reading would let a single slow handler
// wedge every other stream on the connection.
func (ss *ServerStream) creditConsumed(e StreamEvent) {
	if ss.sc == nil || e.Type != EventData || len(e.Data) == 0 {
		return
	}
	ss.mu.Lock()
	ss.recvRefundPending += uint32(len(e.Data)) //nolint:gosec // G115: frame length ≤ 2^24 per RFC
	refund := uint32(0)
	if ss.recvRefundPending >= recvWindowRefundThreshold {
		refund = ss.recvRefundPending
		ss.recvRefundPending = 0
		ss.recvWindow += int32(refund) //nolint:gosec // G115: refund ≤ the window it came from
	}
	ss.mu.Unlock()
	if refund > 0 && !ss.state().WasReset() {
		_ = ss.sc.writeWindowUpdate(ss.id, refund)
	}
}

// Close sends RST_STREAM(CANCEL) if neither side has ended. Idempotent.
func (ss *ServerStream) Close() error {
	// One transition answers both questions: was this already closed, and had both
	// halves ended. Reading them separately is what let a reset land between the
	// two and draw a second RST_STREAM.
	before := ss.advance(stReset)
	if before.Terminal() {
		return nil
	}
	return ss.sc.writeServerRSTStream(ss, frame.ErrCodeCancel)
}

// remoteHalfEnded reports whether the client has ended its half of the stream,
// i.e. whether the stream is in RFC 9113 §5.1's "half-closed (remote)" state.
func (ss *ServerStream) remoteHalfEnded() bool { return ss.state().RemoteEnded() }

// markRemoteEnd marks the remote side as closed.
// markRemoteEnd records that the client has ended its half of the stream
// (END_STREAM received). It returns true if the stream is now fully closed
// (both the remote and local halves are done), so the caller can release it.
// While the stream is only half-closed (remote), it MUST stay registered: the
// server may still be writing its response and must keep receiving that stream's
// WINDOW_UPDATE / RST_STREAM (RFC 7540 §5.1).
func (ss *ServerStream) markRemoteEnd() bool {
	return ss.advance(stRecvEnded).LocalEnded()
}

// markLocalEnd records that the server has ended its half of the stream (sent
// END_STREAM). It returns true if the stream is now fully closed.
func (ss *ServerStream) markLocalEnd() bool {
	return ss.advance(stSentEnded).RemoteEnded()
}

// markRemoteEndReset records a client RST_STREAM and reports whether the
// request was still open (END_STREAM not yet observed) at that moment. The
// answer comes from the transition itself, so the rapid-reset classification
// (CVE-2023-44487) cannot race the state it is classifying.
//
// A received RST_STREAM closes the stream in both directions, not merely the
// remote half. Recording that is what stops the server answering a reset with a
// reset: RFC 9113 §5.1 (rfc9113.txt:1082) — "An endpoint MUST NOT send frames
// other than PRIORITY on a closed stream" — and §5.4.2 (:1197) — "To avoid
// looping, an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM
// frame." Called before the EventReset is pushed, so no handler can observe the
// reset while the stream still reports itself writable.
func (ss *ServerStream) markRemoteEndReset() (wasOpen bool) {
	return !ss.advance(stRecvEnded | stReset).RemoteEnded()
}

// push delivers an event from the reader goroutine. Non-blocking; on overflow
// it drops the stream and resets it.
//
// INTERNAL_ERROR, not REFUSED_STREAM. RFC 9113 §8.7 (rfc9113.txt:2977) makes
// REFUSED_STREAM a promise: "The REFUSED_STREAM error code can be included in a
// RST_STREAM frame to indicate that the stream is being closed prior to any
// processing having occurred. Any request that was sent on the reset stream can
// be safely retried." By the time this buffer overflows the request has already
// been dispatched — some of its events reached the application — so that promise
// would be false, and a conformant client would replay a request this server had
// begun to serve. The overflow is a server-side buffer failure and INTERNAL_ERROR
// is what says so.
func (ss *ServerStream) push(e StreamEvent) {
	select {
	case ss.events <- e:
		return
	default:
	}
	if ss.advance(stReset).WasReset() {
		return
	}
	go func() {
		_ = ss.sc.writeServerRSTStream(ss, frame.ErrCodeInternalError)
	}()
	select {
	case ss.events <- StreamEvent{Type: EventReset, RSTCode: frame.ErrCodeInternalError, EndStream: true}:
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
