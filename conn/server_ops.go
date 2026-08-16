package conn

import (
	"context"
	"fmt"
	"sync"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// encBufPool recycles the HPACK block-fragment buffer used by writeServerHeaders.
var encBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

// --- serverConnOps implementation on *ServerConn ---

// lookupStream returns the stream for the given ID, or nil.
func (sc *ServerConn) lookupStream(id uint32) *ServerStream { return sc.tbl.lookup(id) }

// registerStream adds a new stream to the registry and delivers it to
// AcceptStream via acceptCh, seeding its send window from the peer's
// SETTINGS_INITIAL_WINDOW_SIZE. It enforces the advertised
// SETTINGS_MAX_CONCURRENT_STREAMS limit: if the connection already has that
// many open/half-closed streams, the new stream is refused with
// RST_STREAM(REFUSED_STREAM) (RFC 9113 §5.1.2) and the function returns false
// without registering it. REFUSED_STREAM signals the request was not processed,
// so the client may safely retry it on a fresh connection.
//
// A full accept queue is refused the same way and for the same reason: both are
// "this server will not process the request", which is what §8.7 reserves
// REFUSED_STREAM for. Returning false suppresses event delivery on both paths
// while OnHeaders still decodes the field block, so the shared HPACK dynamic
// table stays in step with the client's encoder.
func (sc *ServerConn) registerStream(id uint32, s *ServerStream) bool {
	s.sc = sc
	// Admission seeds the send window and consumes the identifier under the
	// table's own lock, so the §6.9.2 retroactive window walk cannot interleave
	// with the seeding, and a refusal still burns the identifier (§5.1.1 forbids
	// reuse either way).
	if !sc.tbl.admitClient(id, s, int(sc.opts.AdvertisedSettings.MaxConcurrentStreams)) {
		// At the concurrency limit: refuse rather than serve. REFUSED_STREAM says
		// the request was not processed, so the client may safely retry it
		// elsewhere (§5.1.2). Best-effort; ignored if the connection is going away.
		_ = sc.writeServerRSTStream(s, frame.ErrCodeRefusedStream)
		return false
	}
	// Per-stream context derived from the connection context; cancelled when the
	// stream completes or resets (markStreamDone) or the connection closes.
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(sc.connCtx)
	s.mu.Unlock()
	// Non-blocking, and it has to stay that way. This runs on the single frame
	// reader goroutine, so blocking here would stop PING, SETTINGS, WINDOW_UPDATE
	// and RST_STREAM for the whole connection — including the frames whose
	// processing is what lets the application make progress and drain the queue.
	// Stalling every stream on the connection to avoid refusing one is the worse
	// trade, so a full queue is refused rather than waited on.
	//
	// The queue is sized from the same advertised MaxConcurrentStreams enforced
	// above (ServerConnOptions.acceptQueueDepth), so a peer that honours the limit
	// it was given does not reach this branch. It is still reachable and so must
	// still be correct: a stream the client resets leaves the table
	// (OnRSTStream -> markStreamDone) but keeps its queue slot until the
	// application takes delivery, so the queue can be full with the table empty.
	//
	// REFUSED_STREAM, not CANCEL, for the same reason as the concurrency-limit
	// branch above. RFC 9113 §8.7: "The REFUSED_STREAM error code can be included
	// in a RST_STREAM frame to indicate that the stream is being closed prior to
	// any processing having occurred. Any request that was sent on the reset
	// stream can be safely retried." Nothing here processed the request, and
	// CANCEL — what ServerStream.Close sends — promises the peer nothing of the
	// kind, so a non-idempotent request refused with it cannot be replayed and is
	// simply lost.
	select {
	case sc.acceptCh <- s:
	default:
		_ = sc.writeServerRSTStream(s, frame.ErrCodeRefusedStream)
		return false
	}
	// Counted only once delivery is certain: a refused stream was never accepted,
	// and ConnStats.StreamsAccepted is the number the operator's dashboards
	// reconcile against requests actually served.
	sc.atomicStreamsAccepted.Add(1)
	return true
}

// onClientRSTStream accounts a client-initiated RST_STREAM for Rapid Reset
// (CVE-2023-44487) detection. Only resets that tore a stream down before it
// produced useful work (rapid == true) are counted toward the budget;
// benign post-completion cancellations are ignored. Returns a connError with
// ErrCodeEnhanceYourCalm once the per-connection budget is exceeded so the
// reader loop sends GOAWAY and tears the connection down.
//
// Hot path: a single atomic load of the budget and, for rapid resets, one
// atomic increment plus a comparison. No allocations.
func (sc *ServerConn) onClientRSTStream(_ uint32, rapid bool) error {
	budget := sc.opts.rapidResetBudget()
	if budget == 0 {
		return nil // mitigation disabled
	}
	if !rapid {
		return nil
	}
	n := sc.rapidResetCount.Add(1)
	if int(n) > budget {
		return connError{
			code: frame.ErrCodeEnhanceYourCalm,
			msg:  "HTTP/2 rapid reset flood detected (CVE-2023-44487)",
		}
	}
	return nil
}

// notePeerGoAway records the client's GOAWAY. From that point the server must
// not open new streams on this connection (RFC 9113 §6.8), which for a server
// means server push.
func (sc *ServerConn) notePeerGoAway() { sc.peerGoAway.Store(true) }

// markStreamDone cleans up a finished stream.
func (sc *ServerConn) markStreamDone(id uint32) {
	s := sc.tbl.release(id)
	if s == nil {
		// Not live: either never registered, or already released — including by the
		// connection teardown that drains the whole table, which is why teardown has
		// to cancel for itself. Nothing left here can do it (issue #139).
		return
	}
	s.cancelCtx() // cancel the handler's context on stream completion/reset
}

// writeSettingsAck sends a SETTINGS ACK.
func (sc *ServerConn) writeSettingsAck() error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WriteSettingsAck(); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// writePingAck echoes a PING with ACK=1.
func (sc *ServerConn) writePingAck(payload [8]byte) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WritePing(true, payload); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// validatePeerSettings enforces the RFC 9113 §6.5.2 value bounds. A violation is
// a connection error (PROTOCOL_ERROR or FLOW_CONTROL_ERROR); unknown settings
// are ignored. Used for BOTH the handshake SETTINGS and mid-connection updates.
func validatePeerSettings(s frame.SettingsParams) error {
	const maxWindow = int64(1<<31 - 1)
	for i := range s.N {
		p := s.Pairs[i]
		//nolint:exhaustive // only bounded settings are validated; others ignored per RFC 9113 §6.5.2
		switch p.ID {
		case frame.SettingEnablePush:
			if p.Value > 1 {
				return connError{code: frame.ErrCodeProtocolError, msg: "SETTINGS_ENABLE_PUSH must be 0 or 1"}
			}
		case frame.SettingInitialWindowSize:
			if int64(p.Value) > maxWindow {
				return connError{code: frame.ErrCodeFlowControlError, msg: "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1"}
			}
		case frame.SettingMaxFrameSize:
			if p.Value < 16384 || p.Value > 16777215 {
				return connError{code: frame.ErrCodeProtocolError, msg: "SETTINGS_MAX_FRAME_SIZE out of range [16384, 16777215]"}
			}
		default:
		}
	}
	return nil
}

// applyPeerSettings applies client SETTINGS. Handles retroactive
// INITIAL_WINDOW_SIZE delta on all open streams (RFC 7540 §6.9.2).
func (sc *ServerConn) applyPeerSettings(s frame.SettingsParams) error {
	if err := validatePeerSettings(s); err != nil {
		return err
	}
	const maxWindow = int64(1<<31 - 1)

	// The encoder is shared with every writer on this connection, and resizing its
	// dynamic table emits a Dynamic Table Size Update into the next block it
	// encodes (RFC 7541 §4.2). Taking wmu keeps that from landing in the middle of
	// a header block another goroutine is already writing. Done before the table
	// section so wmu is never held while the table lock is: a pushing handler
	// holds wmu across writePushPromise and takes the table lock inside it.
	sc.wmu.Lock()
	for i := range s.N {
		p := s.Pairs[i]
		if p.ID == frame.SettingHeaderTableSize {
			sc.enc.SetMaxDynamicTableSize(p.Value)
		}
	}
	sc.wmu.Unlock()

	// Publishing the new values and carrying §6.9.2's retroactive delta happen
	// under one lock, together with the seeding of any stream admitted meanwhile.
	// See streamTable.applyInitialWindow for why they cannot be separate steps.
	changed := false
	err := sc.tbl.applyInitialWindow(
		func() (uint32, uint32) {
			sc.psMu.Lock()
			defer sc.psMu.Unlock()
			oldInitial := settingValue(sc.peerSettings, frame.SettingInitialWindowSize, connInitialRecvWindow)
			for i := range s.N {
				sett := s.Pairs[i]
				setPeerSetting(&sc.peerSettings, sett.ID, sett.Value)
			}
			newInitial := settingValue(sc.peerSettings, frame.SettingInitialWindowSize, connInitialRecvWindow)
			changed = newInitial != oldInitial
			return oldInitial, newInitial
		},
		func(st *ServerStream, delta int64) error {
			st.mu.Lock()
			defer st.mu.Unlock()
			newWin := int64(st.sendWindow) + delta
			if newWin > maxWindow {
				return connError{code: frame.ErrCodeFlowControlError, msg: fmt.Sprintf("SETTINGS_INITIAL_WINDOW_SIZE delta overflowed stream %d send window", st.id)}
			}
			st.sendWindow = int32(newWin) //nolint:gosec // G115: checked above
			return nil
		})
	if err != nil {
		return err
	}
	if changed {
		sc.fcOutMu.Lock()
		sc.fcOutCond.Broadcast()
		sc.fcOutMu.Unlock()
	}
	return nil
}

// onWindowUpdate handles inbound WINDOW_UPDATE.
func (sc *ServerConn) onWindowUpdate(streamID, increment uint32) error {
	const maxWindow = int32(1<<31 - 1)
	if streamID == 0 {
		sc.fcOutMu.Lock()
		newVal := int64(sc.peerConnSendWindow) + int64(increment)
		if newVal > int64(maxWindow) {
			sc.fcOutMu.Unlock()
			return connError{code: frame.ErrCodeFlowControlError, msg: "WINDOW_UPDATE overflowed connection send window"}
		}
		sc.peerConnSendWindow = int32(newVal) //nolint:gosec // G115: checked above
		sc.fcOutCond.Broadcast()
		sc.fcOutMu.Unlock()
		return nil
	}
	// §5.1 (rfc9113.txt:1000): WINDOW_UPDATE is not one of the two frames an idle
	// stream accepts.
	if sc.isIdleStream(streamID) {
		return connError{code: frame.ErrCodeProtocolError, msg: "WINDOW_UPDATE on an idle stream"}
	}
	s := sc.lookupStream(streamID)
	if s == nil {
		// §6.9 (rfc9113.txt:2093) carves this out explicitly: a WINDOW_UPDATE for a
		// stream the receiver has already closed "MUST NOT be treated as an error"
		// — the peer cannot have known in time.
		return nil
	}
	s.mu.Lock()
	newVal := int64(s.sendWindow) + int64(increment)
	if newVal > int64(maxWindow) {
		s.mu.Unlock()
		// Record the reset BEFORE the event is pushed. The EventReset below reaches
		// the handler before writeServerRSTStream puts the frame on the wire, so a
		// handler that reacts by calling Close would otherwise emit a second
		// RST_STREAM — which RFC 9113 §5.4.2 (rfc9113.txt:1201) asks endpoints to
		// avoid: "An endpoint SHOULD NOT send more than one RST_STREAM frame for
		// any stream."
		s.advance(stReset)
		// RFC 9113 §6.9.1: a WINDOW_UPDATE overflowing a STREAM flow-control
		// window is a stream error (RST_STREAM(FLOW_CONTROL_ERROR)), not a
		// connection error — the connection and its other streams survive.
		// Notify a handler reading this stream that it was reset (mirrors
		// OnRSTStream) before writeServerRSTStream releases and cancels it, so the
		// reset event is delivered ahead of the context cancellation.
		s.push(StreamEvent{Type: EventReset, RSTCode: frame.ErrCodeFlowControlError, EndStream: true})
		_ = sc.writeServerRSTStream(s, frame.ErrCodeFlowControlError)
		return nil
	}
	s.sendWindow = int32(newVal) //nolint:gosec // G115: checked above
	s.mu.Unlock()
	sc.fcOutMu.Lock()
	sc.fcOutCond.Broadcast()
	sc.fcOutMu.Unlock()
	return nil
}

// onDataReceived debits flow-control windows for an inbound DATA frame.
//
// s may be nil: the stream has been reset, refused or has already completed.
// The connection-level half still runs, and must. RFC 9113 §6.9.1
// (rfc9113.txt:2113) — "A receiver MUST count the padding and the entire size of
// a frame ... against its connection-level flow-control window even if the
// frame is in error"; §6.8 (:2044) says the same of frames on streams discarded
// after a GOAWAY. The peer has already debited those octets from its own send
// window, so a receiver that neither counts nor refunds them burns connection
// credit permanently: repeat it and the peer's window drains to zero and every
// stream on the connection wedges.
func (sc *ServerConn) onDataReceived(s *ServerStream, length uint32) error {
	debit := int32(length) //nolint:gosec // G115: frame length ≤ 2^24 per RFC

	if s != nil {
		// Debit only. The per-stream window is refunded when the application takes
		// delivery of the bytes (ServerStream.creditConsumed), not when they
		// arrive — refunding on receipt handed the peer credit for data that was
		// merely buffered, so the advertised window bounded nothing.
		s.mu.Lock()
		s.recvWindow -= debit
		if s.recvWindow < 0 {
			s.mu.Unlock()
			return connError{code: frame.ErrCodeFlowControlError, msg: fmt.Sprintf("stream %d: flow control error", s.id)}
		}
		s.mu.Unlock()
	}

	sc.fcMu.Lock()
	sc.connRecvWindow -= debit
	if sc.connRecvWindow < 0 {
		sc.fcMu.Unlock()
		return connError{code: frame.ErrCodeFlowControlError, msg: "connection flow control error"}
	}
	sc.connRefundPending += length
	connRefund := uint32(0)
	if sc.connRefundPending >= recvWindowRefundThreshold {
		connRefund = sc.connRefundPending
		sc.connRefundPending = 0
		sc.connRecvWindow += int32(connRefund) //nolint:gosec // G115: refund ≤ initial
	}
	sc.fcMu.Unlock()

	if connRefund > 0 {
		if err := sc.writeWindowUpdate(0, connRefund); err != nil {
			return err
		}
	}
	return nil
}

// --- Outbound write methods (called from ServerStream) ---

// writeServerHeaders encodes and writes a HEADERS frame. If prio is
// non-nil it is embedded in the frame via the PRIORITY flag. If prio
// is nil but the stream carries a stored priority (from the request
// HEADERS, or set via PushWithPriority), that stored priority is used.
func (sc *ServerConn) writeServerHeaders(_ context.Context, ss *ServerStream, fields []hpack.HeaderField, endStream bool, prio *frame.Priority) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	if prio == nil {
		prio = ss.priority.Load()
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := ss.authorizeSend(); err != nil {
		return err
	}

	// Decide BEFORE encoding. EncodeBlock mutates the connection's shared HPACK
	// dynamic table, and refusing afterwards leaves that table holding entries the
	// peer never received — so its decoder falls a step behind and every LATER
	// response on the connection is undecodable. That is the decode-side trap
	// (emitHeaderBlock) seen from the encoder, and it is why this check cannot
	// simply measure len(block).
	// Budget the frame payload, not just the field block: a HEADERS frame carrying
	// a priority block spends 5 octets before the fragment begins (§6.2).
	budget := sc.maxWritableFrame()
	if prio != nil {
		budget -= 5
	}
	if !fieldsFitFrame(fields, budget) {
		return ErrHeaderBlockTooLarge
	}
	buf := encBufPool.Get().(*[]byte)
	*buf = (*buf)[:0]
	block := sc.enc.EncodeBlock(*buf, fields)
	err := sc.fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      ss.id,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     endStream,
		Priority:      prio,
	})
	*buf = block[:0]
	encBufPool.Put(buf)
	if err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// writeServerData writes a DATA frame with chunking and flow control.
func (sc *ServerConn) writeServerData(ctx context.Context, ss *ServerStream, p []byte, endStream bool) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	// Determine max frame size.
	sc.psMu.RLock()
	peerMax := settingValue(sc.peerSettings, frame.SettingMaxFrameSize, 16384)
	sc.psMu.RUnlock()
	ourMax := sc.opts.AdvertisedSettings.MaxFrameSize
	maxFrame := int(peerMax)
	if int(ourMax) < maxFrame {
		maxFrame = int(ourMax)
	}
	if maxFrame <= 0 {
		maxFrame = 16384
	}

	// Empty DATA with END_STREAM.
	if len(p) == 0 {
		if !endStream {
			return nil
		}
		sc.wmu.Lock()
		defer sc.wmu.Unlock()
		if sc.closed.Load() {
			return ErrConnClosed
		}
		if err := ss.authorizeSend(); err != nil {
			return err
		}
		if err := sc.fr.WriteData(ss.id, true, nil); err != nil {
			return err
		}
		sc.bumpFramesSent()
		return nil
	}

	return sc.writeServerDataChunks(ctx, ss, p, maxFrame, endStream)
}

// writeServerDataChunks sends p as one or more flow-controlled DATA frames.
func (sc *ServerConn) writeServerDataChunks(ctx context.Context, ss *ServerStream, p []byte, maxFrame int, endStream bool) error {
	for len(p) > 0 {
		want := len(p)
		if want > maxFrame {
			want = maxFrame
		}
		n, err := sc.acquireSendCredits(ctx, ss, want)
		if err != nil {
			return err
		}
		last := endStream && n == len(p)
		sc.wmu.Lock()
		if sc.closed.Load() {
			sc.wmu.Unlock()
			return ErrConnClosed
		}
		// Re-checked per chunk: acquireSendCredits above can block for as long as
		// the peer withholds window, and a reset can arrive throughout. Refusing
		// here — unlike the two exits above — happens on a HEALTHY connection, so
		// the credit already debited for this chunk has to go back.
		if aerr := ss.authorizeSend(); aerr != nil {
			sc.wmu.Unlock()
			sc.releaseSendCredits(ss, n)
			return aerr
		}
		if werr := sc.fr.WriteData(ss.id, last, p[:n]); werr != nil {
			sc.wmu.Unlock()
			return werr
		}
		sc.bumpFramesSent()
		sc.wmu.Unlock()
		p = p[n:]
	}
	return nil
}

// fieldLineOverhead bounds the HPACK framing a single field line can cost on top
// of its name and value: one prefix octet for the representation, plus at most
// four octets for each of the two length integers. Huffman coding only ever
// shrinks the payload, and an indexed or incrementally-indexed field costs far
// less, so a field section whose raw size fits within a frame is certain to fit
// once encoded.
const fieldLineOverhead = 9

// fieldsFitFrame reports whether the field section is guaranteed to encode into
// limit octets or fewer, WITHOUT encoding it — which is the point: the encoder's
// dynamic table must not be disturbed by a block that is never sent.
//
// Deliberately conservative. It can refuse a section that HPACK would have
// compressed under the limit, but the alternative — encode, measure, then throw
// the block away — desyncs the connection.
func fieldsFitFrame(fields []hpack.HeaderField, limit int) bool {
	total := 0
	for i := range fields {
		total += len(fields[i].Name) + len(fields[i].Value) + fieldLineOverhead
		if total > limit {
			return false
		}
	}
	return true
}

// maxWritableFrame is the largest frame payload this endpoint can actually put
// on the wire: the smaller of what the peer will accept and what the framer will
// emit.
//
// The two are different numbers and pre-checking against the peer's alone lets a
// frame past the check that the framer then refuses — a client that advertises a
// large SETTINGS_MAX_FRAME_SIZE (legal up to 2^24-1) opens a whole band of sizes
// where that happens. writeServerData has always computed this minimum; the
// field-section paths did not.
func (sc *ServerConn) maxWritableFrame() int {
	ours := int(sc.opts.AdvertisedSettings.MaxFrameSize)
	if peer := sc.peerMaxFrameSize(); peer < ours {
		return peer
	}
	return ours
}

// peerMaxFrameSize is the largest frame payload the peer has said it will
// accept (RFC 9113 §6.5.2 SETTINGS_MAX_FRAME_SIZE, initial value 2^14).
func (sc *ServerConn) peerMaxFrameSize() int {
	sc.psMu.RLock()
	defer sc.psMu.RUnlock()
	return int(settingValue(sc.peerSettings, frame.SettingMaxFrameSize, 16384))
}

// writeServerRSTStream sends RST_STREAM for a server stream.
//
// Resetting a stream closes it, so the transition is recorded here rather than
// left to each caller: §5.1 (rfc9113.txt:1082) forbids sending anything but
// PRIORITY afterwards, and a later ServerStream.Close on the same stream must be
// the no-op it already is for a stream that ended normally.
func (sc *ServerConn) writeServerRSTStream(ss *ServerStream, code frame.ErrCode) error {
	// Close for writing BEFORE the frame goes out. A handler goroutine holding
	// this stream gates its writes on the reset bit alone, so any window between
	// the RST_STREAM reaching the wire and the bit being set is a window in which
	// it can answer on a stream the server has just reset — what RFC 9113 §5.1
	// (rfc9113.txt:1082) forbids.
	ss.advance(stReset)
	if sc.closed.Load() {
		// Connection already gone: release here, since no write will follow.
		sc.markStreamDone(ss.id)
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	// Release unconditionally, whatever becomes of the write — an early return
	// used to leave the stream in the registry with its context uncancelled,
	// stranding the handler goroutine, inflating ActiveStreams, and leaking the
	// peer's push allowance (which is counted by scanning that registry). Every
	// caller discards this error, so nothing downstream could compensate.
	//
	// Registered AFTER the wmu unlock so that, by defer LIFO, it runs BEFORE it —
	// the deregistration stays inside the wmu critical section. writePushPromise
	// takes wmu and then tests registry identity to decide whether the parent is
	// still live, so a window in which wmu is free while the reset stream is
	// still registered is a window in which PUSH_PROMISE goes out on a stream
	// this endpoint has already reset (§6.6, and §5.1 rfc9113.txt:1082).
	defer sc.markStreamDone(ss.id)
	if err := sc.fr.WriteRSTStream(ss.id, code); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// writeRSTStreamID resets a stream by identifier, for the two codec-detected
// violations RFC 9113 scopes to a stream (§6.3 a wrong-length PRIORITY, §6.9.1 a
// zero-increment WINDOW_UPDATE). Those arrive with nothing but a FrameHeader —
// the stream may be idle, or may never exist — so writeServerRSTStream's
// *ServerStream signature cannot serve them.
//
// Deliberately does not call markStreamDone: a malformed PRIORITY naming an idle
// stream must not evict a live sibling's registry entry.
func (sc *ServerConn) writeRSTStreamID(id uint32, code frame.ErrCode) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	// If the identifier does name a live stream, close it for writing before the
	// reset goes out. A handler goroutine holding that *ServerStream gates its
	// writes on the reset bit alone, so without this it would answer on a stream
	// the server has just reset — RFC 9113 §5.1 (rfc9113.txt:1082) forbids sending
	// anything but PRIORITY there.
	live := false
	if ss := sc.lookupStream(id); ss != nil {
		live = true
		ss.advance(stReset)
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	// ...and release it, exactly as writeServerRSTStream does. Recording the reset
	// without deregistering leaves the stream in the registry with its context
	// uncancelled: its handler goroutine waits forever on events that will never
	// come, ActiveStreams never returns to zero so IdleTimeout can never reap the
	// connection, and the odd-stream scan keeps counting it toward
	// MaxConcurrentStreams until every later request is refused. Two client
	// frames reach this path — a wrong-length PRIORITY or a zero-increment
	// WINDOW_UPDATE on an open stream — and the rapid-reset budget does not apply,
	// because these are resets this server sends.
	//
	// Only when the identifier resolved: an unknown or idle id must not evict a
	// live sibling's entry. Deferred after the unlock so it runs before it, so
	// the deregistration stays inside the wmu critical section that
	// writePushPromise's liveness test depends on.
	if live {
		defer sc.markStreamDone(id)
	}
	if err := sc.fr.WriteRSTStream(id, code); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// acquireSendCredits blocks until both per-stream and connection-level
// outbound send windows have credit, then deducts up to `want` bytes.
func (sc *ServerConn) acquireSendCredits(ctx context.Context, ss *ServerStream, want int) (int, error) {
	if want <= 0 {
		return 0, nil
	}

	sc.fcOutMu.Lock()
	defer sc.fcOutMu.Unlock()
	for {
		if sc.closed.Load() {
			return 0, ErrConnClosed
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ss.mu.Lock()
		streamWin := ss.sendWindow
		ss.mu.Unlock()
		connWin := sc.peerConnSendWindow
		avail := streamWin
		if connWin < avail {
			avail = connWin
		}
		if avail > 0 {
			n := int32(want) //nolint:gosec // G115: want ≤ maxFrameSize
			if n > avail {
				n = avail
			}
			sc.peerConnSendWindow -= n
			ss.mu.Lock()
			ss.sendWindow -= n
			ss.mu.Unlock()
			return int(n), nil
		}
		// Only spawn watchdog goroutine when we actually need to wait
		// and the context might be cancelled (non-background contexts).
		if ctx.Done() != nil {
			sc.fcOutMu.Unlock()
			n, err := sc.acquireSendCreditsSlow(ctx, ss, want)
			sc.fcOutMu.Lock()
			return n, err
		}
		sc.fcOutCond.Wait()
	}
}

// releaseSendCredits returns credit that acquireSendCredits debited for octets
// that were then never written.
//
// Only a refusal on a live connection needs this. RFC 9113 §6.9.1 replenishes a
// flow-control window solely through the peer's WINDOW_UPDATE, and the peer
// sends those for octets it has RECEIVED — so credit spent on a frame that never
// left is gone for the life of the connection. The connection-level window is
// shared by every stream, so a stream reset mid-body would take a chunk of it
// down with it: four cancelled downloads at the default 16 KiB frame and 64 KiB
// connection window are enough to strand every other stream in
// acquireSendCredits, with nothing reported anywhere.
//
// Saturates rather than wraps. onWindowUpdate bounds an incoming grant against
// the window as it stands, which is already net of any octets debited and not
// yet written — so a peer may legally bring a window to exactly 2^31-1 while a
// chunk is outstanding, and adding that chunk back on top overflows int32 to a
// large negative number. That is the very wedge this function exists to prevent,
// arrived at from the other side: avail stays ≤ 0 for every stream on the
// connection and no WINDOW_UPDATE a peer would ever send can lift it out.
//
// The excess can only exist because the peer credited octets it never received,
// which is its own §6.9.1 violation. Saturating keeps this endpoint from sending
// more than the peer allowed; tearing the connection down instead would punish
// the peer for arithmetic this endpoint chose to do.
//
// Called without sc.wmu held. Lock order is fcOutMu then ss.mu, matching
// acquireSendCredits.
func (sc *ServerConn) releaseSendCredits(ss *ServerStream, n int) {
	if n <= 0 {
		return
	}
	sc.fcOutMu.Lock()
	sc.peerConnSendWindow = addWindowSaturating(sc.peerConnSendWindow, n)
	sc.fcOutCond.Broadcast()
	sc.fcOutMu.Unlock()
	ss.mu.Lock()
	ss.sendWindow = addWindowSaturating(ss.sendWindow, n)
	ss.mu.Unlock()
}

// addWindowSaturating adds n to a flow-control window, capping at the RFC 9113
// §6.9.1 maximum of 2^31-1 instead of overflowing int32.
func addWindowSaturating(win int32, n int) int32 {
	const maxWindow = int64(1<<31 - 1)
	v := int64(win) + int64(n)
	if v > maxWindow {
		return int32(maxWindow)
	}
	return int32(v) //nolint:gosec // G115: bounded above here, and n > 0
}

// acquireSendCreditsSlow is the slow path that spawns a watchdog goroutine
// to wake the condition variable when the context is cancelled.
func (sc *ServerConn) acquireSendCreditsSlow(ctx context.Context, ss *ServerStream, want int) (int, error) {
	watchdog := make(chan struct{})
	defer close(watchdog)
	go func() {
		select {
		case <-ctx.Done():
			sc.fcOutMu.Lock()
			sc.fcOutCond.Broadcast()
			sc.fcOutMu.Unlock()
		case <-watchdog:
		}
	}()

	sc.fcOutMu.Lock()
	defer sc.fcOutMu.Unlock()
	for {
		if sc.closed.Load() {
			return 0, ErrConnClosed
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ss.mu.Lock()
		streamWin := ss.sendWindow
		ss.mu.Unlock()
		connWin := sc.peerConnSendWindow
		avail := streamWin
		if connWin < avail {
			avail = connWin
		}
		if avail > 0 {
			n := int32(want) //nolint:gosec // G115: want ≤ maxFrameSize
			if n > avail {
				n = avail
			}
			sc.peerConnSendWindow -= n
			ss.mu.Lock()
			ss.sendWindow -= n
			ss.mu.Unlock()
			return int(n), nil
		}
		sc.fcOutCond.Wait()
	}
}

// writeWindowUpdate emits a WINDOW_UPDATE frame.
func (sc *ServerConn) writeWindowUpdate(streamID, increment uint32) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WriteWindowUpdate(streamID, increment); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// setPeerSetting merges a SETTINGS pair into params.
//
// Identifiers this server does not implement are dropped rather than stored.
// RFC 9113 §6.5.2 (rfc9113.txt:1888): "An endpoint that receives a SETTINGS frame
// with any unknown or unsupported identifier MUST ignore that setting."
// Storing them was not merely untidy: SettingsParams holds a fixed 16 pairs, so a
// peer sending sixteen invented identifiers filled the array and every real
// setting after it was silently dropped.
func setPeerSetting(params *frame.SettingsParams, id frame.SettingID, val uint32) {
	//nolint:exhaustive // the listed six are the settings this server implements;
	// everything else, SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441) included, is
	// unsupported here and must therefore be ignored rather than stored.
	switch id {
	case frame.SettingHeaderTableSize, frame.SettingEnablePush,
		frame.SettingMaxConcurrentStreams, frame.SettingInitialWindowSize,
		frame.SettingMaxFrameSize, frame.SettingMaxHeaderListSize:
	default:
		return
	}
	for i := range params.N {
		if params.Pairs[i].ID == id {
			params.Pairs[i].Value = val
			return
		}
	}
	if params.N < len(params.Pairs) {
		params.Pairs[params.N] = frame.SettingPair{ID: id, Value: val}
		params.N++
	}
}
