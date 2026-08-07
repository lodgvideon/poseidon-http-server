package conn

import (
	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// serverConnOps is the contract server_handler.go needs from ServerConn.
//
// handler performs; the width tracks HTTP/2's own frame surface. Splitting it
// into themed sub-interfaces would buy nothing — *ServerConn implements all of
// it and the single mock in server_handler_test.go stubs all of it.
//
//nolint:interfacebloat // one method per connection-level operation the frame
type serverConnOps interface {
	lookupStream(id uint32) *ServerStream
	// isIdleStream reports whether the identifier names a stream that has never
	// been opened (RFC 9113 §5.1). A lookupStream miss alone cannot tell idle
	// from closed, and the two demand opposite reactions.
	isIdleStream(id uint32) bool
	// validateClientStreamID enforces RFC 9113 §5.1.1 (odd, strictly increasing)
	// for a newly opened client stream, returning a connError on violation.
	validateClientStreamID(id uint32) error
	// writeRSTStreamID resets a stream by identifier, for the paths that hold no
	// *ServerStream: a closed stream, or one that was never registered.
	writeRSTStreamID(id uint32, code frame.ErrCode) error
	// registerStream registers a new client stream, returning false if it was
	// refused for exceeding SETTINGS_MAX_CONCURRENT_STREAMS (RST_STREAM already
	// sent). The caller must not process a refused stream.
	registerStream(id uint32, s *ServerStream) bool
	markStreamDone(id uint32)
	// writeServerRSTStream resets a single stream without disturbing the
	// connection — the reaction RFC 9113 §8.1.1 mandates for a malformed
	// request. It calls markStreamDone itself.
	writeServerRSTStream(ss *ServerStream, code frame.ErrCode) error
	writeSettingsAck() error
	writePingAck(payload [8]byte) error
	deliverPingAck(payload [8]byte)
	applyPeerSettings(s frame.SettingsParams) error
	onWindowUpdate(streamID, increment uint32) error
	onDataReceived(s *ServerStream, length uint32) error
	// notePeerGoAway records that the peer has sent GOAWAY, after which this
	// endpoint must not open further streams on the connection (RFC 9113 §6.8).
	notePeerGoAway()
	// onClientRSTStream accounts a client-initiated RST_STREAM for Rapid
	// Reset (CVE-2023-44487) detection. Returns a non-nil error when the
	// per-connection budget is exceeded; the reader loop then sends
	// GOAWAY(ENHANCE_YOUR_CALM) and tears the connection down.
	onClientRSTStream(streamID uint32, rapid bool) error
}

// defaultMaxHeaderBytes bounds the total compressed size of a single header
// block (the HEADERS frame plus all of its CONTINUATION frames) when the
// connection does not advertise SETTINGS_MAX_HEADER_LIST_SIZE. It defends
// against the CONTINUATION flood (CVE-2024-27316): an endless stream of
// CONTINUATION frames with no END_HEADERS would otherwise grow pendingBuf
// without bound until the process is OOM-killed.
const defaultMaxHeaderBytes = 1 << 20 // 1 MiB

// status431Fields is the response to a request whose field section is larger
// than the server is prepared to process. Package-level and reused, never
// re-minted (ADR-0001).
//
// RFC 9110 §5.4: "A server that receives a request header field line, field
// value, or set of fields larger than it wishes to process MUST respond with an
// appropriate 4xx (Client Error) status code. Ignoring such header fields would
// increase the server's vulnerability to request smuggling attacks." 431
// (Request Header Fields Too Large) is RFC 6585 §5; RFC 9110 itself asks only
// for "an appropriate 4xx".
var status431Fields = []hpack.HeaderField{
	{Name: []byte(":status"), Value: []byte("431")},
}

// fieldEntryOverhead is the per-field constant of the HPACK entry-size formula
// (RFC 7541 §4.1), which is what SETTINGS_MAX_HEADER_LIST_SIZE is measured in:
// RFC 9113 §6.5.2 sizes the list "based on the uncompressed size of field
// lines, including the length of the name and value in octets plus an overhead
// of 32 octets for each field line".
const fieldEntryOverhead = 32

// fieldSpan records one decoded field's extent inside serverConnHandler.fieldBuf.
// Lengths rather than slices: fieldBuf reallocates as it grows, which would
// invalidate any slice taken before the growth.
type fieldSpan struct {
	nameLen   int
	valLen    int
	sensitive bool
}

// serverConnHandler bridges frame.Handler into per-ServerStream events.
type serverConnHandler struct {
	streams serverConnOps
	dec     *hpack.Decoder

	// maxHeaderBytes caps the accumulated compressed size of one header block.
	maxHeaderBytes int

	// recvWindowSeed is the initial per-stream receive window for new streams,
	// seeded from the server's advertised InitialWindowSize so the server's recv
	// accounting matches what the peer was told it may send.
	recvWindowSeed int32

	scratch []hpack.HeaderField
	// fieldBuf and spans hold a private copy of the decoded field section.
	// hpack.Decoder documents its field slices as valid only for the duration of
	// the visit call — they alias its scratch buffer, or the dynamic table's
	// arena, which is rewritten in place when an insertion evicts the table
	// empty. Retaining them meant a later field in the SAME block could silently
	// rewrite an earlier one, which also defeats the §8.2.1 name validation:
	// the checks run inside the callback, on bytes that no longer exist by the
	// time the fields are read again. Both buffers are reused across blocks, so
	// the copy costs no steady-state allocation.
	fieldBuf         []byte
	spans            []fieldSpan
	pendingStreamID  uint32
	pendingBuf       []byte
	pendingEndStream bool
	pendingTrailer   bool
	// pendingDiscard marks an open header block whose stream was refused
	// (over MaxConcurrentStreams): the block is still decoded to keep the
	// shared HPACK decoder in sync, but the result and stream are discarded.
	pendingDiscard bool
}

func newServerConnHandler(streams serverConnOps, dec *hpack.Decoder, maxHeaderBytes int, recvWindowSeed int32) *serverConnHandler {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = defaultMaxHeaderBytes
	}
	if recvWindowSeed <= 0 {
		recvWindowSeed = connInitialRecvWindow
	}
	return &serverConnHandler{
		streams:        streams,
		dec:            dec,
		maxHeaderBytes: maxHeaderBytes,
		recvWindowSeed: recvWindowSeed,
		scratch:        make([]hpack.HeaderField, 0, 16),
	}
}

// respondFieldsTooLarge answers one stream with 431 and releases it, leaving
// the connection and its sibling streams alone. Best-effort: a write failure
// here means the connection is already going away.
func (h *serverConnHandler) respondFieldsTooLarge(s *ServerStream) {
	if s == nil {
		return
	}
	_ = s.SendHeaders(s.Context(), status431Fields, true)
	h.streams.markStreamDone(s.id)
}

// undispatchedFrameType reports whether ReadFrame delivers no Handler callback
// at all for this frame type — the codec's "ignore and discard" branch for
// types it does not recognise (RFC 9113 §5.5). guardHeaderBlock can never fire
// for one, so the §6.10 check for these has to happen in the reader loop, where
// the FrameHeader is available.
//
// The dispatched set is 0x0..0x9 plus ALTSVC (0x0a) and ORIGIN (0x0c); this is
// exactly 0x0b and 0x0d..0xff.
func undispatchedFrameType(t frame.FrameType) bool {
	return t > frame.FrameContinuation && t != frame.FrameAltSvc && t != frame.FrameOrigin
}

// guardHeaderBlock enforces RFC 9113 §6.10: once a HEADERS frame without
// END_HEADERS opens a header block, the only frame permitted until END_HEADERS
// is a CONTINUATION on the same stream. Any other frame is a connection error
// of type PROTOCOL_ERROR. Invoked at the top of every non-CONTINUATION callback.
func (h *serverConnHandler) guardHeaderBlock() error {
	if h.pendingStreamID != 0 {
		return connError{code: frame.ErrCodeProtocolError, msg: "expected CONTINUATION for open header block"}
	}
	return nil
}

func (h *serverConnHandler) OnData(fh frame.FrameHeader, p []byte, _ uint8) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	// A client may never send DATA on a server-initiated (even) stream, but §5.1
	// scopes the reaction by the state this server holds it in. A push stream that
	// is still reserved (local) — or one that never existed — gives "Receiving any
	// type of frame other than RST_STREAM, PRIORITY, or WINDOW_UPDATE on a stream
	// in this state MUST be treated as a connection error ... of type
	// PROTOCOL_ERROR" (rfc9113.txt:1020). Once the server has sent its response
	// the stream is half-closed (remote), and there the same section mandates only
	// a stream error of type STREAM_CLOSED (:1044). Falling through lets the
	// idle/closed/half-closed guards below draw that distinction.
	if fh.StreamID%2 == 0 && h.streams.lookupStream(fh.StreamID) == nil {
		return connError{code: frame.ErrCodeProtocolError, msg: "client DATA on a server-initiated stream"}
	}
	// §5.1 (rfc9113.txt:1000): in the idle state "receiving any frame other than
	// HEADERS or PRIORITY ... MUST be treated as a connection error of type
	// PROTOCOL_ERROR". Checked before the debit: an idle stream ends the
	// connection, so there is no window left to keep books for.
	if h.streams.isIdleStream(fh.StreamID) {
		return connError{code: frame.ErrCodeProtocolError, msg: "DATA on an idle stream"}
	}
	s := h.streams.lookupStream(fh.StreamID)
	// Account before branching. The connection-level window is owed for every
	// flow-controlled frame that arrives, including one for a stream that no
	// longer exists — see onDataReceived. s == nil is tolerated there.
	if err := h.streams.onDataReceived(s, fh.Length); err != nil {
		return err
	}
	if s == nil {
		// Closed, reset or refused. §5.1 lets a receiver "treat frames that arrive
		// on a closed stream after ... RST_STREAM as being in error", but the peer
		// may simply not have learned yet, so the frame is counted and dropped
		// rather than escalated.
		return nil
	}
	// §5.1 (rfc9113.txt:1044): in half-closed (remote), "if an endpoint receives
	// additional frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a
	// stream that is in this state, it MUST respond with a stream error of type
	// STREAM_CLOSED". Left unenforced, body bytes sent after END_STREAM reached
	// the handler behind its own EOF.
	if s.remoteHalfEnded() {
		// writeServerRSTStream, not writeRSTStreamID: it marks the stream closed
		// under ss.mu and calls markStreamDone itself. Resetting by identifier alone
		// leaves ss.closed false, and the handler goroutine — which already holds
		// this *ServerStream and gates its writes on exactly that flag — would then
		// put its response on the wire AFTER the RST_STREAM, which is the §5.1
		// violation this guard exists to prevent.
		_ = h.streams.writeServerRSTStream(s, frame.ErrCodeStreamClosed)
		return nil
	}
	end := fh.Flags&frame.FlagDataEndStream != 0
	dataCopy := append([]byte(nil), p...)
	// Record the transition before the push, release after it: the handler must
	// never see EOF on a stream that still reports itself open, and it must
	// observe the final event before markStreamDone cancels its context. Until
	// the server has ended its half too, the stream stays registered
	// (half-closed remote) so its WINDOW_UPDATE and RST_STREAM still reach it.
	fullyClosed := end && s.markRemoteEnd()
	s.push(StreamEvent{Type: EventData, Data: dataCopy, EndStream: end})
	if fullyClosed {
		h.streams.markStreamDone(fh.StreamID)
	}
	return nil
}

func (h *serverConnHandler) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, prio *frame.Priority, _ uint8) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	// A client must never send HEADERS on an even (server-initiated) stream ID
	// (RFC 9113 §5.1.1) — including one colliding with a live push stream, which
	// would otherwise be treated as an existing stream and bypass validation.
	if fh.StreamID%2 == 0 {
		return connError{code: frame.ErrCodeProtocolError, msg: "client HEADERS on even (server-initiated) stream ID"}
	}
	end := fh.Flags&frame.FlagHeadersEndStream != 0
	endHeaders := fh.Flags&frame.FlagHeadersEndHeaders != 0

	s := h.streams.lookupStream(fh.StreamID)
	isNew := s == nil

	// refused: a new stream rejected for exceeding MaxConcurrentStreams
	// (RST_STREAM already sent by registerStream). The header block is still
	// decoded to keep the shared HPACK decoder's dynamic table in sync with the
	// client's persistent encoder — only stream registration and event delivery
	// are suppressed. Skipping the decode would desync HPACK and corrupt every
	// subsequent stream on the connection.
	refused := false
	if isNew {
		// RFC 9113 §5.1.1 (rfc9113.txt:1113): "The identifier of a newly
		// established stream MUST be numerically greater than all streams that the
		// initiating endpoint has opened or reserved... An endpoint that receives
		// an unexpected stream identifier MUST respond with a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR."
		//
		// This deliberately also catches a field section arriving for a stream the
		// server has already reset — the one-round-trip overlap where the client
		// had trailers on the wire. §5.1's closed state would allow the softer
		// stream error there, but only for a stream this endpoint reset, and once
		// markStreamDone has removed it that is indistinguishable from genuine
		// identifier reuse without per-stream-identifier memory. Trading §5.1.1's
		// explicit MUST for a softer reaction to a case we cannot identify is the
		// worse of the two errors; see docs/RFC_COVERAGE.md.
		if err := h.streams.validateClientStreamID(fh.StreamID); err != nil {
			return err
		}
		s = newServerStream(fh.StreamID, 8, nil, h.recvWindowSeed)
		if !h.streams.registerStream(fh.StreamID, s) {
			refused = true
		}
	}

	// RFC 7540 §5.3: priority block is sent only on the first HEADERS
	// frame. Capture it once, before any CONTINUATION frames.
	if isNew && !refused && prio != nil {
		s.setPriority(prio)
	}

	if !endHeaders {
		if len(hb) > h.maxHeaderBytes {
			// The client is owed a status before the connection goes (RFC 9110
			// §5.4). ENHANCE_YOUR_CALM, not PROTOCOL_ERROR: an oversized but
			// well-formed field block is not a protocol violation, it is a
			// client sending more than this server will process.
			h.respondFieldsTooLarge(s)
			return connError{code: frame.ErrCodeEnhanceYourCalm, msg: "header block exceeds max size"}
		}
		h.pendingStreamID = fh.StreamID
		h.pendingBuf = append(h.pendingBuf[:0], hb...)
		h.pendingEndStream = end
		h.pendingDiscard = refused
		h.pendingTrailer = !isNew && s.headersReceived
		// Only the first HEADERS carries priority; ignore any on trailers.
		return nil
	}

	if refused {
		// Single-frame refused block: decode-and-discard for HPACK sync.
		return h.discardHeaderBlock(hb)
	}

	isTrailer := false
	if !isNew {
		isTrailer = s.headersReceived
	}

	if !isTrailer {
		s.headersReceived = true
	}
	return h.emitHeaderBlock(s, hb, end, isTrailer)
}

// discardHeaderBlock decodes a header block solely to advance the shared HPACK
// decoder's dynamic table (keeping it in sync with the client's encoder) and
// throws the decoded fields away. Used for streams refused over
// MaxConcurrentStreams and for the defensive stream-vanished path: skipping the
// decode would desync the decoder and corrupt every later stream. Clears the
// open-block state so the interleaving guard re-admits other frames.
func (h *serverConnHandler) discardHeaderBlock(hb []byte) error {
	h.pendingStreamID = 0
	h.pendingDiscard = false
	if err := h.dec.DecodeBlock(hb, func(hpack.HeaderField) error { return nil }); err != nil {
		// Same rule as emitHeaderBlock: a block that will not decode has already
		// desynced the connection's shared dynamic table (RFC 9113 §4.3).
		return connError{code: frame.ErrCodeCompressionError, msg: "HPACK decoding error: " + err.Error()}
	}
	return nil
}

func (h *serverConnHandler) OnContinuation(fh frame.FrameHeader, hb frame.HeaderBlock) error {
	// A CONTINUATION with no open header block, or one on a different stream
	// than the one awaiting it, is a connection PROTOCOL_ERROR (RFC 9113 §6.10).
	if h.pendingStreamID == 0 {
		return connError{code: frame.ErrCodeProtocolError, msg: "unexpected CONTINUATION"}
	}
	if fh.StreamID != h.pendingStreamID {
		return connError{code: frame.ErrCodeProtocolError, msg: "CONTINUATION on wrong stream"}
	}
	// Bound the accumulated compressed header block (CVE-2024-27316 defense).
	if len(h.pendingBuf)+len(hb) > h.maxHeaderBytes {
		h.respondFieldsTooLarge(h.streams.lookupStream(fh.StreamID))
		return connError{code: frame.ErrCodeEnhanceYourCalm, msg: "header block exceeds max size"}
	}
	h.pendingBuf = append(h.pendingBuf, hb...)
	if fh.Flags&frame.FlagContinuationEndHeaders == 0 {
		return nil
	}
	if h.pendingDiscard {
		// Refused stream: decode-and-discard the full block for HPACK sync.
		return h.discardHeaderBlock(h.pendingBuf)
	}
	s := h.streams.lookupStream(fh.StreamID)
	if s == nil {
		// Defensive (unreachable with a single reader goroutine): decode-and-
		// discard rather than drop, so the HPACK decoder cannot desync.
		return h.discardHeaderBlock(h.pendingBuf)
	}
	end := h.pendingEndStream
	isTrailer := h.pendingTrailer
	if !isTrailer {
		s.headersReceived = true
	}
	return h.emitHeaderBlock(s, h.pendingBuf, end, isTrailer)
}

// ownedCopy moves the decoded field section into a single right-sized backing
// slab the event owns. h.fieldBuf is reused by the next block on this
// connection, and the handler goroutine may retain the fields indefinitely
// (req.Headers alias the slab), so a sync.Pool would be unsafe — like net/http
// we allocate per request. Pre-sizing to the exact total means the appends never
// reallocate, keeping the three-index sub-slices valid.
func (h *serverConnHandler) ownedCopy() []hpack.HeaderField {
	total := 0
	for i := range h.scratch {
		total += len(h.scratch[i].Name) + len(h.scratch[i].Value)
	}
	slab := make([]byte, 0, total)
	copied := make([]hpack.HeaderField, len(h.scratch))
	for i, f := range h.scratch {
		nameOff := len(slab)
		slab = append(slab, f.Name...)
		valOff := len(slab)
		slab = append(slab, f.Value...)
		endOff := len(slab)
		copied[i] = hpack.HeaderField{
			Name:      slab[nameOff:valOff:valOff],
			Value:     slab[valOff:endOff:endOff],
			Sensitive: f.Sensitive,
		}
	}
	return copied
}

func (h *serverConnHandler) emitHeaderBlock(s *ServerStream, hb []byte, endStream, isTrailer bool) error {
	// The header block is complete: clear the "awaiting CONTINUATION" state so
	// the interleaving guard re-admits other frame types. hb may alias
	// pendingBuf, so do NOT reset pendingBuf here — it is reused on the next
	// HEADERS via append(pendingBuf[:0], ...).
	h.pendingStreamID = 0
	h.scratch = h.scratch[:0]
	// Field validation runs inside the decode callback so it costs one pass and
	// no allocation, but it only *flags* — the whole block must still decode or
	// the shared HPACK dynamic table desyncs from the client's encoder and every
	// later stream on this connection is corrupted.
	h.fieldBuf = h.fieldBuf[:0]
	h.spans = h.spans[:0]
	malformed := false
	// SETTINGS_MAX_HEADER_LIST_SIZE is measured over the UNCOMPRESSED list
	// (RFC 9113 §6.5.2), so it cannot be checked on the encoded block — a small
	// block can decode into an arbitrarily large field list. Accounting here
	// costs one integer add per field inside a callback that already runs, and
	// allocates nothing. Like the character check it only flags: the whole block
	// must still decode or the shared HPACK dynamic table desyncs.
	listSize, oversized := 0, false
	err := h.dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		if !malformed && isProhibitedField(f.Name, f.Value, isTrailer) {
			malformed = true
		}
		listSize += len(f.Name) + len(f.Value) + fieldEntryOverhead
		if listSize > h.maxHeaderBytes {
			oversized = true
			return nil // keep decoding, stop collecting
		}
		if !oversized {
			h.fieldBuf = append(h.fieldBuf, f.Name...)
			h.fieldBuf = append(h.fieldBuf, f.Value...)
			h.spans = append(h.spans, fieldSpan{nameLen: len(f.Name), valLen: len(f.Value), sensitive: f.Sensitive})
		}
		return nil
	})
	// Materialise the fields now that fieldBuf has stopped growing, so every slice
	// below points at storage this handler owns.
	off := 0
	for _, sp := range h.spans {
		nameEnd := off + sp.nameLen
		valEnd := nameEnd + sp.valLen
		h.scratch = append(h.scratch, hpack.HeaderField{
			Name:      h.fieldBuf[off:nameEnd:nameEnd],
			Value:     h.fieldBuf[nameEnd:valEnd:valEnd],
			Sensitive: sp.sensitive,
		})
		off = valEnd
	}
	if err != nil {
		// RFC 9113 §4.3 (rfc9113.txt:668): "A decoding error in a field block MUST
		// be treated as a connection error (Section 5.4.1) of type
		// COMPRESSION_ERROR." Not a stream error, and the reason is structural
		// rather than a matter of severity: the dynamic table this block was being
		// decoded against is shared by every stream on the connection, so once a
		// block fails there is no correct way to decode anything that follows.
		// Resetting only this stream would leave the peer believing the connection
		// is still usable — and RST_STREAM(CANCEL), which this used to send, would
		// additionally invite it to retry the request.
		return connError{code: frame.ErrCodeCompressionError, msg: "HPACK decoding error: " + err.Error()}
	}
	if oversized {
		// RFC 9110 §5.4 — answer this stream, leave the connection alone.
		h.respondFieldsTooLarge(s)
		return nil
	}
	// §5.1 (rfc9113.txt:1044) — a field section arriving after the client already
	// ended its half is a stream error of type STREAM_CLOSED. Without this the
	// block was classified as trailers (headersReceived is already set) and
	// delivered to the handler after its EOF: a second, unannounced field section
	// on a request the application considers complete.
	//
	// Deliberately after the decode, never before. The block has to reach the
	// shared HPACK decoder or the connection's dynamic table falls a step behind
	// the client's encoder and every later stream decodes corruption.
	if s.remoteHalfEnded() {
		// See OnData: writeServerRSTStream also closes the stream for writing, so
		// the handler cannot answer on a stream this just reset.
		_ = h.streams.writeServerRSTStream(s, frame.ErrCodeStreamClosed)
		return nil
	}
	// RFC 9113 §8.3 — request pseudo-headers must be present, unique, defined,
	// and ahead of every regular field. Only a request header block carries
	// them; a trailer section is judged by the character rules alone.
	if !isTrailer && !validRequestPseudoHeaders(h.scratch) {
		malformed = true
	}
	// RFC 9113 §8.1 (rfc9113.txt:2415) — a trailer section is the end of the
	// message: "The last frame in the sequence bears an END_STREAM flag". A
	// trailer HEADERS without it leaves the request open behind a field section
	// that claimed to close it.
	if isTrailer && !endStream {
		malformed = true
	}
	if malformed {
		// RFC 9110 §5.5 — reject a message whose field value carries CR, LF or
		// NUL; RFC 9113 §8.1.1 — as a STREAM error of type PROTOCOL_ERROR, so
		// the connection and its sibling streams survive. Nothing is delivered
		// to the handler: an unvalidated value is a header-injection primitive.
		// Best-effort like the MaxConcurrentStreams refusal above; a write
		// failure here means the connection is already going away. Do NOT
		// s.Close() first — that emits its own RST_STREAM(CANCEL), which would
		// reach the peer ahead of the PROTOCOL_ERROR the RFC calls for.
		// writeServerRSTStream calls markStreamDone, cancelling the stream
		// context, which is what releases the accept side.
		_ = h.streams.writeServerRSTStream(s, frame.ErrCodeProtocolError)
		return nil
	}

	evType := EventHeaders
	if isTrailer {
		evType = EventTrailers
	}
	copied := h.ownedCopy()

	// Record the state transition BEFORE handing the event over, so a stream that
	// has told its handler "this is the end" never simultaneously reports itself
	// as still open. Releasing it stays AFTER the push, so the handler observes
	// the headers and EOF before its context is cancelled — a half-closed (remote)
	// stream stays registered for its WINDOW_UPDATE and RST_STREAM (§5.1).
	fullyClosed := endStream && s.markRemoteEnd()
	s.push(StreamEvent{
		Type:      evType,
		Headers:   copied,
		EndStream: endStream,
	})
	if fullyClosed {
		h.streams.markStreamDone(s.id)
	}
	return nil
}

func (h *serverConnHandler) OnPriority(frame.FrameHeader, frame.Priority) error {
	return h.guardHeaderBlock()
}

func (h *serverConnHandler) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	// §5.1 (rfc9113.txt:1000) — RST_STREAM is not one of the two frames an idle
	// stream accepts, and §6.4 (:1596) restates it: "If a RST_STREAM frame
	// identifying an idle stream is received, the recipient MUST treat this as a
	// connection error of type PROTOCOL_ERROR." Checking it also stops these
	// being charged as rapid resets, which made the CVE-2023-44487 budget
	// answerable by frames that had never opened a stream at all.
	if h.streams.isIdleStream(fh.StreamID) {
		return connError{code: frame.ErrCodeProtocolError, msg: "RST_STREAM on an idle stream"}
	}
	s := h.streams.lookupStream(fh.StreamID)
	if s == nil {
		// RST_STREAM for an already-finished stream. A flood of these (e.g.
		// resetting streams the server already closed) is the classic Rapid Reset
		// signature, so still account it as rapid.
		return h.streams.onClientRSTStream(fh.StreamID, true)
	}
	// A reset is "rapid" (cheap-to-trigger, no useful work) when the
	// client tears the stream down before completing its request
	// (END_STREAM not yet observed). A reset arriving after the request
	// fully completed is a normal, benign cancellation.
	// Atomically end the remote half and learn whether the request was still
	// open (the rapid-reset signal), then hard-close the stream — RST is an
	// unconditional close regardless of the local half.
	rapid := s.markRemoteEndReset()
	// Deliver the reset event before releasing (and cancelling) the stream.
	s.push(StreamEvent{Type: EventReset, RSTCode: code, EndStream: true})
	h.streams.markStreamDone(fh.StreamID)
	return h.streams.onClientRSTStream(fh.StreamID, rapid)
}

func (h *serverConnHandler) OnSettings(fh frame.FrameHeader, s frame.SettingsParams) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	if fh.Flags&frame.FlagSettingsAck != 0 {
		return nil
	}
	if err := h.streams.applyPeerSettings(s); err != nil {
		return err
	}
	return h.streams.writeSettingsAck()
}

func (h *serverConnHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	// RFC 7540 §8.2: server must not receive PUSH_PROMISE from client.
	// Connection error of type PROTOCOL_ERROR.
	return connError{code: frame.ErrCodeProtocolError, msg: "server received PUSH_PROMISE"}
}

func (h *serverConnHandler) OnPing(fh frame.FrameHeader, payload [8]byte) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	if fh.Flags&frame.FlagPingAck != 0 {
		h.streams.deliverPingAck(payload)
		return nil
	}
	return h.streams.writePingAck(payload)
}

func (h *serverConnHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	// RFC 9113 §6.8 (rfc9113.txt:1990): "Once sent, the sender will ignore frames
	// sent on streams initiated by the receiver if the stream has an identifier
	// higher than the included last stream identifier. Receivers of a GOAWAY frame
	// MUST NOT open additional streams on the connection". For a server the only
	// way to open one is server push, so this is what stops a push racing a
	// shutdown the client has already announced.
	h.streams.notePeerGoAway()
	return nil
}

func (h *serverConnHandler) OnWindowUpdate(fh frame.FrameHeader, increment uint32) error {
	if err := h.guardHeaderBlock(); err != nil {
		return err
	}
	return h.streams.onWindowUpdate(fh.StreamID, increment)
}

// OnOrigin handles ORIGIN frames (RFC 8336). Silently ignored — server side.
func (h *serverConnHandler) OnOrigin(frame.FrameHeader, []string) error {
	return h.guardHeaderBlock()
}

func (h *serverConnHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error {
	return h.guardHeaderBlock()
}

var _ frame.Handler = (*serverConnHandler)(nil)
