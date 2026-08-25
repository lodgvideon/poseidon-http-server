package http3server

import (
	"crypto/tls"
	"errors"
	"sync/atomic"

	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// maxControlFrameLen bounds the declared length of a frame this server will buffer
// on the client's control stream. Control frames (SETTINGS, GOAWAY, MAX_PUSH_ID)
// are small, so a larger declared length is refused as H3_EXCESSIVE_LOAD rather
// than buffered: without a cap a peer declares a huge frame, dribbles it, and the
// reader's buffer grows without bound. http3.FrameReader defaults to unlimited, so
// this must be set explicitly.
const maxControlFrameLen uint64 = 1 << 16

// fieldLineOverhead is the per-field overhead RFC 9114 §4.2.2 charges when sizing a
// field section: the size "is calculated based on the uncompressed size of fields,
// including the length of the name and value in bytes plus an overhead of 32 bytes
// for each field".
const fieldLineOverhead uint64 = 32

// errH3Conn reports that the connection has been closed with an HTTP/3 error code
// because the peer violated the protocol. It is the serveConn loop's signal to stop
// serving the connection; nothing inspects it, the CONNECTION_CLOSE carries the
// reason to the peer.
var errH3Conn = errors.New("http3server: connection error")

// connState is one connection's HTTP/3 state: what the peer's SETTINGS said, and
// the unidirectional streams it opened.
//
// # Concurrency
//
// The serveConn goroutine owns the connection and every field below except
// peerMaxFieldSection; the per-request goroutines read that one. It is an atomic
// rather than a mutex-guarded field deliberately: it is written at most once per
// connection (when the peer's SETTINGS arrive) and read once per response, so a
// mutex would serialise every response on a connection behind a value that almost
// never changes, while an atomic load is a plain load on every architecture this
// builds for. The alternative of copying the value to each request goroutine at
// spawn time is wrong rather than slow — SETTINGS can arrive after a request stream
// does (§7.2.4.2), and the copy would be stale. This mirrors the client's
// http3.Client.maxFieldSection, which is an atomic for the same reason.
type connState struct {
	// peerMaxFieldSection is the peer's SETTINGS_MAX_FIELD_SECTION_SIZE (§4.2.2),
	// the limit a response field section is held to. It starts at this server's own
	// maxFieldSection: the parameter's default is unlimited (§7.2.4.1), so this is
	// not the peer's limit but a local buffering policy for a peer that stated
	// none, and it is what the server enforced for every response before it read
	// the peer's SETTINGS at all.
	peerMaxFieldSection atomic.Uint64

	// tlsState is the connection's completed handshake, snapshotted once by
	// serveConn and shared read-only by every request on the connection (#102).
	tlsState tls.ConnectionState

	// Below here: written and read only by the serveConn goroutine.

	// pendingUni holds accepted unidirectional streams whose leading stream-type
	// varint has not arrived whole yet. It is bounded twice over: by the peer's
	// unidirectional stream limit (maxStreamsUni), and per entry by the 8-byte
	// maximum length of a QUIC varint, since a complete one always parses.
	pendingUni []*pendingUniStream

	control       *quic.Stream      // the peer's control stream, once identified (§6.2.1)
	controlFrames http3.FrameReader // frames buffered off that stream
	settingsRead  bool              // its first frame has been read and was SETTINGS

	// The two identifier spaces §5.2 and §7.2.7 require a receiver to keep
	// monotonic, whether or not it acts on them. Neither is a push feature: they
	// are the state the "MUST NOT go backwards / forwards" rules are checked
	// against, and without them a peer contradicting itself goes unnoticed.
	maxPushID     uint64 // highest MAX_PUSH_ID received (§7.2.7); must not decrease
	maxPushIDSeen bool
	goawayID      uint64 // last GOAWAY identifier received (§5.2); must not increase
	goawaySeen    bool

	// The peer's QPACK instruction streams (RFC 9204 §4.2). They are retained and
	// drained rather than acted on: this server speaks the static-table profile
	// (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0), so a conforming peer's encoder stream
	// carries nothing that changes our state and its decoder stream only
	// acknowledges sections we encoded without the dynamic table. Draining is not
	// decoration — an undrained stream's flow-control window fills and the peer
	// blocks on it.
	qpackEnc *quic.Stream
	qpackDec *quic.Stream
}

// newConnState returns the state for one connection, with the response field
// section bounded by this server's own limit until the peer's SETTINGS say
// otherwise (§7.2.4.2: an endpoint sends messages before the peer's SETTINGS
// arrive rather than waiting for them).
func newConnState() *connState {
	cs := &connState{}
	cs.peerMaxFieldSection.Store(maxFieldSection)
	return cs
}

// pendingUniStream is an accepted unidirectional stream whose type varint is still
// arriving, with the bytes received so far.
type pendingUniStream struct {
	stream *quic.Stream
	buf    []byte
}

// serviceUni accepts the peer's newly arrived unidirectional streams, identifies
// each by its leading stream-type varint (RFC 9114 §6.2), and reads whatever has
// arrived on the control stream. It never blocks: it processes only bytes already
// received, and runs on the serveConn goroutine after each Poll.
//
// A non-nil return means the connection has already been closed with the HTTP/3
// error code the violation calls for, and the caller must stop serving it.
func (cs *connState) serviceUni(c *quic.Conn) error {
	for us := c.AcceptUniStream(); us != nil; us = c.AcceptUniStream() {
		cs.pendingUni = append(cs.pendingUni, &pendingUniStream{stream: us})
	}
	kept := cs.pendingUni[:0]
	for _, u := range cs.pendingUni {
		u.buf = append(u.buf, u.stream.Recv()...)
		typ, n, err := http3.ReadStreamType(u.buf)
		if err != nil {
			kept = append(kept, u) // ErrNeedMore: the type varint is not complete
			continue
		}
		if err := cs.routeUni(c, typ, u.stream, u.buf[n:]); err != nil {
			cs.pendingUni = kept
			return err
		}
	}
	cs.pendingUni = kept
	cs.drainQPACK()
	if err := cs.readControl(c); err != nil {
		return err
	}
	// After readControl, not before: a control stream that opens with the wrong
	// frame AND is closed in the same pass has violated two rules, and
	// H3_MISSING_SETTINGS is the more specific verdict on it.
	return cs.checkCriticalStreams(c)
}

// checkCriticalStreams reports a connection error if the peer has ended any stream
// the connection cannot do without: its control stream, or either QPACK
// instruction stream.
//
// RFC 9114 §6.2.1: "The sender MUST NOT close the control stream, and the receiver
// MUST NOT request that the sender close the control stream. If either control
// stream is closed at any point, this MUST be treated as a connection error of type
// H3_CLOSED_CRITICAL_STREAM." RFC 9204 §4.2 says the same of the QPACK encoder and
// decoder streams: "Closure of either unidirectional stream type MUST be treated as
// a connection error of type H3_CLOSED_CRITICAL_STREAM."
//
// Both endings count, which is why quic.Stream.Finished is the right predicate: it
// reports a clean FIN or a peer RESET_STREAM, and §8.1 defines the code as "A
// stream required by the HTTP/3 connection was closed or reset". A stream that is
// merely open and idle is not finished, so a conforming peer never trips this — the
// production HTTP/3 client opens all three and keeps them open for the connection's
// life, and a peer with nothing to say on a QPACK stream is told by §4.2 to not
// open one at all ("An endpoint MAY avoid creating an encoder stream if it will not
// be used") rather than to open and close it.
//
// A graceful peer teardown does not come through here either: that is a QUIC
// CONNECTION_CLOSE, which ends Poll before serviceUni runs again, not a FIN on any
// stream. This mirrors the client's http3.Client.checkCriticalStreams.
func (cs *connState) checkCriticalStreams(c *quic.Conn) error {
	for _, s := range [...]*quic.Stream{cs.control, cs.qpackEnc, cs.qpackDec} {
		if s != nil && s.Finished() {
			return connError(c, http3.H3ClosedCriticalStream)
		}
	}
	return nil
}

// routeUni dispatches one identified unidirectional stream by its type (RFC 9114
// §6.2). rest is the bytes that arrived after the type varint.
func (cs *connState) routeUni(c *quic.Conn, typ uint64, s *quic.Stream, rest []byte) error {
	switch typ {
	case http3.StreamTypeControl:
		// "Only one control stream per peer is permitted; receipt of a second
		// stream claiming to be a control stream MUST be treated as a connection
		// error of type H3_STREAM_CREATION_ERROR" (§6.2.1).
		if cs.control != nil {
			return connError(c, http3.H3StreamCreationError)
		}
		cs.control = s
		cs.controlFrames.SetMaxFrameLen(maxControlFrameLen)
		// Frame bytes coalesced with the type varint are already off the stream:
		// dropping them here would desync the control stream permanently.
		cs.controlFrames.Feed(rest)
	case http3.StreamTypeQPACKEncoder:
		if cs.qpackEnc != nil {
			return connError(c, http3.H3StreamCreationError) // one encoder stream (RFC 9204 §4.2)
		}
		cs.qpackEnc = s
	case http3.StreamTypeQPACKDecoder:
		if cs.qpackDec != nil {
			return connError(c, http3.H3StreamCreationError) // one decoder stream (RFC 9204 §4.2)
		}
		cs.qpackDec = s
	case http3.StreamTypePush:
		// "Only servers can push; if a server receives a client-initiated push
		// stream, this MUST be treated as a connection error of type
		// H3_STREAM_CREATION_ERROR" (§6.2.2).
		return connError(c, http3.H3StreamCreationError)
	default:
		// An unknown stream type — GREASE included — "MUST NOT" be a connection
		// error; the recipient aborts reading it instead (§6.2).
		_ = s.StopSending(http3.H3StreamCreationError)
	}
	return nil
}

// drainQPACK discards whatever has arrived on the peer's QPACK instruction
// streams. See connState.qpackEnc for why the bytes are dropped rather than
// applied, and why they must still be read.
func (cs *connState) drainQPACK() {
	if cs.qpackEnc != nil {
		_ = cs.qpackEnc.Recv()
	}
	if cs.qpackDec != nil {
		_ = cs.qpackDec.Recv()
	}
}

// readControl parses whole frames off the peer's control stream and applies the
// ones this server acts on. The first frame MUST be SETTINGS (§6.2.1); the rules
// for what may follow are §7.2. A violation closes the connection and returns
// errH3Conn.
func (cs *connState) readControl(c *quic.Conn) error {
	if cs.control == nil {
		// The peer has not opened a control stream yet. That is not (yet) an error:
		// §7.2.4.2 has each endpoint act on initial values "before the peer's
		// SETTINGS frame has arrived, as packets carrying the settings can be lost
		// or delayed", so a request that overtakes the control stream is served
		// with the defaults rather than refused.
		//
		// Nothing HERE bounds how long a peer may go without opening one, and
		// deliberately so: the bound is QUIC's max_idle_timeout, which #168 made this
		// server advertise and which reaps a peer that opens no stream at all on
		// exactly its advertised schedule (measured; pinned by
		// TestServer_PeerWithNoControlStreamIsIdleClosed). RFC 9114 names no code and
		// no deadline for a control stream that never arrives, and a locally-invented
		// timer could only mis-fire on the conforming-but-delayed client §7.2.4.2
		// anticipates — which is why issue #143 was closed without one.
		return nil
	}
	if data := cs.control.Recv(); len(data) > 0 {
		cs.controlFrames.Feed(data)
	}
	for {
		typ, payload, err := cs.controlFrames.ReadFrame()
		if errors.Is(err, http3.ErrNeedMore) {
			break // the rest of this frame has not arrived
		}
		if err != nil {
			// The only other error the reader reports is a declared frame length
			// past maxControlFrameLen, which is refused rather than buffered.
			return connError(c, http3.H3ExcessiveLoad)
		}
		if !cs.settingsRead {
			// "Each side MUST initiate a single control stream at the beginning of
			// the connection and send its SETTINGS frame as the first frame on this
			// stream. If the first frame of the control stream is any other frame
			// type, this MUST be treated as a connection error of type
			// H3_MISSING_SETTINGS" (§6.2.1).
			if typ != http3.FrameSettings {
				return connError(c, http3.H3MissingSettings)
			}
			settings, perr := http3.ParseSettings(payload)
			if perr != nil {
				if errors.Is(perr, http3.ErrH3Frame) {
					return connError(c, http3.H3FrameError) // a setting cut off by the frame length (§7.1)
				}
				// A duplicate identifier, or a reserved HTTP/2 setting the peer
				// "MUST NOT" send (§7.2.4, §7.2.4.1).
				return connError(c, http3.H3SettingsErrorCode)
			}
			cs.applySettings(settings)
			cs.settingsRead = true
			continue
		}
		switch typ {
		case http3.FrameSettings:
			// SETTINGS "MUST NOT be sent subsequently. If an endpoint receives a
			// second SETTINGS frame on the control stream, the endpoint MUST respond
			// with a connection error of type H3_FRAME_UNEXPECTED" (§7.2.4).
			return connError(c, http3.H3FrameUnexpected)
		case http3.FrameData, http3.FrameHeaders, http3.FramePushPromise, 0x02, 0x06, 0x08, 0x09:
			// DATA (§7.2.1) and HEADERS (§7.2.2) on a control stream, a
			// PUSH_PROMISE at a server (§7.2.5), and the reserved HTTP/2-carryover
			// types (§7.2.8) are each H3_FRAME_UNEXPECTED.
			return connError(c, http3.H3FrameUnexpected)
		case http3.FrameCancelPush, http3.FrameMaxPushID, http3.FrameGoaway:
			// The three control frames that carry exactly one identifier. The rules
			// are in identifierFault, so this switch keeps naming frame types rather
			// than growing a second subject.
			if code := cs.identifierFault(typ, payload); code != 0 {
				return connError(c, code)
			}

		default:
			// Genuinely unknown types and the GREASE types of §7.2.8 MUST be
			// ignored (§9). Nothing else reaches here: every frame type this
			// server has a rule for is named above.
		}
	}
	return nil
}

// identifierFault applies the rules RFC 9114 puts on the three control frames
// that carry exactly one identifier, and updates the state those rules are
// checked against. It returns the §8.1 code the connection must be closed with,
// or 0 when the frame is acceptable.
//
// All three used to be discarded, on the reasoning that this server never pushes
// so a push-ID frame has nothing to control. That is right about push FULFILMENT
// and wrong about the push-ID SPACE: the identifier rules bind a receiver whether
// or not it uses the identifiers, and H3_ID_ERROR was emitted nowhere in the
// package before this.
//
// Framing is judged first, because a payload that is not one identifier is not a
// question about identifiers at all (§7.1).
func (cs *connState) identifierFault(typ uint64, payload []byte) uint64 {
	id, ok := singleVarintPayload(payload)
	if !ok {
		return http3.H3FrameError
	}
	switch typ {
	case http3.FrameCancelPush:
		// §7.2.3 — "If a server receives a CANCEL_PUSH frame for a Push ID that
		// has not yet been mentioned by a PUSH_PROMISE frame, this MUST be treated
		// as a connection error of type H3_ID_ERROR." This server never sends
		// PUSH_PROMISE, so no Push ID has ever been mentioned on this connection
		// and every CANCEL_PUSH names one that was not. The section's other rule —
		// a Push ID above the maximum — points the same way, since no maximum has
		// been raised for a server that does not push.
		return http3.H3IDError

	case http3.FrameMaxPushID:
		// §7.2.7 — "A server MUST treat receipt of a MAX_PUSH_ID frame that
		// contains a smaller value than previously received as a connection error
		// of type H3_ID_ERROR."
		if cs.maxPushIDSeen && id < cs.maxPushID {
			return http3.H3IDError
		}
		cs.maxPushID, cs.maxPushIDSeen = id, true

	case http3.FrameGoaway:
		// §5.2 — "the identifier in each frame MUST NOT be greater than the
		// identifier in any previous frame, since clients might already have
		// retried unprocessed requests on another HTTP connection. Receiving a
		// GOAWAY containing a larger identifier than previously received MUST be
		// treated as a connection error of type H3_ID_ERROR."
		//
		// Only the identifier rule is enforced. Acting on a peer's GOAWAY — and
		// sending one of this server's own — is issue #80 and group E of #212;
		// tracking the value is what that will build on.
		if cs.goawaySeen && id > cs.goawayID {
			return http3.H3IDError
		}
		cs.goawayID, cs.goawaySeen = id, true
	}
	return 0
}

// singleVarintPayload parses a frame payload that RFC 9114 defines as exactly one
// variable-length integer — CANCEL_PUSH (§7.2.3), MAX_PUSH_ID (§7.2.7) and GOAWAY
// (§5.2) each carry one identifier and nothing else.
//
// It reports false for both ways §7.1 says such a payload can be wrong: "A frame
// payload that contains additional bytes after the identified fields or a frame
// payload that terminates before the end of the identified fields MUST be treated
// as a connection error of type H3_FRAME_ERROR." A zero-length CANCEL_PUSH is the
// second of those, and was accepted before this.
func singleVarintPayload(payload []byte) (uint64, bool) {
	v, n := readVarint(payload)
	if n == 0 || n != len(payload) {
		return 0, false
	}
	return v, true
}

// readVarint decodes one QUIC variable-length integer (RFC 9000 §16) and returns
// it with the number of bytes consumed, or n == 0 if b does not hold a whole one.
// The two most significant bits of the first byte select the length; the rest of
// that byte is the top of the value.
//
// Written here rather than taken from the codec because poseidon-http-client keeps
// its varint reader in an internal package. It is a dozen lines and the format is
// frozen, so a local copy is cheaper than widening the dependency's API.
func readVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6) // 1, 2, 4 or 8
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// applySettings records the peer settings this server acts on. An identifier it
// does not understand "MUST" be ignored (§7.2.4), and an absent one leaves the
// field at its default (§7.2.4.1) — so a peer that sends SETTINGS without
// SETTINGS_MAX_FIELD_SECTION_SIZE keeps the local default seeded by newConnState
// rather than losing the bound entirely.
//
// SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS are
// deliberately not acted on: they size a dynamic table on the peer's decoder that
// this server's static-profile encoder never inserts into (RFC 9204 §3.2.3).
func (cs *connState) applySettings(settings []http3.Setting) {
	for _, st := range settings {
		if st.ID == http3.SettingMaxFieldSectionSize {
			cs.peerMaxFieldSection.Store(st.Value)
		}
	}
}

// connError closes the connection with an HTTP/3 error code (§8.1) and returns
// errH3Conn so the caller stops serving it. CloseWithError is idempotent, so the
// serveConn deferred Close that follows does not overwrite the code with NO_ERROR.
func connError(c *quic.Conn, code uint64) error {
	_ = c.CloseWithError(true, code, "")
	return errH3Conn
}
