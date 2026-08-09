package conn

import (
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// UpgradedRequest carries the HTTP/1.1 request that initiated an h2c Upgrade,
// so the connection can honour RFC 7540 §3.2:
//
//	"The HTTP/1.1 request that is sent prior to upgrade is assigned a stream
//	 identifier of 1 ... Stream 1 is implicitly "half-closed" from the client
//	 toward the server ... After commencing the HTTP/2 connection, stream 1 is
//	 used for the response."
//
// Without this the response to the upgrading request is never sent and a
// conformant client — which does not open stream 1 itself — hangs.
//
// Headers are the already-translated HTTP/2 request fields (pseudo-headers
// first, connection-specific fields removed).
//
// The HTTP2-Settings header field is deliberately NOT represented here. Its
// governing rule is a precondition on upgrading at all — "A server MUST NOT
// upgrade the connection to HTTP/2 if this header field is not present or if
// more than one is present" (RFC 7540 §3.2.1) — so it is decoded and validated
// by the caller before this type is constructed. Its values are superseded
// moments later by the client's preface SETTINGS, which §3.2 obliges the client
// to send on receiving the 101.
type UpgradedRequest struct {
	Headers []hpack.HeaderField
}

// seedUpgradedStream registers stream 1 in the half-closed (remote) state and
// delivers the upgrading request to AcceptStream, exactly as if it had arrived
// as a HEADERS frame with END_STREAM set.
//
// Called once from NewServerConn after the handshake and before the reader
// goroutine starts, so it needs no additional synchronisation. Registering the
// stream also advances maxClientStreamID to 1, which makes the client's next
// stream 3 — the monotonic-ID rule of RFC 9113 §5.1.1 — fall out for free.
func (sc *ServerConn) seedUpgradedStream(up *UpgradedRequest) {
	s := newServerStream(1, sc.opts.StreamEventBuffer, sc, int32(sc.opts.AdvertisedSettings.InitialWindowSize)) //nolint:gosec // G115: AdvertisedSettings.defaulted() clamps InitialWindowSize to ≤ 2^31-1
	if !sc.registerStream(1, s) {
		// Only reachable with MaxConcurrentStreams == 0, which defaulted()
		// forbids. Nothing to clean up: registerStream already reset the stream.
		return
	}
	// The request headers have been received (as HTTP/1.1). Recording that keeps
	// the stream's state truthful, so a later HEADERS frame from the client on
	// stream 1 is not mistaken for a second request. Combined with the
	// half-closed (remote) transition below it draws RST_STREAM(STREAM_CLOSED),
	// which is what RFC 9113 §5.1 requires of that state — a conformant client
	// sends nothing more on stream 1 after upgrading.
	s.advance(stRecvFields)
	s.push(StreamEvent{
		Type:      EventHeaders,
		Headers:   up.Headers,
		EndStream: true,
	})
	// Half-closed (remote): the client completed the request as HTTP/1.1 and
	// will never send DATA on this stream. markRemoteEnd reports whether BOTH
	// halves are now closed; the response has not been written yet, so it is
	// false here and the stream correctly stays registered.
	s.markRemoteEnd()
}
