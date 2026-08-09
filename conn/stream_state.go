package conn

// streamState is the RFC 9113 §5.1 state of one stream, packed into a word so it
// is read with one atomic load and advanced with one compare-and-swap.
//
// It replaces five booleans — localEnded, remoteEnded, closed, headersSent,
// headersReceived — that used to sit behind a mutex, except headersReceived,
// which was written lock-free from the reader goroutine with nothing saying so.
//
// No bit is separately readable or separately writable, and that is the point.
// Every defect this type exists to prevent came from reading a subset of the
// five and acting on it, or from setting one of them in a place that did not
// also do the thing it implied. A frame that changes two facts about a stream —
// a HEADERS frame carrying END_STREAM changes two — now changes them in one
// indivisible step, instead of two mutex sections with a bespoke boolean return
// for each combination.
//
// The zero value is a live stream on which nothing has yet crossed in either
// direction: RFC 9113 §5.1's "open", which is where a client-initiated stream is
// admitted.
type streamState uint32

const (
	// stRecvFields: a complete request field section has been received. A SECOND
	// field section while this is set is a trailer section (§8.1).
	stRecvFields streamState = 1 << iota
	// stRecvEnded: END_STREAM has been received — or the remote direction never
	// opened at all, which is how a pushed stream begins (§5.1 reserved (local)).
	stRecvEnded
	// stSentFields: a response field section has gone on the wire. §8.2.1 forbids
	// PUSH_PROMISE past this point.
	stSentFields
	// stSentEnded: END_STREAM has gone on the wire.
	stSentEnded
	// stReset: RST_STREAM crossed in either direction. The stream is closed in
	// BOTH directions whatever the other bits say, and nothing further may be
	// sent on it — §5.1 (rfc9113.txt:1082) "An endpoint MUST NOT send frames
	// other than PRIORITY on a closed stream", and §5.4.2 (:1197) "To avoid
	// looping, an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM
	// frame."
	stReset
)

// RecvdFields reports whether a complete request field section has arrived, so
// the next one is a trailer section rather than a request (§8.1).
func (s streamState) RecvdFields() bool { return s&stRecvFields != 0 }

// RemoteEnded reports whether the peer has ended its half — §5.1's "half-closed
// (remote)" or beyond. A frame other than WINDOW_UPDATE, PRIORITY or RST_STREAM
// arriving while this holds is a STREAM_CLOSED stream error (§5.1
// rfc9113.txt:1044).
func (s streamState) RemoteEnded() bool { return s&stRecvEnded != 0 }

// SentFields reports whether the response field section is already on the wire.
func (s streamState) SentFields() bool { return s&stSentFields != 0 }

// LocalEnded reports whether this endpoint has sent END_STREAM.
func (s streamState) LocalEnded() bool { return s&stSentEnded != 0 }

// WasReset reports whether RST_STREAM crossed in either direction.
func (s streamState) WasReset() bool { return s&stReset != 0 }

// Terminal reports whether the stream has reached §5.1's "closed": both halves
// ended, or reset.
func (s streamState) Terminal() bool {
	return s.WasReset() || s&(stRecvEnded|stSentEnded) == stRecvEnded|stSentEnded
}

// Writable reports whether this endpoint may still put a HEADERS or DATA frame
// on this stream. It is the old `!closed && !localEnded`, except that the reset
// half can no longer be forgotten: every reset path sets stReset, because that
// is the only way to record a reset at all.
func (s streamState) Writable() bool { return s&(stReset|stSentEnded) == 0 }

// state returns the stream's current state. One atomic load; no lock.
func (ss *ServerStream) state() streamState { return streamState(ss.st.Load()) }

// advance sets the given bits and returns the state as it was immediately
// before. The previous state is what callers actually need — "was this the first
// reset", "had a field section already arrived, so this one is trailers", "did
// that transition close the stream" are all questions about the edge, not the
// level, and answering them from a separate read is what let two of them race.
func (ss *ServerStream) advance(delta streamState) (before streamState) {
	for {
		old := streamState(ss.st.Load())
		if old&delta == delta {
			return old // nothing to do; every bit is already set
		}
		if ss.st.CompareAndSwap(uint32(old), uint32(old|delta)) {
			return old
		}
	}
}
