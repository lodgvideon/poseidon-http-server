package conn

import (
	"sync"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// streamTable owns a connection's stream identifier space and its live stream
// population. Before it existed, both were spread across a bare
// map[uint32]*ServerStream, a mutex, two atomic counters and a scattering of
// loops, and every caller composed its own answer out of them.
//
// That is not a tidiness complaint. Three shipped defects came out of it and
// each is a different way of getting the same composition wrong:
//
//   - the GOAWAY last-stream-id scanned every key with no odd/even filter,
//     though the two counting loops beside it filtered, so a live push stream
//     could be reported as the last stream the PEER opened — and a client reads
//     that as "everything below was processed" and stops retrying;
//   - a reset set the stream's closed flag on one path and deregistered it on
//     another, so two of the four reset paths left the stream in the map with
//     its context uncancelled;
//   - a stream could be registered before the SETTINGS that size its windows
//     were published, and the retroactive delta did not reach it.
//
// The table answers each of those questions once. Parity lives in one place;
// the counts are maintained rather than scanned; the last peer identifier is a
// field, so there is no loop left in which to forget the filter; and admission
// and release are single exits, so a stream cannot be closed without being
// removed or removed without being closed.
//
// LOCKING. One mutex covers the map, the counters and the maintained totals, so
// a caller never observes them disagreeing. It is a leaf with one deliberate
// exception: admission reads the peer's SETTINGS_INITIAL_WINDOW_SIZE while
// holding it, so that seeding a new stream's send window and the §6.9.2
// retroactive walk over existing streams cannot interleave. peerWindow is
// therefore called with t.mu held and must not take any lock that is ever held
// while acquiring t.mu.
type streamTable struct {
	mu      sync.Mutex
	streams map[uint32]*ServerStream

	// maxClient is the highest client-initiated (odd) identifier ever admitted,
	// refused included: RFC 9113 §5.1.1 forbids reusing one either way. It is
	// what makes "idle" provable for an odd identifier after the stream itself
	// is gone, and it is the GOAWAY last-stream-id (§6.8) — a field rather than
	// a scan, so the parity filter cannot be omitted.
	maxClient uint32

	// nextPush is the next unused server-initiated (even) identifier. It plays
	// the same role for even identifiers that maxClient plays for odd ones.
	nextPush uint32

	// nClient and nPush are the live populations by parity. The limit this
	// server advertises governs what the CLIENT may open, and the peer's limit
	// governs what this server may push, so the two are counted apart. They were
	// O(n) scans, which is how one of them came to be written without its filter.
	nClient int
	nPush   int

	// peerWindow reports the peer's current SETTINGS_INITIAL_WINDOW_SIZE. Called
	// under t.mu; see the locking note on the type.
	peerWindow func() uint32
}

func newStreamTable(peerWindow func() uint32) *streamTable {
	return &streamTable{
		streams:    map[uint32]*ServerStream{},
		nextPush:   2, // the lowest legal server-initiated identifier
		peerWindow: peerWindow,
	}
}

// lookup returns the live stream for the identifier, or nil.
//
// A nil answer says only "not live". It does not distinguish idle from closed,
// and those two demand opposite reactions under RFC 9113 §5.1 — ask idle for
// that.
func (t *streamTable) lookup(id uint32) *ServerStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams[id]
}

// idle reports whether the identifier names a stream that has never been opened
// — RFC 9113 §5.1's "idle" state.
//
// Parity decides which counter answers, which is the whole reason this is one
// function rather than a comparison written out at each call site.
func (t *streamTable) idle(id uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.idleLocked(id)
}

func (t *streamTable) idleLocked(id uint32) bool {
	if id%2 == 1 {
		return id > t.maxClient
	}
	return id >= t.nextPush
}

// validateClientID enforces RFC 9113 §5.1.1 for a newly opened client stream:
// "The identifier of a newly established stream MUST be numerically greater
// than all streams that the initiating endpoint has opened or reserved... An
// endpoint that receives an unexpected stream identifier MUST respond with a
// connection error (Section 5.4.1) of type PROTOCOL_ERROR."
func (t *streamTable) validateClientID(id uint32) error {
	if id%2 == 0 {
		return connError{code: frame.ErrCodeProtocolError, msg: "client-initiated stream ID must be odd"}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if id <= t.maxClient {
		return connError{code: frame.ErrCodeProtocolError, msg: "client stream ID must exceed all previous client streams"}
	}
	return nil
}

// admitClient registers a client-initiated stream, seeds its send window from
// the peer's advertised SETTINGS_INITIAL_WINDOW_SIZE, and reports whether the
// advertised concurrency limit left room for it.
//
// limit is what this server advertised in SETTINGS_MAX_CONCURRENT_STREAMS; only
// client streams count against it, because that is what the setting governs.
// Zero means unlimited.
//
// The identifier is consumed either way — §5.1.1 forbids reuse whether or not
// the stream was accepted — so a refusal still advances maxClient, and a
// refusing caller must not process the stream.
//
// Seeding happens under the table lock together with the registration, so the
// §6.9.2 retroactive window delta either sees this stream or supplies its
// starting value, never both and never neither.
func (t *streamTable) admitClient(id uint32, s *ServerStream, limit int) bool {
	t.mu.Lock()
	initial := t.peerWindow()
	if id > t.maxClient {
		t.maxClient = id
	}
	if limit > 0 && t.nClient >= limit {
		t.mu.Unlock()
		return false
	}
	s.mu.Lock()
	s.sendWindow = int32(initial) //nolint:gosec // G115: INITIAL_WINDOW_SIZE ≤ 2^31-1, checked in validatePeerSettings
	s.mu.Unlock()
	t.streams[id] = s
	t.nClient++
	t.mu.Unlock()
	return true
}

// reservePush allocates the next server-initiated identifier and registers the
// pushed stream against it, under one lock so the identifier cannot be burned
// by a push that then fails to register.
//
// limit is the peer's SETTINGS_MAX_CONCURRENT_STREAMS; RFC 9113 §5.1.2:
// "Endpoints MUST NOT exceed the limit set by their peer." A promised stream
// counts from the moment the PUSH_PROMISE is sent, and only server-initiated
// streams count against this limit. ok is false when there is no room, and no
// identifier is consumed in that case.
//
// The caller supplies the stream because it must exist before the PUSH_PROMISE
// frame is written; it is registered here and the identifier returned so the
// caller can name it on the wire.
func (t *streamTable) reservePush(s *ServerStream, limit uint32) (id uint32, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit != noStreamLimit && uint32(t.nPush) >= limit { //nolint:gosec // G115: nPush is bounded by this same limit
		return 0, false
	}
	initial := t.peerWindow()
	id = t.nextPush
	t.nextPush += 2
	// Finish the stream BEFORE publishing it. Once it is in the map the reader
	// goroutine can find it — a client is free to send WINDOW_UPDATE or
	// RST_STREAM for an identifier the moment it learns of it — and a half-built
	// stream answers with id 0 and a nil cancel.
	s.mu.Lock()
	s.id = id
	s.sendWindow = int32(initial) //nolint:gosec // G115: as above
	s.mu.Unlock()
	t.streams[id] = s
	t.nPush++
	return id, true
}

// release removes a stream from the live population. It is the only exit: a
// stream that is finished, reset or refused leaves through here, so "closed"
// and "deregistered" cannot drift apart the way they did when each reset path
// decided for itself.
//
// Returns the stream if it was live, so the caller can cancel its context
// outside the lock. Releasing an identifier that is not live is a no-op —
// resets arrive for streams that are already gone.
func (t *streamTable) release(id uint32) *ServerStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.streams[id]
	if s == nil {
		return nil
	}
	delete(t.streams, id)
	if id%2 == 1 {
		t.nClient--
	} else {
		t.nPush--
	}
	return s
}

// live reports the total number of streams in any non-closed state. Zero means
// the connection is genuinely idle, which is a different question from whether
// a new stream has arrived recently.
func (t *streamTable) live() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nClient + t.nPush
}

// lastPeerID is the GOAWAY last-stream-id: RFC 9113 §6.8 (rfc9113.txt:2013),
// "the highest-numbered stream identifier for which the sender of the GOAWAY
// frame might have taken some action on or might yet take action on" — among
// streams the PEER initiated. §5.1.1 reserves even identifiers for this server,
// so one can never be the answer.
func (t *streamTable) lastPeerID() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxClient
}

// applyInitialWindow publishes a new SETTINGS_INITIAL_WINDOW_SIZE and carries
// RFC 9113 §6.9.2's retroactive delta to every live stream, both under the table
// lock.
//
// The atomicity is the point. Publishing and walking as two separate steps
// leaves a gap in which a stream can be admitted after the new value is visible
// and still be caught by the walk — so the delta is applied twice, the server
// believes it may send more than the peer allowed, and §6.9.1 obliges the peer
// to answer with a connection error. The mirror gap loses the delta entirely.
// Admission seeds under this same lock, so a concurrent admission is either
// seeded from the old value and walked, or seeded from the new value and not
// walked.
//
// publish runs under t.mu and reports the old and new values. Lock order is
// t.mu then psMu, matching peerWindow; nothing may take t.mu while holding psMu.
// fn runs per stream, also under t.mu, and reports the first overflow.
func (t *streamTable) applyInitialWindow(publish func() (oldWin, newWin uint32), adjust func(*ServerStream, int64) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	oldWin, newWin := publish()
	if oldWin == newWin {
		return nil
	}
	delta := int64(newWin) - int64(oldWin)
	var firstErr error
	for _, st := range t.streams {
		if err := adjust(st, delta); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// drain empties the table and returns everything that was in it, for connection
// teardown.
func (t *streamTable) drain() []*ServerStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	all := make([]*ServerStream, 0, len(t.streams))
	for id, s := range t.streams {
		all = append(all, s)
		delete(t.streams, id)
	}
	t.nClient, t.nPush = 0, 0
	return all
}

// noStreamLimit is the absent SETTINGS_MAX_CONCURRENT_STREAMS: RFC 9113 §6.5.2
// says the setting "is initially unlimited".
const noStreamLimit = ^uint32(0)
