package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ServerConn manages a single server-side HTTP/2 connection.
// Goroutine-safe for AcceptStream and Close; per-stream methods
// are single-goroutine.
type ServerConn struct {
	transport net.Conn
	fr        *frame.Framer
	enc       *hpack.Encoder
	dec       *hpack.Decoder
	opts      ServerConnOptions

	// peerSettings is the most recently observed client SETTINGS.
	// Guarded by psMu.
	psMu         sync.RWMutex
	peerSettings frame.SettingsParams

	wmu sync.Mutex // serializes all writes to fr

	// tbl owns the stream identifier space and the live stream population:
	// parity rules, admission, release, counting, and the idle/closed
	// distinction. It replaced a bare map plus a mutex plus two counters that
	// every caller composed its own answer out of — see conn/stream_table.go for
	// the three defects that produced.
	tbl *streamTable

	// fcMu guards the connection-level recv window.
	fcMu              sync.Mutex
	connRecvWindow    int32
	connRefundPending uint32

	// fcOutMu guards the outbound connection-level send window.
	fcOutMu            sync.Mutex
	fcOutCond          *sync.Cond
	peerConnSendWindow int32

	closed     atomic.Bool
	readerDone chan struct{}

	// handler is the single frame.Handler used for BOTH the SETTINGS handshake
	// and the reader loop, so a header block split across that boundary keeps
	// its pending CONTINUATION state instead of being lost.
	handler *serverConnHandler

	// connCtx is cancelled when the connection closes (or its parent ctx is
	// cancelled). Per-stream contexts derive from it, so closing the connection
	// cancels every in-flight handler.
	connCtx    context.Context
	connCancel context.CancelFunc

	// acceptCh delivers new client-initiated streams to AcceptStream.
	acceptCh chan *ServerStream

	// pingMu guards pingWaiters. pingCounter produces unique payloads.
	pingMu      sync.Mutex
	pingWaiters map[[8]byte]chan struct{}
	pingCounter atomic.Uint64

	// goAwayRequested flags that the server has initiated GOAWAY.
	goAwayRequested atomic.Bool

	// goAwaySentID is the last stream identifier carried by the most recent
	// GOAWAY, so a later one can never name a larger stream (RFC 9113 §6.8).
	// Seeded to the maximum as the "nothing sent yet" sentinel. Guarded by wmu,
	// which every GOAWAY write site already holds across its write.
	goAwaySentID uint32

	// peerGoAway records that the CLIENT has sent GOAWAY. After that the server
	// must not create new streams on this connection, which for a server means
	// no server push (RFC 9113 §6.8).
	peerGoAway atomic.Bool

	// rapidResetCount accumulates client-initiated RST_STREAM frames that
	// reset a stream before it produced useful work (CVE-2023-44487).
	// Compared against opts.rapidResetBudget(). Atomic: incremented by the
	// single reader goroutine, read on the same path; no allocation.
	rapidResetCount atomic.Uint32

	// Stats counters.
	atomicBytesSent       atomic.Int64
	atomicBytesReceived   atomic.Int64
	atomicFramesSent      atomic.Int64
	atomicFramesReceived  atomic.Int64
	atomicStreamsAccepted atomic.Uint32
}

// ServerConnOptions configures the server-side connection.
type ServerConnOptions struct {
	// AdvertisedSettings are sent in the server's SETTINGS frame.
	AdvertisedSettings AdvertisedSettings
	// StreamEventBuffer is the per-stream event channel capacity.
	StreamEventBuffer int
	// KeepaliveInterval, when non-zero, enables a background keepalive
	// loop. Zero disables keepalive.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout is the max time to wait for PING ACK before
	// closing the connection. Defaults to max(interval*5, 5s).
	KeepaliveTimeout time.Duration
	// MaxRapidResets bounds the number of client-initiated RST_STREAM
	// frames that reset a stream before it produced useful work, before
	// the server treats the connection as a Rapid Reset flood
	// (CVE-2023-44487) and tears it down with GOAWAY(ENHANCE_YOUR_CALM).
	//
	//   0  => secure default: max(MaxConcurrentStreams*4, rapidResetFloor)
	//   <0 => mitigation disabled
	//   >0 => explicit budget
	//
	// Mirrors the Go x/net/http2 fix philosophy: secure-by-default, with
	// a budget proportional to the advertised stream concurrency so that
	// legitimate cancellations never trip it under normal operation.
	MaxRapidResets int

	// HandshakeTimeout bounds the time allowed to complete the HTTP/2
	// connection preface + SETTINGS exchange (RFC 7540 §3.5). A client that
	// connects but trickles the preface/SETTINGS slowly is dropped once the
	// deadline elapses — a Slowloris defense at the connection-establishment
	// stage. The deadline is cleared once the handshake completes, so it does
	// NOT act as a blanket connection read deadline and never interferes with
	// long-lived, multiplexed HTTP/2 keep-alive traffic.
	//
	//   0  => secure default (defaultHandshakeTimeout)
	//   <0 => disabled
	//   >0 => explicit timeout
	HandshakeTimeout time.Duration

	// ConnRecvWindow optionally enlarges the connection-level HTTP/2 flow-control
	// receive window (RFC 9113 §6.9.1): the total unacknowledged request-body
	// bytes the server accepts across ALL streams before the peer must await a
	// connection WINDOW_UPDATE. The protocol default is 64 KiB, which throttles
	// large uploads into many WINDOW_UPDATE round-trips; setting a larger value
	// makes the server emit one initial WINDOW_UPDATE at connection start (as
	// net/http2's server does with a ~1 MiB default). This is distinct from
	// AdvertisedSettings.InitialWindowSize, which is the PER-STREAM window.
	//
	//   ≤ 64 KiB (incl. 0) => protocol default; no enlargement
	//   > 64 KiB           => enlarge to this value (clamped to 2^31-1)
	ConnRecvWindow int32

	// UpgradedRequest, when non-nil, means this connection was established via
	// the HTTP/1.1 h2c Upgrade mechanism (RFC 7540 §3.2) rather than prior
	// knowledge. The request that triggered the upgrade is seeded onto stream 1
	// in the half-closed (remote) state, so the response to it is delivered on
	// stream 1 as the RFC requires. nil for every other start mode.
	UpgradedRequest *UpgradedRequest
}

// defaultHandshakeTimeout is the secure-by-default bound on completing the
// HTTP/2 handshake. Generous enough for high-latency clients yet short enough
// to shed Slowloris-style connections that never finish the preface.
const defaultHandshakeTimeout = 10 * time.Second

// defaultStreamEventBuffer is the per-stream event channel capacity. It absorbs
// the scheduling gap between the single reader goroutine and one handler
// goroutine; the peer's flow-control window is what bounds how far ahead the
// reader can get, so this only has to cover jitter, not backlog.
const defaultStreamEventBuffer = 8

// rapidResetFloor is the minimum Rapid Reset budget regardless of how
// small MaxConcurrentStreams is, so low-concurrency configs still tolerate
// a reasonable burst of legitimate cancellations.
const rapidResetFloor = 100

// maxAcceptQueueDepth caps how large acceptQueueDepth will size the accept
// queue. The queue is allocated eagerly, once per connection during the
// handshake, so its depth is memory an idle connection pays for before it has
// carried a single request — and MaxConcurrentStreams is a uint32 an operator
// may set arbitrarily high, which handed straight to make() would allocate tens
// of gigabytes per connection. Above the cap the queue stops tracking the
// advertised limit and overflow becomes reachable again; that is answered
// correctly, with RST_STREAM(REFUSED_STREAM), rather than silently.
const maxAcceptQueueDepth = 1024

// acceptQueueDepth is how many admitted-but-not-yet-delivered streams the
// connection can hold for AcceptStream.
//
// Derived from the advertised SETTINGS_MAX_CONCURRENT_STREAMS rather than being
// a number of its own. The two used to be independent literals — a 64-slot
// channel against an advertised 100 — so a client that took the server at its
// word lost every stream past the 64th, and lost it to RST_STREAM(CANCEL),
// which forbids a retry (issue #119). The advertised limit is the promise the
// peer acts on, so it is the only number allowed to govern how many streams the
// connection must be able to hold.
//
// A zero MaxConcurrentStreams means "no advertised limit" (streamTable.admitClient
// treats it that way); an unbounded queue is not on offer, so the cap applies.
func (o ServerConnOptions) acceptQueueDepth() int {
	n := o.AdvertisedSettings.MaxConcurrentStreams
	if n == 0 || n > maxAcceptQueueDepth {
		return maxAcceptQueueDepth
	}
	return int(n)
}

func (o ServerConnOptions) defaulted() ServerConnOptions {
	// Always fully default the advertised settings (idempotent: only zero fields
	// change). Gating this on MaxConcurrentStreams==0 used to leave
	// InitialWindowSize at 0 when a caller set only MaxConcurrentStreams — which
	// then advertised a 0 recv window and deadlocked every request body.
	o.AdvertisedSettings = o.AdvertisedSettings.defaulted()
	if o.StreamEventBuffer <= 0 {
		o.StreamEventBuffer = defaultStreamEventBuffer
	}
	if o.MaxRapidResets == 0 {
		budget := int(o.AdvertisedSettings.MaxConcurrentStreams) * 4
		if budget < rapidResetFloor {
			budget = rapidResetFloor
		}
		o.MaxRapidResets = budget
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = defaultHandshakeTimeout
	}
	return o
}

// rapidResetBudget returns the configured Rapid Reset budget, or 0 if the
// mitigation is disabled (negative MaxRapidResets).
func (o ServerConnOptions) rapidResetBudget() int {
	if o.MaxRapidResets < 0 {
		return 0
	}
	return o.MaxRapidResets
}

// effectiveConnRecvWindow returns the connection-level recv window to seed: the
// 64 KiB protocol default, or the caller's larger ConnRecvWindow (clamped to a
// valid window) when it opted into one.
func (o ServerConnOptions) effectiveConnRecvWindow() int32 {
	if o.ConnRecvWindow <= connInitialRecvWindow {
		return connInitialRecvWindow
	}
	v := int64(o.ConnRecvWindow)
	if v > 1<<31-1 {
		v = 1<<31 - 1
	}
	return int32(v) //nolint:gosec // clamped to (64 KiB, 2^31-1]
}

// sendInitialConnWindowUpdate advertises an enlarged connection recv window with
// one WINDOW_UPDATE(0, delta). It is a no-op (emits nothing) when the window is
// the 64 KiB protocol default, so a default connection sends no unsolicited
// frame. Called once during setup, before the reader goroutine starts.
func (sc *ServerConn) sendInitialConnWindowUpdate() error {
	delta := sc.connRecvWindow - int32(connInitialRecvWindow)
	if delta <= 0 {
		return nil
	}
	return sc.writeWindowUpdate(0, uint32(delta)) //nolint:gosec // delta > 0 checked above
}

// ConnStats is a point-in-time counter snapshot.
//
//nolint:revive // exported stutters with package; kept for API consistency with client.
type ConnStats struct {
	BytesSent      int64
	BytesReceived  int64
	FramesSent     int64
	FramesReceived int64
	// StreamsAccepted counts streams AcceptStream handed to the application, so
	// it reconciles against requests actually served. It is deliberately NOT the
	// number of streams the peer opened: streams refused over
	// MaxConcurrentStreams or a full accept queue, and streams that died while
	// they waited in that queue, are all excluded (issue #147).
	StreamsAccepted uint32
	// RapidResets counts client RST_STREAM frames charged against the
	// Rapid Reset budget (CVE-2023-44487) on this connection.
	RapidResets uint32
	// GoAwaySent reports whether this connection has emitted a GOAWAY
	// (graceful or error). A connection sends at most one GOAWAY.
	GoAwaySent bool
}

// clientPreface is the HTTP/2 connection preface sent by clients
// (RFC 7540 §3.5).
var clientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// NewServerConn performs the HTTP/2 server-side handshake over an
// already-connected transport (typically a *tls.Conn or net.Conn for h2c):
//
//  1. Read the 24-byte client preface magic (RFC 7540 §3.5)
//  2. Send server SETTINGS frame with advertised settings
//  3. Read client SETTINGS frame
//  4. Send SETTINGS ACK for client SETTINGS
//  5. Read client SETTINGS ACK for our SETTINGS
//  6. Start reader goroutine
//
// Returns ErrBadPreface if the client preface is invalid.
func NewServerConn(ctx context.Context, nc net.Conn, opts ServerConnOptions) (*ServerConn, error) {
	opts = opts.defaulted()

	// Slowloris defense: bound the handshake (preface + SETTINGS exchange)
	// with a read deadline. A client that connects but never finishes the
	// preface is dropped here instead of pinning a goroutine forever. The
	// deadline is cleared on success so it does NOT linger as a blanket
	// connection read deadline that would break HTTP/2 keep-alive.
	if opts.HandshakeTimeout > 0 {
		if dl, ok := nc.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dl.SetReadDeadline(time.Now().Add(opts.HandshakeTimeout))
		}
	}

	// Step 1: read and verify client preface.
	if err := readClientPreface(nc); err != nil {
		_ = nc.Close()
		return nil, err
	}

	sc := &ServerConn{
		transport:          nc,
		enc:                hpack.NewEncoder(),
		dec:                hpack.NewDecoder(),
		opts:               opts,
		readerDone:         make(chan struct{}),
		acceptCh:           make(chan *ServerStream, opts.acceptQueueDepth()),
		pingWaiters:        make(map[[8]byte]chan struct{}),
		connRecvWindow:     opts.effectiveConnRecvWindow(),
		peerConnSendWindow: int32(connInitialRecvWindow),
		goAwaySentID:       maxStreamID,
	}
	// The table reads the peer's SETTINGS_INITIAL_WINDOW_SIZE while holding its
	// own lock, so seeding a new stream and the §6.9.2 retroactive walk cannot
	// interleave. psMu is a leaf with respect to the table lock and must stay so.
	sc.tbl = newStreamTable(func() uint32 {
		sc.psMu.RLock()
		defer sc.psMu.RUnlock()
		return settingValue(sc.peerSettings, frame.SettingInitialWindowSize, connInitialRecvWindow)
	})
	sc.fr = newCountingFramer(nc, sc, opts.AdvertisedSettings.MaxFrameSize)
	sc.fcOutCond = sync.NewCond(&sc.fcOutMu)
	// Connection-lifetime context: cancelled on Close or when the caller's ctx
	// is cancelled. Per-stream contexts derive from this.
	sc.connCtx, sc.connCancel = context.WithCancel(ctx)

	// Step 2: send server SETTINGS.
	myParams := encodeAdvertised(opts.AdvertisedSettings)
	if err := sc.fr.WriteSettings(myParams); err != nil {
		sc.abortHandshake(nc)
		return nil, fmt.Errorf("server write settings: %w", err)
	}
	sc.atomicFramesSent.Add(1)

	// Steps 3-5: handshake — read client SETTINGS, send ACK, read ACK.
	// Create the real frame handler early so that non-SETTINGS frames
	// arriving during the handshake (e.g. HEADERS) are not lost.
	sc.handler = newServerConnHandler(sc, sc.dec, int(sc.opts.AdvertisedSettings.MaxHeaderListSize), int32(sc.opts.AdvertisedSettings.InitialWindowSize), sc.opts.StreamEventBuffer) //nolint:gosec // G115: AdvertisedSettings.defaulted() clamps InitialWindowSize to ≤ 2^31-1
	// applyPeerSettings is handed to the handshake rather than called after it, so
	// the client's values are in force before any frame that follows them in the
	// same batch is dispatched. It validates (RFC 9113 §6.5.2), merges, resizes
	// the shared encoder under wmu, and carries the retroactive
	// SETTINGS_INITIAL_WINDOW_SIZE delta to any stream that already exists —
	// though with the settings applied in receipt order there is normally nothing
	// for that delta to correct. Uncontended: the reader goroutine has not started.
	if _, err := handshakeServerSettings(ctx, sc.fr, sc.handler, sc.applyPeerSettings); err != nil {
		var ce connError
		if errors.As(err, &ce) {
			sc.sendGoAway(ce.code)
		}
		sc.abortHandshake(nc)
		return nil, err
	}

	// If the caller opted into a larger connection recv window, advertise it now
	// (one WINDOW_UPDATE, after the handshake and before the reader starts so
	// there is no wmu contention). No-op — and no unsolicited frame — by default.
	if err := sc.sendInitialConnWindowUpdate(); err != nil {
		sc.abortHandshake(nc)
		return nil, fmt.Errorf("server initial connection window update: %w", err)
	}

	// Handshake complete: clear the read deadline so the long-lived, multiplexed
	// connection is never killed by a stale handshake deadline. Post-handshake
	// liveness is intentionally NOT a blanket connection read deadline (that would
	// break keep-alive); it is governed by the per-stream idle timeout at the accept
	// layer (server.acceptLoop), which closes a connection left idle with no streams.
	// The brief window before readerLoop starts performs no reads, so there is no
	// slow-client vector there.
	if opts.HandshakeTimeout > 0 {
		if dl, ok := nc.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dl.SetReadDeadline(time.Time{})
		}
	}

	// h2c Upgrade (RFC 7540 §3.2): the HTTP/1.1 request that triggered the
	// upgrade owns stream 1 and is half-closed from the client. Seed it before
	// the reader starts, so the response goes out on stream 1 and the client's
	// next stream is 3.
	if opts.UpgradedRequest != nil {
		sc.seedUpgradedStream(opts.UpgradedRequest)
	}

	go sc.readerLoop()
	if opts.KeepaliveInterval > 0 {
		go sc.keepaliveLoop(opts.KeepaliveInterval)
	}
	return sc, nil
}

// readClientPreface reads exactly 24 bytes and validates against
// the HTTP/2 client preface magic (RFC 7540 §3.5).
func readClientPreface(nc net.Conn) error {
	buf := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(nc, buf); err != nil {
		return fmt.Errorf("read preface: %w", err)
	}
	for i, b := range buf {
		if b != clientPreface[i] {
			return ErrBadPreface
		}
	}
	return nil
}

// handshakeServerSettings runs the server-side SETTINGS exchange:
//
//   - Read client SETTINGS
//   - Send SETTINGS ACK
//   - Read client SETTINGS ACK for our SETTINGS
//
// Returns the client's SETTINGS.
func handshakeServerSettings(ctx context.Context, fr *frame.Framer, delegate frame.Handler, apply func(frame.SettingsParams) error) (frame.SettingsParams, error) {
	rec := &settingsRecorder{delegate: delegate, fr: fr, apply: apply}
	for !rec.peerSeen {
		if err := readOneFrame(ctx, fr, rec); err != nil {
			return frame.SettingsParams{}, fmt.Errorf("server read client settings: %w", err)
		}
	}
	for !rec.ackSeen {
		if err := readOneFrame(ctx, fr, rec); err != nil {
			return frame.SettingsParams{}, fmt.Errorf("server read client ack: %w", err)
		}
	}
	return rec.peer, nil
}

func readOneFrame(ctx context.Context, fr *frame.Framer, h frame.Handler) error {
	_, err := fr.ReadFrame(ctx, h)
	return err
}

// AcceptStream blocks until a new client-initiated stream arrives
// (HEADERS frame on an idle stream ID). Returns the stream with
// initial headers ready to read via Recv.
//
// Streams that died while they waited in the queue are skipped rather than
// delivered; see deliverable. The loop is bounded by the queue depth — every
// iteration consumes exactly one queued stream, and an empty queue parks in the
// blocking select — so it cannot spin.
func (sc *ServerConn) AcceptStream(ctx context.Context) (*ServerStream, error) {
	if sc.closed.Load() {
		return nil, ErrConnClosed
	}
	for {
		// Drain what is already queued before considering the connection over. Both
		// channels can be ready at once — acceptCh is buffered and the reader
		// registers a stream before it exits — and select would then pick uniformly
		// at random, silently discarding requests that were already accepted and
		// counted. Same reason ServerStream.Recv checks its buffer first.
		select {
		case ss, ok := <-sc.acceptCh:
			if !ok {
				return nil, ErrConnClosed
			}
			if !ss.deliverable() {
				continue
			}
			return sc.deliver(ss), nil
		default:
		}
		select {
		case ss, ok := <-sc.acceptCh:
			if !ok {
				return nil, ErrConnClosed
			}
			if !ss.deliverable() {
				// Back to waiting, not back to the caller: returning here would hand
				// out a nil stream with a nil error, which server.acceptLoop passes
				// straight into spawnStream.
				continue
			}
			return sc.deliver(ss), nil
		case <-sc.readerDone:
			// The reader goroutine has exited — the connection is finished, whether it
			// ended cleanly or on a protocol error. acceptCh is never closed, so without
			// this the owner would block here until its own context expired, and with
			// IdleTimeout disabled that is forever.
			return nil, ErrConnClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// deliver records a stream as accepted and hands it back. It is the single
// accounting point for ConnStats.StreamsAccepted, and it exists as a function
// rather than a line repeated at AcceptStream's two exits because that counter
// has already drifted from its meaning once by being written where delivery was
// merely likely.
//
// StreamsAccepted counts streams handed to the APPLICATION. registerStream used
// to count them at enqueue instead, on the reasoning that a successful send into
// acceptCh made delivery certain — true when AcceptStream returned everything it
// dequeued, and false from the moment it began skipping streams that died in the
// queue (deliverable, issue #133). A client that opens and cancels aggressively,
// or one sending malformed field sections — which emitHeaderBlock answers with
// RST_STREAM(PROTOCOL_ERROR) after the stream is already queued — drove the
// counter above the number of handlers that ran, with nothing else reporting the
// gap. Under a rapid-reset flood (CVE-2023-44487) the two diverge completely:
// the counter climbs at the full request rate while zero handlers run, so the
// number meant to say how much work the application is carrying instead reports
// the attack volume (issue #147).
//
// Counting here rather than there also moves the atomic off the single frame
// reader goroutine, which every stream on the connection is serialised behind,
// onto the accepting one. What is no longer counted is a stream the reader
// queued that nobody ever accepted before the connection ended — which is the
// point: nobody served it.
func (sc *ServerConn) deliver(ss *ServerStream) *ServerStream {
	sc.atomicStreamsAccepted.Add(1)
	return ss
}

// deliverable reports whether a stream just taken off the accept queue is still
// worth handing to the application.
//
// The accept queue is a Go channel of *ServerStream, so a stream that dies while
// it waits there cannot be taken back out: a channel offers FIFO enqueue and
// dequeue and no removal. Every path that kills a stream therefore leaves the
// pointer in the queue — a client RST_STREAM runs OnRSTStream -> markStreamDone,
// which does streamTable.release and cancels the stream's context and never
// touches acceptCh; ServerStream.push does the same when a queued stream's event
// buffer overflows. Dequeue is the one moment at which the structure permits an
// eviction at all, so it is the only place this check can live (issue #133).
//
// Delivering such a stream is not merely wasted work: the application spawns a
// goroutine, runs a handler, and writes a response to a stream the peer has
// abandoned — RFC 9113 §5.1: "An endpoint MUST NOT send frames other than
// PRIORITY on a closed stream". authorizeSend refuses the write so it fails
// safely, but only after the handler has run, and the only advance warning is a
// cancelled context handlers are not obliged to check.
//
// streamState.Terminal is exactly §5.1's "closed" — "A stream enters the
// 'closed' state after an endpoint both sends and receives a frame with an
// END_STREAM flag set. A stream also enters the 'closed' state after an endpoint
// either sends or receives a RST_STREAM frame." That existing predicate is asked
// rather than a second flag invented, per ADR-0009: the state is already one
// atomic word, and a separate source of truth for "is this stream dead" is
// precisely what that ADR exists to prevent. On a stream that has not been
// delivered yet this coincides with WasReset — only the handler's own writes set
// stSentEnded — but Terminal is the question actually being asked.
//
// One atomic load and a mask: no lock, no allocation, and nothing added to the
// frame reader's path.
func (ss *ServerStream) deliverable() bool { return !ss.state().Terminal() }

// Close sends GOAWAY(NO_ERROR) and closes the underlying connection.
// Idempotent.
func (sc *ServerConn) Close() error {
	if !sc.closed.CompareAndSwap(false, true) {
		return nil
	}
	if sc.connCancel != nil {
		sc.connCancel() // cancel every in-flight handler's context
	}
	sc.fcOutMu.Lock()
	if sc.fcOutCond != nil {
		sc.fcOutCond.Broadcast()
	}
	sc.fcOutMu.Unlock()

	// Best-effort GOAWAY. The write deadline is set under wmu together with the
	// write so a concurrent teardown path (sendGoAway) cannot clobber the deadline
	// on the shared transport.
	sc.wmu.Lock()
	if dl, ok := sc.transport.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(closeGoAwayDeadline))
	}
	// Account for the GOAWAY frame and flag the connection as having emitted one,
	// matching GoAway/sendGoAway, so Stats (FramesSent, GoAwaySent) stays accurate
	// for Close-initiated teardowns (e.g. keepalive timeout).
	if err := sc.fr.WriteGoAway(sc.clampGoAwayID(sc.lastPeerStreamID()), frame.ErrCodeNoError, nil); err == nil {
		sc.bumpFramesSent()
		sc.goAwayRequested.Store(true)
	}
	sc.wmu.Unlock()
	_ = sc.transport.Close()
	<-sc.readerDone
	sc.fr.Close()
	return nil
}

// Stats returns a point-in-time snapshot of connection counters.
func (sc *ServerConn) Stats() ConnStats {
	return ConnStats{
		BytesSent:       sc.atomicBytesSent.Load(),
		BytesReceived:   sc.atomicBytesReceived.Load(),
		FramesSent:      sc.atomicFramesSent.Load(),
		FramesReceived:  sc.atomicFramesReceived.Load(),
		StreamsAccepted: sc.atomicStreamsAccepted.Load(),
		RapidResets:     sc.rapidResetCount.Load(),
		GoAwaySent:      sc.goAwayRequested.Load(),
	}
}

// countingReader / countingWriter tally bytes flowing through the transport into
// an atomic counter, so Stats can report BytesReceived / BytesSent. They sit
// between the Framer and the raw connection; the byte count is updated even on a
// partial read/write that ends in error (n bytes still crossed the wire).
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

func (sc *ServerConn) lastPeerStreamID() uint32 { return sc.tbl.lastPeerID() }

// validateClientStreamID enforces RFC 9113 §5.1.1 for a newly opened client
// stream: the ID must be odd and strictly greater than every client stream ID
// already seen. An even ID, or a reused/decreasing ID (idle-stream reuse), is a
// connection error of type PROTOCOL_ERROR. Called only for new streams, on the
// single reader goroutine, before admission consumes the identifier.
func (sc *ServerConn) validateClientStreamID(id uint32) error { return sc.tbl.validateClientID(id) }

// ActiveStreams reports how many streams are currently live on the connection:
// open, half-closed, or reserved for a push whose response is still being
// written. Zero means the connection is genuinely idle, which is not the same
// question as "has a new stream arrived recently".
func (sc *ServerConn) ActiveStreams() int { return sc.tbl.live() }

// isIdleStream reports whether the identifier names a stream that has never
// been opened — RFC 9113 §5.1's "idle" state.
//
// The streams map alone cannot answer this: it holds only live streams, so a
// lookup miss means idle, closed, reset or refused indifferently, and those
// states demand opposite reactions. A frame on an idle stream is a connection
// error; the same frame on a closed one is at most a stream error, because a
// peer cannot know a stream is gone until its RST_STREAM has arrived.
//
// The identifier space knows the answer; see conn/stream_table.go. Reading it
// takes the table's lock — it used to be two atomic loads, but the counters and
// the population have to be observed together or a caller sees them disagreeing,
// which is how a stream came to be reported idle and live at once. The lock is
// held for a comparison, on a path that already takes it to look the stream up.
func (sc *ServerConn) isIdleStream(id uint32) bool { return sc.tbl.idle(id) }

// IsAlive reports whether the connection is open.
func (sc *ServerConn) IsAlive() bool {
	return !sc.closed.Load()
}

// Ping sends a PING and blocks until the client's ACK arrives.
func (sc *ServerConn) Ping(ctx context.Context) (time.Duration, error) {
	if sc.closed.Load() {
		return 0, ErrConnClosed
	}
	n := sc.pingCounter.Add(1)
	var payload [8]byte
	//nolint:gosec // ping counter is monotonic, overflow is fine
	binary.BigEndian.PutUint64(payload[:], n)

	ch := make(chan struct{})
	sc.pingMu.Lock()
	sc.pingWaiters[payload] = ch
	sc.pingMu.Unlock()

	sc.wmu.Lock()
	if sc.closed.Load() {
		sc.wmu.Unlock()
		sc.pingMu.Lock()
		delete(sc.pingWaiters, payload)
		sc.pingMu.Unlock()
		return 0, ErrConnClosed
	}
	start := time.Now()
	err := sc.fr.WritePing(false, payload)
	if err == nil {
		sc.bumpFramesSent()
	}
	sc.wmu.Unlock()
	if err != nil {
		sc.pingMu.Lock()
		delete(sc.pingWaiters, payload)
		sc.pingMu.Unlock()
		return 0, err
	}

	select {
	case <-ch:
		return time.Since(start), nil
	case <-ctx.Done():
		sc.pingMu.Lock()
		delete(sc.pingWaiters, payload)
		sc.pingMu.Unlock()
		return 0, ctx.Err()
	case <-sc.readerDone:
		sc.pingMu.Lock()
		delete(sc.pingWaiters, payload)
		sc.pingMu.Unlock()
		return 0, ErrConnClosed
	}
}

// deliverPingAck signals any Ping call waiting for payload.
func (sc *ServerConn) deliverPingAck(payload [8]byte) {
	sc.pingMu.Lock()
	ch, ok := sc.pingWaiters[payload]
	if ok {
		delete(sc.pingWaiters, payload)
	}
	sc.pingMu.Unlock()
	if ok {
		close(ch)
	}
}

// newCountingFramer builds the connection's Framer over a transport wrapped so
// every frame byte read and written is tallied for Stats (BytesReceived /
// BytesSent). The 24-byte preface read before this is not counted; everything
// from the SETTINGS exchange onward is.
//
// maxFrameSize is the value this connection advertises in SETTINGS. The Framer's
// own cap defaults to 16,384 regardless, so left unset an operator raising
// AdvertisedSettings.MaxFrameSize would make the server reject exactly the
// frames its own SETTINGS invited (RFC 9113 §4.2).
// AdvertisedSettings.defaulted() has already clamped it into the legal range.
func newCountingFramer(nc net.Conn, sc *ServerConn, maxFrameSize uint32) *frame.Framer {
	fr := frame.NewFramer(
		&countingWriter{w: nc, n: &sc.atomicBytesSent},
		&countingReader{r: nc, n: &sc.atomicBytesReceived},
	)
	// Was SetMaxReadFrameSize, deprecated in the codec for naming half of what
	// it does: the same limit has always been checked on the write sites too,
	// and the deprecated name now simply delegates here. Behaviour is identical.
	fr.SetMaxFrameSize(maxFrameSize)
	return fr
}

// abortHandshake tears down a connection that failed to come up, after connCtx
// exists. Closing the socket alone is not enough: connCtx is a child of the
// caller's context, which for this server is the process-lifetime context every
// connection is handed, so an uncancelled child stays in its parent's map
// forever — a leak whose rate an unauthenticated peer chooses. A stream may also
// already be registered, because the handshake forwards HEADERS to the real
// handler; shutdownStreams releases it and its own context child.
func (sc *ServerConn) abortHandshake(nc net.Conn) {
	sc.shutdownStreams(nil)
	if sc.connCancel != nil {
		sc.connCancel()
	}
	sc.fr.Close()
	_ = nc.Close()
}

// maxStreamID is the largest legal stream identifier, and the last-stream-id a
// server sends in the advance-warning GOAWAY of a graceful shutdown.
const maxStreamID = 1<<31 - 1

// clampGoAwayID returns the last-stream-id for the next GOAWAY, never larger
// than one already sent.
//
//	RFC 9113 §6.8 — "Endpoints MUST NOT increase the value
//	they send in the last stream identifier, since the peers might already have
//	retried unprocessed requests on another connection."
//
// Raising it would tell a peer that streams it has already replayed elsewhere
// were processed after all. Caller must hold wmu, which every GOAWAY write site
// already does across its write.
func (sc *ServerConn) clampGoAwayID(id uint32) uint32 {
	if id > sc.goAwaySentID {
		id = sc.goAwaySentID
	}
	sc.goAwaySentID = id
	return id
}

// GoAwayGraceful sends the advance-warning GOAWAY of RFC 9113 §6.8's two-phase
// shutdown.
//
//	RFC 9113 §6.8 — "A server that is attempting to gracefully shut down a
//	connection SHOULD send an initial GOAWAY frame with the last stream
//	identifier set to 2^31-1 and a NO_ERROR code. This signals to the client
//	that a shutdown is imminent and that initiating further requests is
//	prohibited. After allowing time for any in-flight stream creation (at least
//	one round-trip time), the server MAY send another GOAWAY frame with an
//	updated last stream identifier."
//
// Announcing the real last-stream-id in one shot instead makes every stream the
// client had in flight look unprocessed, so it replays requests this server was
// about to serve. Close provides phase two; clampGoAwayID lets the identifier
// fall from 2^31-1 to the real one, which is the only direction §6.8 allows.
func (sc *ServerConn) GoAwayGraceful() error {
	if !sc.goAwayRequested.CompareAndSwap(false, true) {
		return nil // already sent
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if sc.closed.Load() {
		return ErrConnClosed
	}
	err := sc.fr.WriteGoAway(sc.clampGoAwayID(maxStreamID), frame.ErrCodeNoError, nil)
	if err == nil {
		sc.bumpFramesSent()
	}
	return err
}

// GoAway sends GOAWAY with the given error code. After this call
// AcceptStream returns ErrConnClosed but existing streams continue.
func (sc *ServerConn) GoAway(code frame.ErrCode) error {
	if !sc.goAwayRequested.CompareAndSwap(false, true) {
		return nil // already sent
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if sc.closed.Load() {
		return ErrConnClosed
	}
	err := sc.fr.WriteGoAway(sc.clampGoAwayID(sc.lastPeerStreamID()), code, nil)
	if err == nil {
		sc.bumpFramesSent()
	}
	return err
}

func (sc *ServerConn) keepaliveLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			pingTimeout := sc.opts.KeepaliveTimeout
			if pingTimeout == 0 {
				pingTimeout = interval * 5
				if pingTimeout < 5*time.Second {
					pingTimeout = 5 * time.Second
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
			_, err := sc.Ping(ctx)
			cancel()
			if err != nil {
				_ = sc.Close()
				return
			}
		case <-sc.readerDone:
			_ = sc.Close()
			return
		}
	}
}

func (sc *ServerConn) bumpFramesSent() { sc.atomicFramesSent.Add(1) }

// readerLoop reads frames from the connection and dispatches them.
func (sc *ServerConn) readerLoop() {
	defer close(sc.readerDone)
	// Reuse the handshake handler so a header block split across the handshake
	// boundary keeps its pending CONTINUATION state instead of being lost.
	h := sc.handler
	for {
		fh, err := sc.fr.ReadFrame(context.Background(), h)
		// RFC 9113 §5.5: "extension frames that appear in the
		// middle of a field block (Section 4.3) are not permitted; these MUST be
		// treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
		// The codec correctly discards frame types it does not recognise before
		// calling any Handler method, so guardHeaderBlock — which enforces §6.10
		// for every dispatched type — can never see one. Here the FrameHeader is
		// still in hand, which is all the check needs.
		if err == nil && h.pendingStreamID != 0 && undispatchedFrameType(fh.Type) {
			err = connError{code: frame.ErrCodeProtocolError, msg: "extension frame inside an open field block"}
		}
		if err == nil {
			sc.atomicFramesReceived.Add(1)
			continue
		}

		// §6.10 outranks whatever the codec objected to: while
		// a field block is open, "any other type of frame or a frame on a
		// different stream" is a connection error of type PROTOCOL_ERROR. A
		// malformed PRIORITY is rejected on length before guardHeaderBlock runs,
		// so without this the peer would be told FRAME_SIZE_ERROR and never learn
		// it had broken the far more important rule.
		//
		// Only for a frame that was actually read. ReadFrame returns the zero
		// FrameHeader when it fails before parsing one — an EOF on the 9-byte
		// header, a deadline, a socket closed under the reader — and that zero
		// value has Type DATA and stream 0, which would read as a §6.10 violation
		// and blame a peer that has simply gone away.
		if h.pendingStreamID != 0 && !transportErr(err) &&
			(fh.Type != frame.FrameContinuation || fh.StreamID != h.pendingStreamID) {
			sc.sendGoAway(frame.ErrCodeProtocolError)
			_ = sc.transport.Close()
			sc.shutdownStreams(err)
			return
		}

		// RFC 9113 §6.3 and §6.9 scope
		// two of the codec's rejections to a single stream, not the connection.
		// Recovering in place is safe because ReadFrame consumes the whole
		// payload before rejecting either one, so the byte stream is still
		// frame-aligned. Never while a field block is open: §6.10 makes any
		// non-CONTINUATION frame there a connection error whatever it was, and
		// the codec rejects the malformed frame before guardHeaderBlock can run.
		//
		// Nor on an idle stream. §6.4 is flatly the other way:
		// "RST_STREAM frames MUST NOT be sent for a stream in the 'idle' state. If
		// a RST_STREAM frame identifying an idle stream is received, the recipient
		// MUST treat this as a connection error ... of type PROTOCOL_ERROR."
		// Answering a malformed PRIORITY on an unopened stream with RST_STREAM
		// would hand a conformant peer a mandatory reason to kill the connection
		// the recovery exists to save.
		if h.pendingStreamID == 0 && fh.StreamID != 0 && !sc.isIdleStream(fh.StreamID) {
			switch {
			case errors.Is(err, frame.ErrPriorityWrongLength):
				_ = sc.writeRSTStreamID(fh.StreamID, frame.ErrCodeFrameSizeError)
				continue
			case errors.Is(err, frame.ErrZeroIncrement):
				_ = sc.writeRSTStreamID(fh.StreamID, frame.ErrCodeProtocolError)
				continue
			}
		}

		// A connError from a handler callback (e.g. PROTOCOL_ERROR or the Rapid
		// Reset ENHANCE_YOUR_CALM trip) carries its own code. Everything else
		// that is a protocol violation arrives as a codec sentinel and is mapped
		// by codecErrCode. Either way RFC 9113 §5.4 requires the error be
		// reported, and §5.4.1 requires the transport be
		// closed afterwards: "After sending the GOAWAY frame for an error
		// condition, the endpoint MUST close the TCP connection." Not sc.Close(),
		// which waits on readerDone and would deadlock here.
		var ce connError
		var code frame.ErrCode
		var mapped bool
		if errors.As(err, &ce) {
			code, mapped = ce.code, true
		} else {
			code, mapped = codecErrCode(err)
		}
		if mapped {
			sc.sendGoAway(code)
			_ = sc.transport.Close()
		}
		sc.shutdownStreams(err)
		return
	}
}

// sendGoAway emits a best-effort GOAWAY with the given error code and the
// last client stream ID we processed. Bounded by a short write deadline so
// a stuck transport cannot block connection teardown.
func (sc *ServerConn) sendGoAway(code frame.ErrCode) {
	if !sc.goAwayRequested.CompareAndSwap(false, true) {
		return
	}
	sc.wmu.Lock()
	// Deadline set under wmu with the write so it cannot race Close()'s deadline
	// on the shared transport.
	if dl, ok := sc.transport.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(closeGoAwayDeadline))
	}
	if !sc.closed.Load() {
		if err := sc.fr.WriteGoAway(sc.clampGoAwayID(sc.lastPeerStreamID()), code, nil); err == nil {
			sc.bumpFramesSent()
		}
	}
	sc.wmu.Unlock()
}

// shutdownStreams ends every stream still live when the connection does. It is
// the bulk form of markStreamDone and owes each stream the same two things: the
// final event, and then the cancellation of its context.
//
// It used to owe only the first. ServerStream.Context promises cancellation
// "when the stream is reset by the client (RST_STREAM), completes, or the
// underlying connection closes", and this is the third clause — but the two
// reader-loop exits reach here and return, and connCancel, which cancels every
// per-stream context at once, is called only by Close and abortHandshake. A
// handler blocked in Recv was released by close(s.events); one selecting on
// Context().Done() was not, and markStreamDone could not rescue it later because
// streamTable.release finds nothing to release once drain has run (issue #139).
//
// Cancelling here rather than routing teardown through release keeps the cancel
// outside the table lock, which is what release's contract asks of every caller:
// it hands the stream back precisely so the caller can cancel unlocked. The only
// lock taken per stream is the stream's own leaf mutex, for one pointer load.
func (sc *ServerConn) shutdownStreams(_ error) {
	for _, s := range sc.tbl.drain() {
		select {
		case s.events <- StreamEvent{Type: EventReset, RSTCode: frame.ErrCodeInternalError, EndStream: true}:
		default:
		}
		close(s.events)
		// After the event, never before — the ordering OnData documents for
		// markStreamDone. Recv prefers a buffered event to cancellation, but a
		// handler already parked in its blocking select would take the ctx.Done arm
		// and never see the reset this loop just queued.
		s.cancelCtx()
	}
}

// --- shared helpers ---

// encodeAdvertised converts AdvertisedSettings to a SettingsParams frame payload.
func encodeAdvertised(a AdvertisedSettings) frame.SettingsParams {
	var p frame.SettingsParams
	add := func(id frame.SettingID, v uint32) {
		p.Pairs[p.N] = frame.SettingPair{ID: id, Value: v}
		p.N++
	}
	add(frame.SettingHeaderTableSize, a.HeaderTableSize)
	add(frame.SettingEnablePush, 0) // server never accepts push
	add(frame.SettingMaxConcurrentStreams, a.MaxConcurrentStreams)
	add(frame.SettingInitialWindowSize, a.InitialWindowSize)
	add(frame.SettingMaxFrameSize, a.MaxFrameSize)
	if a.MaxHeaderListSize != 0 {
		add(frame.SettingMaxHeaderListSize, a.MaxHeaderListSize)
	}
	return p
}

// settingValue returns the value of `id` from `s` or `def` when not present.
func settingValue(s frame.SettingsParams, id frame.SettingID, def uint32) uint32 {
	for i := range s.N {
		if s.Pairs[i].ID == id {
			return s.Pairs[i].Value
		}
	}
	return def
}

// AdvertisedSettings is what we send to the peer in our SETTINGS frame.
// Zero values are replaced by RFC 7540 defaults.
type AdvertisedSettings struct {
	HeaderTableSize      uint32
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

func (s AdvertisedSettings) defaulted() AdvertisedSettings {
	if s.HeaderTableSize == 0 {
		s.HeaderTableSize = 4096
	}
	if s.MaxConcurrentStreams == 0 {
		s.MaxConcurrentStreams = 100
	}
	if s.InitialWindowSize == 0 {
		s.InitialWindowSize = 65535
	} else if s.InitialWindowSize > 1<<31-1 {
		// RFC 9113 §6.5.2: a SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 is illegal.
		// Clamp the server's own advertised value so we never advertise an out-of-
		// range window (and the int32 recv-window seed derived from it stays valid).
		s.InitialWindowSize = 1<<31 - 1
	}
	// RFC 9113 §6.5.2: SETTINGS_MAX_FRAME_SIZE — "The initial
	// value is 2^14 (16,384) octets. The value advertised by an endpoint MUST be
	// between this initial value and the maximum allowed frame size (2^24-1 or
	// 16,777,215 octets), inclusive." The clamp binds this server as a sender:
	// an operator value outside the range would put an illegal SETTINGS frame on
	// the wire. Clamping rather than erroring keeps a misconfiguration from
	// refusing to serve, and the floor also guarantees the server still accepts
	// the 16,384-octet frames §4.2 entitles every peer to send.
	switch {
	case s.MaxFrameSize < 16384:
		s.MaxFrameSize = 16384
	case s.MaxFrameSize > 16777215:
		s.MaxFrameSize = 16777215
	}
	return s
}

// connInitialRecvWindow is the connection-level recv window size.
// RFC 7540 §6.9.2 fixes this at 65535.
const connInitialRecvWindow = 65535

// recvWindowRefundThreshold batches WINDOW_UPDATE at this granularity.
const recvWindowRefundThreshold = 32768

// closeGoAwayDeadline bounds GOAWAY write during Close.
const closeGoAwayDeadline = 200 * time.Millisecond

// settingsRecorder records the peer's SETTINGS and ACK state.
// Non-SETTINGS frames that arrive during the handshake (e.g. the client's
// request HEADERS sent in the same TCP segment as SETTINGS) are forwarded
// to the delegate handler so they are not lost.
type settingsRecorder struct {
	peer     frame.SettingsParams
	peerSeen bool
	ackSeen  bool
	delegate frame.Handler // optional; receives forwarded frames
	// fr, when set, is used to acknowledge each non-ACK SETTINGS frame the
	// moment its values have been processed (RFC 9113 §6.5.3).
	fr *frame.Framer
	// apply, when set, publishes the peer's SETTINGS to the connection the
	// instant they are processed — before any later frame in the same batch is
	// dispatched. RFC 9113 §6.5: "SETTINGS frames always apply to a
	// connection, never a single stream." A client may pipeline preface, SETTINGS
	// and its first HEADERS into one segment, and the handshake forwards that
	// HEADERS to the real handler, so a stream can register mid-handshake; if the
	// settings are published only afterwards it seeds its windows from the
	// protocol defaults and stays there.
	apply func(frame.SettingsParams) error
}

func (r *settingsRecorder) OnData(fh frame.FrameHeader, data []byte, pad uint8) error {
	if r.delegate != nil {
		return r.delegate.OnData(fh, data, pad)
	}
	return nil
}
func (r *settingsRecorder) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, p *frame.Priority, flags uint8) error {
	if r.delegate != nil {
		return r.delegate.OnHeaders(fh, hb, p, flags)
	}
	return nil
}
func (r *settingsRecorder) OnPriority(fh frame.FrameHeader, p frame.Priority) error {
	if r.delegate != nil {
		return r.delegate.OnPriority(fh, p)
	}
	return nil
}
func (r *settingsRecorder) OnRSTStream(fh frame.FrameHeader, c frame.ErrCode) error {
	if r.delegate != nil {
		return r.delegate.OnRSTStream(fh, c)
	}
	return nil
}
func (r *settingsRecorder) OnSettings(fh frame.FrameHeader, s frame.SettingsParams) error {
	if fh.Flags&frame.FlagSettingsAck != 0 {
		r.ackSeen = true
		return nil
	}
	// Merge, never replace. RFC 9113 §6.5.3: "The values in the
	// SETTINGS frame MUST be processed in the order they appear" — a second
	// SETTINGS frame updates the parameters it names and leaves the rest alone.
	// Assigning the frame wholesale silently reverted every parameter it omitted.
	for i := range s.N {
		setPeerSetting(&r.peer, s.Pairs[i].ID, s.Pairs[i].Value)
	}
	r.peerSeen = true
	// Publish before acknowledging, and before the next frame is read. Everything
	// after this point in the handshake — a pipelined HEADERS, a stream-level
	// WINDOW_UPDATE — then sees the values the client actually sent.
	if r.apply != nil {
		if err := r.apply(r.peer); err != nil {
			return err
		}
	}
	// §6.5.3: "Once all values have been processed, the recipient MUST
	// immediately emit a SETTINGS frame with the ACK flag set." Every non-ACK
	// SETTINGS in the handshake window gets its own acknowledgement; the caller
	// used to send exactly one however many arrived. Safe without wmu: this runs
	// on the constructing goroutine, before the reader loop starts.
	if r.fr != nil {
		return r.fr.WriteSettingsAck()
	}
	return nil
}
func (r *settingsRecorder) OnPushPromise(fh frame.FrameHeader, sid uint32, hb frame.HeaderBlock, flags uint8) error {
	if r.delegate != nil {
		return r.delegate.OnPushPromise(fh, sid, hb, flags)
	}
	return nil
}
func (r *settingsRecorder) OnPing(fh frame.FrameHeader, payload [8]byte) error {
	if r.delegate != nil {
		return r.delegate.OnPing(fh, payload)
	}
	return nil
}
func (r *settingsRecorder) OnGoAway(fh frame.FrameHeader, sid uint32, c frame.ErrCode, d []byte) error {
	if r.delegate != nil {
		return r.delegate.OnGoAway(fh, sid, c, d)
	}
	return nil
}
func (r *settingsRecorder) OnWindowUpdate(fh frame.FrameHeader, inc uint32) error {
	if r.delegate != nil {
		return r.delegate.OnWindowUpdate(fh, inc)
	}
	return nil
}
func (r *settingsRecorder) OnContinuation(fh frame.FrameHeader, hb frame.HeaderBlock) error {
	if r.delegate != nil {
		return r.delegate.OnContinuation(fh, hb)
	}
	return nil
}

func (r *settingsRecorder) OnOrigin(fh frame.FrameHeader, origins []string) error {
	if r.delegate != nil {
		return r.delegate.OnOrigin(fh, origins)
	}
	return nil
}

func (r *settingsRecorder) OnAltSvc(fh frame.FrameHeader, entries []frame.AltSvcEntry) error {
	if r.delegate != nil {
		return r.delegate.OnAltSvc(fh, entries)
	}
	return nil
}

var _ frame.Handler = (*settingsRecorder)(nil)

// --- Error types ---

var (
	// ErrBadPreface is returned when the client sends an invalid
	// HTTP/2 connection preface.
	ErrBadPreface = errors.New("conn: invalid HTTP/2 client preface")
	// ErrConnClosed is returned after the connection has been closed.
	ErrConnClosed = errors.New("conn: connection closed")
	// ErrStreamClosed is returned when operating on a closed stream.
	ErrStreamClosed = errors.New("conn: stream already closed")
	// ErrHeaderBlockTooLarge is returned when an encoded field section exceeds
	// the peer's SETTINGS_MAX_FRAME_SIZE. A field section cannot be split without
	// CONTINUATION chunking, which this server does not do, so the write is
	// refused rather than emitted as a frame RFC 9113 §4.2 obliges the receiver
	// to answer with a connection error.
	ErrHeaderBlockTooLarge = errors.New("conn: encoded field section exceeds the peer's SETTINGS_MAX_FRAME_SIZE")
)
