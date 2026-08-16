package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"

	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ErrServerClosed is returned by Serve and ListenAndServe after the server
// has been shut down via Close.
var ErrServerClosed = errors.New("server: server closed")

// Logger is the minimal logging interface the server writes diagnostics to.
// A nil Options.Logger falls back to the standard library log package.
type Logger interface {
	Printf(format string, args ...interface{})
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...interface{}) { log.Printf(format, args...) }

// Options configures a Server. The zero value is usable; each field documents
// its default when left empty.
type Options struct {
	Addr                     string
	Handler                  Handler
	HTTPHandler              http.Handler
	Middleware               []Middleware
	ConnOpts                 conn.ServerConnOptions
	MaxConcurrentConnections int
	GracefulShutdownTimeout  time.Duration
	Logger                   Logger

	// H2C enables HTTP/2 cleartext (prior knowledge + HTTP/1.1 Upgrade).
	// When false (default), the server expects direct HTTP/2 connections
	// (typically over TLS). When true, the server detects HTTP/1.1 Upgrade
	// requests and responds with 101 Switching Protocols.
	H2C bool

	// StreamingBody enables io.ReadCloser body instead of buffering.
	// When true, Request.BodyReader is set and Body is nil.
	StreamingBody bool

	// IdleTimeout is the maximum amount of time to wait for the next
	// request/stream on an idle connection.
	//
	//   0  => secure default (defaultIdleTimeout)
	//   <0 => disabled (no idle timeout; keep-alive forever)
	//   >0 => explicit timeout
	//
	// A sensible default protects long-lived HTTP/2 connections from being
	// held open indefinitely by idle clients, while sequential/active streams
	// reset the clock on every new stream.
	IdleTimeout time.Duration

	// MaxRequestBodyBytes caps the size of an inbound request body to bound
	// memory use and defend against memory-exhaustion DoS via large uploads.
	// It is enforced in BOTH buffered mode (accumulation stops and the request
	// is rejected with 413 once the cap is exceeded — never buffering beyond
	// the cap) and streaming mode (BodyReader returns ErrBodyTooLarge once the
	// total bytes read exceed the cap).
	//
	//   0  => secure default (defaultMaxRequestBodyBytes, 10 MiB)
	//   <0 => unlimited / disabled
	//   >0 => explicit limit in bytes
	MaxRequestBodyBytes int64

	// OnDrainStart, if set, is invoked exactly once at the very START of
	// Shutdown — before the listener is closed and before GOAWAY is sent —
	// so callers can flip readiness to NOT-ready (e.g.
	// HealthState.SetNotReady and/or grpc health SetServingStatus(NotServing)).
	// This lets Kubernetes stop routing new traffic to this instance while
	// in-flight streams continue to drain. It runs synchronously while the
	// server lock is held, so it must not block or call back into the server.
	OnDrainStart func()
}

// defaultMaxRequestBodyBytes is the secure-by-default cap on buffered request
// bodies (10 MiB), applied when MaxRequestBodyBytes is zero.
const defaultMaxRequestBodyBytes = 10 << 20

// defaultIdleTimeout is the secure-by-default idle connection timeout applied
// when Options.IdleTimeout is zero.
const defaultIdleTimeout = 120 * time.Second

// resolveMaxBodyBytes resolves the body-size cap sentinel into a concrete
// limit: a positive byte count, or -1 for "unlimited".
func (o Options) resolveMaxBodyBytes() int64 {
	switch {
	case o.MaxRequestBodyBytes == 0:
		return defaultMaxRequestBodyBytes
	case o.MaxRequestBodyBytes < 0:
		return -1 // unlimited
	default:
		return o.MaxRequestBodyBytes
	}
}

func (o Options) validate() error {
	if o.Handler == nil && o.HTTPHandler == nil {
		return errors.New("server: Handler or HTTPHandler is required")
	}
	return nil
}

func (o Options) resolvedHandler() Handler {
	h := o.Handler
	if h == nil {
		h = FromHTTPHandler(o.HTTPHandler)
	}
	if len(o.Middleware) > 0 {
		h = Chain(o.Middleware...)(h)
	}
	return h
}

// Server is an HTTP/2 (optionally h2c) server built on the poseidon conn layer.
// Construct one with NewServer, then drive it with Serve or ListenAndServe.
type Server struct {
	handler      Handler
	connOpts     conn.ServerConnOptions
	opts         Options
	maxBodyBytes int64 // resolved: >0 limit, -1 unlimited
	logger       Logger
	mu           sync.Mutex
	closed       bool
	shutdown     bool
	listeners    map[net.Listener]struct{} // listeners passed to Serve; closed by Close/Shutdown
	conns        map[*conn.ServerConn]struct{}
	closedStats  transportTotals // counters folded in from closed conns (guarded by mu)
	inFlight     sync.WaitGroup  // active streams being served
	done         chan struct{}
	closeCh      chan struct{}
}

// transportTotals accumulates ConnStats from connections that have closed, so
// TransportStats can report monotonic counters (closed totals + live conns).
// Guarded by Server.mu.
type transportTotals struct {
	bytesSent       int64
	bytesReceived   int64
	framesSent      int64
	framesReceived  int64
	streamsAccepted uint64
	rapidResets     uint64
	goAways         uint64
}

// NewServer validates opts and returns a ready-to-serve Server. It returns a
// non-nil error if opts is invalid.
func NewServer(opts Options) (*Server, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = stdLogger{}
	}
	if opts.GracefulShutdownTimeout <= 0 {
		opts.GracefulShutdownTimeout = 30 * time.Second
	}
	// Secure-by-default idle timeout: zero => default, negative => disabled.
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = defaultIdleTimeout
	}
	return &Server{
		handler:      opts.resolvedHandler(),
		connOpts:     opts.ConnOpts,
		opts:         opts,
		maxBodyBytes: opts.resolveMaxBodyBytes(),
		logger:       logger,
		listeners:    make(map[net.Listener]struct{}),
		conns:        make(map[*conn.ServerConn]struct{}),
		done:         make(chan struct{}),
		closeCh:      make(chan struct{}),
	}, nil
}

// idleTimeout returns the effective idle timeout: 0 when disabled (negative
// sentinel) so the accept loop skips the per-stream deadline.
func (s *Server) idleTimeout() time.Duration {
	if s.opts.IdleTimeout < 0 {
		return 0
	}
	return s.opts.IdleTimeout
}

// ListenAndServe listens on opts.Addr (TCP) and serves connections until ctx
// is cancelled or Close is called, returning ErrServerClosed on clean shutdown.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	s.logger.Printf("poseidon: listening on %s", ln.Addr())
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln until ctx is cancelled or Close is called,
// returning ErrServerClosed on clean shutdown. It takes ownership of ln.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// No TLS config: a listener the caller wrapped itself cannot be checked
	// against its own certificate. See ServeTLSConfig.
	return s.serve(ctx, ln, nil)
}

// serve is Serve with the TLS config that produced ln, when the caller supplied
// one. cfg is nil for cleartext listeners and for a TLS listener handed to the
// bare Serve.
func (s *Server) serve(ctx context.Context, ln net.Listener, cfg *tls.Config) error {
	s.mu.Lock()
	if s.closed {
		// Already closed before Serve started; don't accept anything.
		s.mu.Unlock()
		_ = ln.Close()
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()

	// serveDone bounds the watcher goroutine to this Serve call's lifetime.
	serveDone := make(chan struct{})
	defer func() {
		close(serveDone)
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
	}()

	// Watch for ctx cancellation (→ Close) and terminate on Close()/Shutdown()
	// or when Serve returns. Selecting on closeCh/serveDone — not just ctx.Done()
	// — means the watcher always exits: with ctx == context.Background(),
	// ctx.Done() is a nil channel (never ready), so on its own this goroutine
	// would block forever (a leak) after the server stops.
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closeCh:
		case <-serveDone:
		}
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closeCh:
				return ErrServerClosed
			default:
				return err
			}
		}
		if s.opts.MaxConcurrentConnections > 0 &&
			s.ConnCount() >= s.opts.MaxConcurrentConnections {
			s.logger.Printf("poseidon: rejecting %s: max connections", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		go func() {
			// Attach the peer address ONCE per connection, not per request: every
			// stream context descends from the context handed to
			// conn.NewServerConn (ServerConn.connCtx), so one context.WithValue
			// here covers every request on the connection — no allocation, no
			// lookup and no lock added to the per-request path. Without this,
			// middleware.PeerAddr is empty for every request and RealIP resolves
			// nothing, which collapses KeyByClientIP into one global bucket.
			//
			// RemoteAddr is nil-checked because Serve accepts a caller-supplied
			// net.Listener: a net.Conn implementation that returns nil here would
			// otherwise panic in this goroutine and take the process down.
			connCtx := ctx
			if ra := nc.RemoteAddr(); ra != nil {
				connCtx = WithPeerAddr(ctx, ra.String())
			}
			if s.opts.H2C {
				s.detectAndServe(connCtx, nc, cfg)
			} else {
				s.serveConn(connCtx, nc, cfg)
			}
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, nc net.Conn, cfg *tls.Config) {
	opts := s.connOpts
	if opts.StreamEventBuffer <= 0 {
		opts.StreamEventBuffer = 8
	}
	sc, err := conn.NewServerConn(ctx, nc, opts)
	if err != nil {
		s.logger.Printf("poseidon: handshake failed for %s: %v", nc.RemoteAddr(), err)
		_ = nc.Close()
		return
	}
	if cs, ok := tlsAdmissible(nc); !ok {
		s.logger.Printf("poseidon: rejecting %s: alpn=%q tls=%#04x", nc.RemoteAddr(), cs.NegotiatedProtocol, cs.Version)
		_ = sc.GoAway(frame.ErrCodeInadequateSecurity)
		_ = sc.Close()
		return
	}
	s.trackConn(sc, true)
	defer s.trackConn(sc, false)
	// Resolve, once per connection, the certificate this server presented. Every
	// stream on the connection is judged against it (RFC 9110 §7.4).
	s.acceptLoop(ctx, sc, presentedLeaf(cfg, nc))
}

// tlsAdmissible reports whether a TLS connection actually satisfies the two
// conditions RFC 9113 places on HTTP/2 over TLS. A cleartext connection is not
// this function's business and is always admitted.
//
//	§3.3 — "HTTP/2 connections over TLS MUST use protocol
//	negotiation in TLS [TLS-ALPN]."
//	§9.2 — "Implementations of HTTP/2 MUST use TLS version 1.2
//	[TLS12] or higher for HTTP/2 over TLS."
//
// Both are checked against what was actually negotiated rather than against the
// configuration, because a *tls.Config can be supplied by the caller
// (ListenAndServeTLSConfig, ServeTLSConfig) or already be in force on a
// connection handed to Serve. Called after conn.NewServerConn so the lazy TLS
// handshake has completed and ConnectionState is populated.
func tlsAdmissible(nc net.Conn) (tls.ConnectionState, bool) {
	tc, ok := nc.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, true
	}
	cs := tc.ConnectionState()
	return cs, cs.NegotiatedProtocol == "h2" && cs.Version >= tls.VersionTLS12
}

// acceptLoop reads streams from a ServerConn with optional idle timeout.
func (s *Server) acceptLoop(ctx context.Context, sc *conn.ServerConn, leaf *x509.Certificate) {
	if idle := s.idleTimeout(); idle > 0 {
		for {
			acceptCtx, cancel := context.WithTimeout(ctx, idle)
			stream, err := sc.AcceptStream(acceptCtx)
			cancel()
			if err != nil {
				// A deadline with streams still in flight does not end anything: the
				// connection is busy, it just has not opened a NEW stream lately.
				// Returning here would leave the socket open with nobody accepting
				// on it, so the response in flight completes and every request after
				// it is ignored. Keep waiting instead.
				if errors.Is(err, context.DeadlineExceeded) && sc.ActiveStreams() > 0 {
					continue
				}
				s.closeIfFinished(sc, err)
				return
			}
			if !s.spawnStream(stream, leaf) {
				return
			}
		}
	}
	for {
		stream, err := sc.AcceptStream(ctx)
		if err != nil {
			s.closeIfFinished(sc, err)
			return
		}
		if !s.spawnStream(stream, leaf) {
			return
		}
	}
}

// closeIfFinished tears the connection down on the two exits from the accept
// loop that mean it is over, and leaves it alone on the one that does not.
//
// The transport is nobody else's to close once this loop returns: serveConn
// untracks the connection immediately afterwards, so a connection left open
// here is invisible to Shutdown and survives as a leaked descriptor for the
// life of the process.
//
//   - ErrConnClosed means the reader goroutine has already exited, whatever the
//     cause. Nothing more will ever be read; Close reclaims the socket and the
//     framer's buffer.
//   - A deadline means no NEW stream arrived within IdleTimeout, which is not
//     the same as an idle connection. A single slow request — a gRPC
//     server-streaming call, an SSE feed, a large download — occupies the
//     connection for minutes without opening another stream, and closing it
//     would cancel every in-flight handler's context and cut the response in
//     half. Only a connection with no live streams is actually idle.
//   - Anything else (a cancelled parent context from Shutdown, a drain exit) is
//     someone else's teardown already in progress; touching the connection here
//     would truncate responses that are being drained on purpose.
func (s *Server) closeIfFinished(sc *conn.ServerConn, err error) {
	switch {
	case errors.Is(err, conn.ErrConnClosed):
		_ = sc.Close()
	case errors.Is(err, context.DeadlineExceeded) && sc.ActiveStreams() == 0:
		_ = sc.Close()
	}
}

// spawnStream begins serving stream unless the server is shutting down. It
// increments inFlight under s.mu, synchronized with Shutdown/Close (which set
// s.shutdown/s.closed under the same lock before waiting on inFlight) — so an
// Add can never race a returning inFlight.Wait(), the documented WaitGroup
// misuse. Returns false when the server is draining, signalling the accept loop
// to stop; the just-accepted stream is reset so the client can retry elsewhere.
func (s *Server) spawnStream(stream *conn.ServerStream, leaf *x509.Certificate) bool {
	s.mu.Lock()
	if s.shutdown || s.closed {
		s.mu.Unlock()
		_ = stream.Close() // refuse a stream that arrived after drain began
		return false
	}
	s.inFlight.Add(1)
	s.mu.Unlock()
	go s.serveStream(stream, leaf)
	return true
}

func (s *Server) serveStream(stream *conn.ServerStream, leaf *x509.Certificate) {
	defer s.inFlight.Done()

	// Backstop panic isolation: a panic anywhere in the request lifecycle
	// (buildRequest, body read, or a handler not already guarded by
	// dispatchAndClose) must not crash the whole process. Recover, log, and
	// tear down just this stream — every other connection survives.
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Printf("poseidon: recovered panic serving stream %d: %v\n%s", stream.ID(), rec, debug.Stack())
			_ = stream.Close()
		}
	}()

	// Drive the whole request lifecycle off the stream's context so a client
	// RST_STREAM or a connection close cancels the handler — and its writes and
	// body reads — promptly. It descends from the server context, so server
	// shutdown still propagates.
	ctx := stream.Context()

	var req *Request

	// Read HEADERS first.
	ev, err := stream.Recv(ctx)
	if err != nil {
		return
	}
	if ev.Type != conn.EventHeaders {
		_ = stream.Close()
		return
	}

	req = s.buildRequest(ev.Headers, stream.ID())

	// RFC 9110 §7.4 — reject a request this connection was not authenticated to
	// serve, before the handler ever sees it.
	if misdirectedRequest(req, leaf) {
		w := newConnResponseWriter(stream, req)
		_ = w.WriteHeaders(421, nil)
		_ = w.WriteTrailers(nil)
		_ = stream.Close()
		return
	}

	if ev.EndStream {
		// RFC 9110 §10.1.1 also allows the interim response to be omitted when
		// "the framing indicates that there is no content" — END_STREAM here.
		s.dispatchAndClose(ctx, stream, req)
		return
	}

	// RFC 9110 §10.1.1: a request carrying a 100-continue expectation, whose
	// framing indicates content will follow, MUST get either an immediate final
	// status "if that status can be determined by examining just the method,
	// target URI, and header fields" or "an immediate 100 (Continue) response".
	// Only the handler could determine the former, so the interim response is
	// the applicable branch.
	//
	// This is not cosmetic: in buffered mode the server waits for the whole body
	// before dispatching, while a client honouring its own expectation waits for
	// the 100 — both sides waiting on each other until something times out.
	if hasExpectContinue(ev.Headers) {
		if err := stream.SendHeaders(ctx, continue100Headers, false); err != nil {
			_ = stream.Close()
			return
		}
	}

	// Streaming mode: attach io.ReadCloser and dispatch immediately.
	if s.opts.StreamingBody {
		req.BodyReader = newStreamBody(ctx, stream, s.maxBodyBytes)
		s.dispatchAndClose(ctx, stream, req)
		return
	}

	// Buffered mode: collect DATA frames then dispatch.
	s.serveStreamBuffered(ctx, stream, req)
}

// serveStreamBuffered collects DATA/Trailers frames and dispatches.
func (s *Server) serveStreamBuffered(ctx context.Context, stream *conn.ServerStream, req *Request) {
	var bodyChunks [][]byte
	var total int64
	for {
		ev, err := stream.Recv(ctx)
		if err != nil {
			return
		}
		switch ev.Type {
		case conn.EventData:
			if ev.Data != nil {
				// Enforce the body-size cap BEFORE accumulating, so an
				// over-cap upload can never balloon memory: reject with 413
				// and drop the (already-collected) chunks immediately.
				total += int64(len(ev.Data))
				if s.maxBodyBytes >= 0 && total > s.maxBodyBytes {
					s.rejectTooLarge(stream)
					return
				}
				bodyChunks = append(bodyChunks, ev.Data)
			}
			if ev.EndStream {
				req.Body = joinChunks(bodyChunks)
				s.dispatchAndClose(ctx, stream, req)
				return
			}
		case conn.EventTrailers:
			req.Trailers = ev.Headers
			if ev.EndStream {
				req.Body = joinChunks(bodyChunks)
				s.dispatchAndClose(ctx, stream, req)
				return
			}
		case conn.EventReset:
			_ = stream.Close()
			return
		case conn.EventHeaders:
			// Extra HEADERS (illegal mid-stream), ignore.
		}
	}
}

// rejectTooLarge responds 413 (Request Entity Too Large) and tears the stream
// down. Used when a buffered request body exceeds MaxRequestBodyBytes. We send
// the status with END_STREAM via empty trailers, then Close (which RSTs if the
// client has not finished). No further body bytes are buffered.
func (s *Server) rejectTooLarge(stream *conn.ServerStream) {
	w := newConnResponseWriter(stream, nil)
	_ = w.WriteHeaders(http.StatusRequestEntityTooLarge, nil)
	_ = w.WriteTrailers(nil)
	_ = stream.Close()
}

func (s *Server) dispatchAndClose(ctx context.Context, stream *conn.ServerStream, req *Request) {
	if req == nil {
		_ = stream.Close()
		return
	}
	w := newConnResponseWriter(stream, req)
	// Per-request panic recovery: a panicking handler returns a 500 (if it has
	// not already written a response) and resets the stream, instead of
	// crashing the server. Mirrors net/http's per-request isolation.
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Printf("poseidon: recovered handler panic on stream %d: %v\n%s", stream.ID(), rec, debug.Stack())
			if !w.Written() {
				_ = w.WriteHeaders(500, nil)
				_ = w.WriteTrailers(nil)
			}
			_ = stream.Close()
		}
	}()
	if err := s.handler.ServeHTTP(ctx, req, w); err != nil {
		s.logger.Printf("poseidon: handler error on stream %d: %v", stream.ID(), err)
		if !w.Written() {
			_ = w.WriteHeaders(500, nil)
		}
		// Send EndStream via empty trailers.
		_ = w.WriteTrailers(nil)
		_ = stream.Close()
		return
	}
	if !w.Written() {
		_ = w.WriteHeaders(200, nil)
	}
	// Send EndStream via empty trailers.
	_ = w.WriteTrailers(nil)
	_ = stream.Close()
}

func (s *Server) buildRequest(headers []hpack.HeaderField, streamID uint32) *Request {
	req := &Request{Headers: headers, streamID: streamID}
	// hostField is the fallback source for the target URI's authority. RFC 9110
	// §7.2 (rfc9110.txt:2426): "A user agent MUST generate a Host header field
	// in a request unless it sends that information as an ":authority"
	// pseudo-header field" — so a request carrying only Host is legal and its
	// authority must come from there. RFC 9113 §8.3.1 fixes
	// the precedence: "The recipient of an HTTP/2 request MUST NOT use the Host
	// header field to determine the target URI if ":authority" is present."
	var hostField string
	for _, h := range headers {
		if req.Authority == "" && len(h.Name) > 0 && h.Name[0] != ':' && strings.EqualFold(string(h.Name), "host") {
			hostField = string(h.Value)
		}
		switch string(h.Name) {
		case ":method":
			req.Method = string(h.Value)
		case ":path":
			// Raw :path per RFC 7540 §8.1.2.3; may include query string.
			// Path stays raw for back-compat with chi-style routers
			// that match routes by the full request line; RawQuery
			// exposes the pre-parsed query string (without '?').
			raw := string(h.Value)
			_, query := splitPathQuery(raw)
			req.Path = raw
			req.RawQuery = query
		case ":scheme":
			req.Scheme = string(h.Value)
		case ":authority":
			req.Authority = string(h.Value)
		}
	}
	if req.Authority == "" {
		req.Authority = hostField
	}
	return req
}

// splitPathQuery splits an :path value into path and query string.
// The query is returned without the leading '?'. Returns path only
// if no query is present. Both inputs are safe with arbitrary user
// data (no allocation beyond a single substring copy).
func splitPathQuery(reqPath string) (path, rawQuery string) {
	for i := range len(reqPath) {
		if reqPath[i] == '?' {
			return reqPath[:i], reqPath[i+1:]
		}
	}
	return reqPath, ""
}

func joinChunks(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		return nil
	}
	if len(chunks) == 1 {
		return chunks[0]
	}
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func (s *Server) trackConn(sc *conn.ServerConn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[sc] = struct{}{}
	} else {
		s.forgetConn(sc)
	}
}

// forgetConn removes sc from the live set, folding its final counters into
// closedStats so transport totals stay monotonic across connection close. It is
// idempotent (a no-op if sc is already gone), so the per-connection teardown
// defer and Close/Shutdown can all funnel through it without double-counting.
// Caller must hold s.mu.
func (s *Server) forgetConn(sc *conn.ServerConn) {
	if _, ok := s.conns[sc]; !ok {
		return
	}
	st := sc.Stats()
	s.closedStats.bytesSent += st.BytesSent
	s.closedStats.bytesReceived += st.BytesReceived
	s.closedStats.framesSent += st.FramesSent
	s.closedStats.framesReceived += st.FramesReceived
	s.closedStats.streamsAccepted += uint64(st.StreamsAccepted)
	s.closedStats.rapidResets += uint64(st.RapidResets)
	if st.GoAwaySent {
		s.closedStats.goAways++
	}
	delete(s.conns, sc)
}

// ConnCount returns the number of connections the server is currently tracking.
func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// TransportStats is an aggregate, point-in-time snapshot of HTTP/2 transport
// counters across every connection the server has handled. The byte/frame/stream
// and rapid-reset/GOAWAY fields are monotonic counters (they include connections
// that have since closed); ActiveConns is a gauge of currently-open connections.
type TransportStats struct {
	ActiveConns     int
	BytesSent       int64
	BytesReceived   int64
	FramesSent      int64
	FramesReceived  int64
	StreamsAccepted uint64
	RapidResets     uint64
	GoAways         uint64
}

// TransportStats returns the aggregate transport counters across all live and
// closed connections. Safe for concurrent use. Suitable as the source for a
// metrics exporter (see middleware.MetricsCollector.SetTransportSource).
func (s *Server) TransportStats() TransportStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := TransportStats{
		ActiveConns:     len(s.conns),
		BytesSent:       s.closedStats.bytesSent,
		BytesReceived:   s.closedStats.bytesReceived,
		FramesSent:      s.closedStats.framesSent,
		FramesReceived:  s.closedStats.framesReceived,
		StreamsAccepted: s.closedStats.streamsAccepted,
		RapidResets:     s.closedStats.rapidResets,
		GoAways:         s.closedStats.goAways,
	}
	for sc := range s.conns {
		st := sc.Stats()
		ts.BytesSent += st.BytesSent
		ts.BytesReceived += st.BytesReceived
		ts.FramesSent += st.FramesSent
		ts.FramesReceived += st.FramesReceived
		ts.StreamsAccepted += uint64(st.StreamsAccepted)
		ts.RapidResets += uint64(st.RapidResets)
		if st.GoAwaySent {
			ts.GoAways++
		}
	}
	return ts
}

// Addr returns a listener address, or nil if not listening. When multiple
// listeners are served, an arbitrary one is returned.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ln := range s.listeners {
		return ln.Addr()
	}
	return nil
}

// Close stops accepting new connections and tears down the listener, causing
// Serve/ListenAndServe to return ErrServerClosed. It is safe to call multiple
// times; only the first call has an effect.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	for ln := range s.listeners {
		_ = ln.Close()
		delete(s.listeners, ln)
	}
	for sc := range s.conns {
		_ = sc.Close()
		s.forgetConn(sc)
	}
	return nil
}

// Shutdown gracefully shuts down the server without interrupting active
// streams. It closes the listener and waits for in-flight streams to
// complete or the context to be cancelled.
//
// If the context expires before all streams are done, remaining
// connections are forcibly closed (equivalent to Close).
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.shutdown = true
	s.closed = true

	// Drain start: flip readiness to NOT-ready BEFORE closing the listener or
	// sending GOAWAY, so k8s removes this instance from Service endpoints and
	// stops routing new traffic while in-flight streams continue to drain.
	if s.opts.OnDrainStart != nil {
		s.opts.OnDrainStart()
	}

	// Close listeners — stop accepting new connections.
	for ln := range s.listeners {
		_ = ln.Close()
		delete(s.listeners, ln)
	}
	close(s.closeCh)

	// Snapshot current connections.
	conns := make([]*conn.ServerConn, 0, len(s.conns))
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	// Send GOAWAY to all connections so clients stop opening new streams.
	for _, sc := range conns {
		_ = sc.GoAwayGraceful()
	}

	// Wait for in-flight streams to complete or context cancellation.
	done := make(chan struct{})
	go func() {
		s.inFlight.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All streams completed gracefully.
	case <-ctx.Done():
		// Timeout — forcibly close remaining connections.
		s.mu.Lock()
		for _, sc := range conns {
			_ = sc.Close()
			s.forgetConn(sc)
		}
		s.mu.Unlock()
		return ctx.Err()
	}

	// Close connections gracefully.
	s.mu.Lock()
	for _, sc := range conns {
		_ = sc.Close()
		s.forgetConn(sc)
	}
	s.mu.Unlock()
	return nil
}

// --- 100-continue expectation (RFC 9110 §10.1.1) -----------------------------

var (
	sFieldExpect       = []byte("expect")
	sExpect100Continue = []byte("100-continue")

	// continue100Headers is the interim response's field section. RFC 9113
	// §8.3.2 requires :status "in all responses, including
	// interim responses". Package-level and reused, never re-minted (ADR-0001);
	// nothing writes to it.
	continue100Headers = []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("100")},
	}
)

// hasExpectContinue reports whether the field section carries a 100-continue
// expectation.
//
// Expect is a list — "Expect = #expectation" (RFC 9110 §10.1.1) — so the value
// is scanned member by member rather than compared whole. The scan allocates
// nothing: IndexByte and TrimSpace both return sub-slices. The field value is
// case-insensitive, as the same section states.
func hasExpectContinue(headers []hpack.HeaderField) bool {
	for i := range headers {
		if !bytes.EqualFold(headers[i].Name, sFieldExpect) {
			continue
		}
		v := headers[i].Value
		for len(v) > 0 {
			member := v
			if j := bytes.IndexByte(v, ','); j >= 0 {
				member, v = v[:j], v[j+1:]
			} else {
				v = nil
			}
			if bytes.EqualFold(bytes.TrimSpace(member), sExpect100Continue) {
				return true
			}
		}
	}
	return false
}

// --- 421 Misdirected Request (RFC 9110 §7.4) ---------------------------------

// presentedLeaf returns the leaf certificate this server presented on nc, or
// nil when there is nothing to judge against — a cleartext connection, or a TLS
// listener the caller wrapped itself and passed to the bare Serve.
//
// crypto/tls does not expose the server's own certificate through
// ConnectionState (it carries the SNI and the *peer's* certificates), so the
// config that selected it has to be threaded down from the entry point. That is
// why ServeTLSConfig exists.
func presentedLeaf(cfg *tls.Config, nc net.Conn) *x509.Certificate {
	if cfg == nil {
		return nil
	}
	if _, ok := nc.(*tls.Conn); !ok {
		return nil
	}
	return selectLeaf(cfg)
}

// selectLeaf returns the leaf certificate the handshake presented, but only
// when that is knowable without guessing.
//
// crypto/tls selects a certificate through GetConfigForClient, then
// GetCertificate (consulted only when Certificates is empty or SNI is
// non-empty), then Certificates with its own SNI matching, and a (nil, nil)
// return from GetCertificate means "fall back to Certificates". Re-running that
// from outside the handshake gets it wrong in ways that matter: an adversarial
// review of an earlier version of this function found it would judge a request
// against a certificate the peer never saw — producing FALSE 421s on
// legitimate traffic — and that a GetCertificate written with the
// crypto/tls-documented hello.SupportsCertificate idiom would error against a
// synthetic ClientHelloInfo and silently switch the check off server-wide.
//
// Rejecting a legitimate request is worse than not enforcing the rule, so this
// enforces only the one arrangement with a single possible answer: exactly one
// static certificate and no callbacks. Anything else returns nil and the check
// stands down. Serving several certificates from one listener therefore opts
// out; that is a deliberate, documented limitation rather than a guess.
func selectLeaf(cfg *tls.Config) *x509.Certificate {
	if cfg.GetConfigForClient != nil || cfg.GetCertificate != nil {
		return nil
	}
	if len(cfg.Certificates) != 1 {
		return nil
	}
	cert := &cfg.Certificates[0]
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

// misdirectedRequest reports whether the request must be answered with 421.
//
// RFC 9110 §7.4 (rfc9110.txt:2510): "Unless the connection is from a trusted
// gateway, an origin server MUST reject a request if any scheme-specific
// requirements for the target URI are not met. In particular, a request for an
// "https" resource MUST be rejected unless it has been received over a
// connection that has been secured via a certificate valid for that target
// URI's origin, as defined by Section 4.2.2."
//
// Three exclusions come straight from that sentence:
//
//   - It binds "a request for an "https" resource", so another :scheme is out
//     of scope.
//   - With no certificate in hand there is nothing to verify against. For a
//     cleartext connection that is h2c, whose documented deployment is behind a
//     TLS-terminating proxy (ADR-0005) — the "connection is from a trusted
//     gateway" case the same sentence exempts.
//   - A hostless target URI cannot be judged: there is no origin to compare.
//     The stdlib-compat path rejects it earlier (NewHTTPRequest returns
//     ErrNoAuthority); a native handler receives it, which is pre-existing
//     behaviour this check does not change either way.
//
// The comparison is against the certificate rather than the SNI deliberately: a
// client may coalesce connections and reuse one for any origin the certificate
// covers, which SNI-matching would wrongly reject.
func misdirectedRequest(req *Request, leaf *x509.Certificate) bool {
	// EqualFold: RFC 9110 §4.2.3 (rfc9110.txt:1179) — "The scheme and host are
	// case-insensitive". A byte comparison here would let a client disable the
	// whole check by sending ":scheme: HTTPS", which net/url then lowercases
	// downstream so the handler sees an ordinary https request.
	if leaf == nil || !strings.EqualFold(req.Scheme, schemeHTTPS) {
		return false
	}
	host := req.Authority
	if h, _, err := net.SplitHostPort(host); err == nil {
		// A port is not part of the identity a certificate attests to.
		host = h
	}
	if host == "" {
		// Nothing to compare against; see the note above.
		return false
	}
	return leaf.VerifyHostname(host) != nil
}
