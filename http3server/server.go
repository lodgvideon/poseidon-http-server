// Package http3server serves HTTP/3 (RFC 9114) to an ordinary http.Handler.
//
// It maps QUIC streams onto HTTP semantics: each client-initiated bidirectional
// stream carries one request/response exchange. The QUIC transport, the HTTP/3
// frame codec, and QPACK field compression all come from poseidon-http-client,
// which owns the wire format for both roles; this package is the http.Handler
// adapter on top.
//
// # Status
//
// It speaks the static-table QPACK profile (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0),
// which is fully conformant and never blocks on head-of-line. Server push, 0-RTT,
// and trailers are not implemented. See the transport's limits in
// poseidon-http-client's quic.Listener: no Retry / address validation and no
// per-peer rate limiting, so front this with a rate limiter before exposing it to
// the internet.
//
// # Peer identity
//
// http.Request.TLS is populated on every request from the connection's completed
// handshake, so a handler can read the negotiated TLS version, cipher suite, SNI
// and ALPN. PeerCertificates is always empty today: a QUIC listener configured to
// require a client certificate never completes its handshake at all
// (poseidon-http-client#711), so mTLS is unavailable on HTTP/3 in either role and
// this field cannot yet carry a peer identity.
//
// http.Request.RemoteAddr is NOT populated, and neither is server.PeerAddr on the
// request context. The transport holds each connection's peer address privately
// and quic.Conn exposes no accessor for it, so this package has no way to reach
// it (poseidon-http-client#710). Anything that authorizes or buckets by client
// address — IP allowlists, per-client rate limiting, abuse logging — is blind on
// HTTP/3 until that lands; do not read RemoteAddr here and conclude the client is
// unknown-but-absent, because it is unknown-and-unavailable.
package http3server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// Default limits. maxRequestBytes bounds a buffered request; maxFieldSection
// bounds a field section, the value advertised as SETTINGS_MAX_FIELD_SECTION_SIZE.
const (
	maxRequestBytes uint64 = 1 << 20
	maxFieldSection uint64 = 1 << 16
	maxStreamsBidi  uint64 = 100 // concurrent requests a client may have in flight
	maxStreamsUni   uint64 = 4   // client control + QPACK encoder/decoder, with slack
)

// defaultIdleTimeout is the QUIC max_idle_timeout this server advertises when
// Server.IdleTimeout is zero. It matches server.defaultIdleTimeout, this repo's
// secure default for the HTTP/2 server, and RFC 4787's REQ-5 — quoted by RFC 9000
// §10.1.2 as recommending "a 2-minute timeout interval" for UDP NAT mappings, past
// which the path is likely gone regardless of what either endpoint keeps in memory.
const defaultIdleTimeout = 120 * time.Second

// Server serves HTTP/3 requests to Handler.
type Server struct {
	// Handler answers requests. A nil Handler serves http.DefaultServeMux.
	Handler http.Handler
	// TLSConfig must carry the server's certificate(s). ALPN "h3" is filled in
	// when NextProtos is unset.
	TLSConfig *tls.Config

	// IdleTimeout is the QUIC max_idle_timeout this server advertises (RFC 9000
	// §18.2, §10.1): after this long with no packet received, the connection is
	// silently closed and its state discarded.
	//
	//   0  => secure default (defaultIdleTimeout)
	//   <0 => advertise none (the parameter is omitted)
	//   >0 => explicit timeout
	//
	// The effective timeout is the minimum of the two advertised values (§10.1),
	// so this is a ceiling, not a floor: a peer asking for less gets less.
	//
	// <0 is the pre-#168 behaviour and is unsafe on an open network — with a peer
	// that also advertises none, §10.1 leaves the idle timeout disabled entirely
	// and one handshake buys an attacker a connection this package will never
	// reap. It exists for closed deployments that keep connections alive by other
	// means.
	IdleTimeout time.Duration
}

// transportParams are the QUIC transport parameters this server advertises. Every
// path that builds a listener for a Server must use it, so no caller can quietly
// drop max_idle_timeout the way ListenAndServe did before #168.
func (s *Server) transportParams() quic.ServerTransportParams {
	return quic.ServerTransportParams{
		MaxStreamsBidi: maxStreamsBidi,
		MaxStreamsUni:  maxStreamsUni,
		MaxIdleTimeout: s.idleTimeoutMillis(),
	}
}

// idleTimeoutMillis renders IdleTimeout as the millisecond integer the transport
// parameter carries: "The maximum idle timeout is a value in milliseconds that is
// encoded as an integer" (RFC 9000 §18.2).
//
// Zero is not a small timeout but the absence of one — "Idle timeout is disabled
// when both endpoints omit this transport parameter or specify a value of 0" (§18.2)
// — so a positive IdleTimeout below a millisecond is raised to 1ms rather than
// rounded down into that hole. The transport floors the effective period at three
// PTOs anyway (RFC 9000 §10.1: "endpoints MUST increase the idle timeout period to
// be at least three times the current Probe Timeout"), so the clamp cannot produce a
// connection that closes under loss recovery.
func (s *Server) idleTimeoutMillis() uint64 {
	d := s.IdleTimeout
	switch {
	case d < 0:
		return 0 // advertise none
	case d == 0:
		d = defaultIdleTimeout
	}
	if ms := d.Milliseconds(); ms > 0 {
		return uint64(ms)
	}
	return 1
}

// ListenAndServe listens on addr ("host:port") and serves HTTP/3 until ctx is
// cancelled or the listener fails.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	l, err := quic.Listen(addr, s.TLSConfig, s.transportParams())
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	return s.Serve(ctx, l)
}

// Serve accepts connections from l and serves each until ctx is cancelled.
//
// l carries the transport parameters it was built with, so IdleTimeout takes
// effect only when the caller built l from transportParams, as ListenAndServe
// does. A listener assembled by hand without max_idle_timeout advertises none
// whatever IdleTimeout says, and RFC 9000 §18.2 then leaves the idle timeout
// disabled against a peer that also advertises none (issue #168).
func (s *Server) Serve(ctx context.Context, l *quic.Listener) error {
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		go s.serveConn(ctx, c)
	}
}

// handler returns the handler to serve with.
func (s *Server) handler() http.Handler {
	if s.Handler != nil {
		return s.Handler
	}
	return http.DefaultServeMux
}

// serveConn drives one connection. This goroutine owns the connection's Poll
// loop — the only thing that reads the socket — and hands each request stream to
// its own goroutine, which waits on that stream's readiness. It mirrors how the
// client drives a connection, so no new concurrency model is introduced.
func (s *Server) serveConn(ctx context.Context, c *quic.Conn) {
	defer func() { _ = c.Close() }()

	if err := s.openControlStream(c); err != nil {
		return
	}

	cs := newConnState()

	// Snapshot the TLS state ONCE per connection, here, before the Poll loop
	// starts. Three reasons this is the only correct place:
	//
	//   - Cost. Every request on the connection shares this one snapshot, so the
	//     per-request cost is a pointer store. Calling ConnectionState() per
	//     request would copy a tls.ConnectionState — a certificate chain and a
	//     signed-certificate-timestamp list among other fields — for each one.
	//   - Concurrency. quic.Conn is not safe for concurrent use, and this
	//     goroutine owns it: it drives Poll and nothing else touches the
	//     connection. Reading the state from the per-request goroutines below
	//     would race that loop. Taking it before the loop needs no lock, no
	//     atomic and no handoff — the value is immutable once the handshake is
	//     complete, which it is by the time Accept returns.
	//   - Sharing. One *tls.ConnectionState across every request on a connection
	//     is what net/http and x/net/http2 both do (Server.conn.tlsState,
	//     http2serverConn.tlsState); handlers read it and must not write it.
	//
	// The peer address cannot be attached the same way: quic.Conn exposes no
	// remote-address accessor, so there is nothing to put on the context here.
	// See the package doc and poseidon-http-client#710; issue #102 stays open on
	// the address half.
	cs.tlsState = c.ConnectionState()

	for {
		if err := c.Poll(ctx); err != nil {
			return // the connection ended: idle timeout, peer close, or ctx
		}
		// Service the client's unidirectional streams — its control stream above
		// all — BEFORE accepting request streams. When one Poll pass delivers the
		// client's SETTINGS and its first request together, this ordering applies
		// the settings before the request goroutine that reads them exists. The
		// other order is not a race in the data sense (peerMaxFieldSection is an
		// atomic) but it would answer that request under the wrong limit.
		if err := cs.serviceUni(c); err != nil {
			return // the peer violated the protocol; the connection is closed
		}
		for rs := c.AcceptBidiStream(); rs != nil; rs = c.AcceptBidiStream() {
			go s.serveRequest(ctx, c, rs, cs)
		}
	}
}

// openControlStream opens the server's control stream and sends SETTINGS, which
// RFC 9114 §6.2.1 requires as its first frame. A client that sees no SETTINGS
// treats the connection as an error, so this must precede any response.
func (s *Server) openControlStream(c *quic.Conn) error {
	ctl, err := c.OpenUniStream()
	if err != nil {
		return err
	}
	// The control stream is stream type 0x00 followed by SETTINGS, identically for
	// both roles.
	frame := http3.AppendClientControlStream(nil, []http3.Setting{
		{ID: http3.SettingMaxFieldSectionSize, Value: maxFieldSection},
		// Advertise the static-table QPACK profile: no dynamic table, no blocked
		// streams. This is what our decoder implements.
		{ID: http3.SettingQPACKMaxTableCapacity, Value: 0},
		{ID: http3.SettingQPACKBlockedStreams, Value: 0},
	})
	_, err = ctl.Send(frame, false) // the control stream stays open
	return err
}

// serveRequest reads one request off its stream, runs the handler, and writes the
// response back on the same stream. cs is the connection's shared state: the TLS
// state snapshotted once by serveConn, and the field-section limit the peer's
// SETTINGS advertised — both read-only here.
//
// # Why this goroutine may close the connection
//
// Some frames on a request stream are CONNECTION errors (§7.2), so the verdict has
// to reach c from here. That is safe, and it is not a hole in "the serveConn
// goroutine owns the connection": what serveConn owns exclusively is Poll and the
// unlocked ConnectionState() read taken before the loop. quic.Conn.CloseWithError
// takes the same connection mutex as the rs.Send / rs.Reset / rs.Recv calls this
// goroutine already makes, it is idempotent and first-error-wins, and the mutex is
// explicitly released across Poll's blocking read ("BLOCKING, UNLOCKED — a Do may
// seal+send here", quic/conn_recv.go), which is how the client's own Do goroutines
// share a connection with its reader. Closing here therefore takes effect at once
// and unblocks Poll, rather than waiting for the peer's next packet to arrive.
func (s *Server) serveRequest(ctx context.Context, c *quic.Conn, rs *quic.Stream, cs *connState) {
	body, err := readRequestStream(ctx, rs)
	if err != nil {
		// The request never arrived whole: the peer reset it, it outgrew the buffer,
		// or the connection is going away.
		_ = rs.Reset(http3.H3RequestCancelled)
		return
	}
	req, err := decodeRequest(body)
	if err != nil {
		var cfe *connFrameError
		if errors.As(err, &cfe) {
			// Not a malformed request but an illegal frame sequence: §7.2 requires
			// the CONNECTION be closed, so resetting the stream and serving on would
			// leave the violation unanswered.
			_ = connError(c, cfe.code)
			return
		}
		_ = rs.Reset(http3.H3MessageError)
		return
	}
	req = req.WithContext(ctx)
	// HTTP/3 runs over QUIC, which is TLS 1.3 by construction (RFC 9001): there is
	// no plaintext HTTP/3, so this is never nil on a served request. Leaving it
	// nil made every net/http handler that gates on `r.TLS != nil` — HSTS, secure
	// cookies, mTLS authorization — treat the most-encrypted transport the server
	// speaks as cleartext, while req.URL.Scheme said "https" three lines away.
	req.TLS = &cs.tlsState

	rw := &responseWriter{header: http.Header{}, status: http.StatusOK}
	s.handler().ServeHTTP(rw, req)

	resp, err := encodeResponse(rw, cs.peerMaxFieldSection.Load())
	if err != nil {
		_ = rs.Reset(http3.H3InternalError)
		return
	}
	_, _ = rs.Send(resp, true) // FIN: the response ends the stream
}

// readRequestStream buffers a whole request. The connection's Poll loop feeds the
// stream; this waits on its readiness until the client signals the end with a FIN.
func readRequestStream(ctx context.Context, rs *quic.Stream) ([]byte, error) {
	var buf []byte
	for {
		// Read the state BEFORE draining. Once a stream reports finished every byte
		// is contiguous, so the Recv below drains the rest. Draining first and then
		// asking would race the connection's Poll loop: data can land in between,
		// and the finished report would send us away without it — a request whose
		// body silently vanishes.
		finished, reset, _ := rs.RecvState()
		buf = append(buf, rs.Recv()...)
		if reset {
			return nil, io.ErrUnexpectedEOF
		}
		if uint64(len(buf)) > maxRequestBytes {
			return nil, io.ErrShortBuffer
		}
		if finished {
			return buf, nil
		}
		if err := rs.WaitReadable(ctx); err != nil {
			return nil, err
		}
	}
}

// connFrameError reports a frame whose receipt is a CONNECTION error rather than a
// stream error (RFC 9114 §8): the offending frame type, the §8.1 code the
// connection must be closed with, and the rule it broke.
//
// It exists so decodeRequest can stay a pure function of the peer's bytes — it is
// the package's top untrusted surface and has a fuzz target — while still reaching
// a verdict only the connection can act on. Handing the decoder a *quic.Conn would
// put connection teardown inside the function the fuzzer drives.
type connFrameError struct {
	typ  uint64 // the frame type that is not permitted here
	code uint64 // the HTTP/3 error code to close the connection with (§8.1)
	why  string // the rule broken, for the error string only
}

func (e *connFrameError) Error() string {
	return "http3server: frame type " + strconv.FormatUint(e.typ, 16) + " " + e.why
}

// decodeRequest turns a request stream's frames into an http.Request. RFC 9114 §4.1
// fixes the sequence: "An HTTP message (request or response) consists of: 1. the
// header section ... sent as a single HEADERS frame, 2. optionally, the content, if
// present, sent as a series of DATA frames, and 3. optionally, the trailer section,
// if present, sent as a single HEADERS frame."
//
// The same section makes a departure from that order a connection error, and names
// the three cases: "Receipt of an invalid sequence of frames MUST be treated as a
// connection error of type H3_FRAME_UNEXPECTED. In particular, a DATA frame before
// any HEADERS frame, or a HEADERS or DATA frame after the trailing HEADERS frame, is
// considered invalid." All three are rejected below, before any of the message
// reaches a handler.
//
// The last of them is the one with teeth. Bytes a peer places after the trailer
// section are not content: an intermediary that parses the stream conformantly ends
// the body at the trailers, so folding them in would leave that intermediary and this
// server disagreeing about where the message ends — a request-smuggling differential
// (issue #167), not a conformance nit. Rejecting is also why the whole message is
// refused rather than truncated at the trailers: a handler must not be able to
// observe part of a message as if it were the whole of one.
//
// A *connFrameError return means the frame sequence is a connection error, not a
// malformed request: the caller must close the connection with its code rather than
// reset the stream.
func decodeRequest(stream []byte) (*http.Request, error) {
	var fr http3.FrameReader
	fr.SetMaxFrameLen(maxRequestBytes)
	fr.Feed(stream)

	var (
		fields   []hpack.HeaderField
		body     []byte
		seen     bool // the header section has arrived
		trailers bool // the trailing HEADERS frame has arrived; nothing may follow it
	)
	for {
		typ, payload, err := fr.ReadFrame()
		if errors.Is(err, http3.ErrNeedMore) {
			break // a partial trailing frame: the request holds nothing more
		}
		if err != nil {
			return nil, err
		}
		switch typ {
		case http3.FrameHeaders:
			if trailers {
				// §4.1: "a HEADERS or DATA frame after the trailing HEADERS frame".
				// A message carries at most two field sections — header and trailer —
				// so a third HEADERS frame has no place in the sequence.
				return nil, &connFrameError{
					typ:  typ,
					code: http3.H3FrameUnexpected,
					why:  "arrived after the trailing HEADERS frame (RFC 9114 §4.1)",
				}
			}
			if seen {
				trailers = true
				continue // the trailer section: read for its position, not surfaced
			}
			seen = true
			if fields, err = decodeFields(payload); err != nil {
				return nil, err
			}
		case http3.FrameData:
			if !seen || trailers {
				// §4.1: "a DATA frame before any HEADERS frame, or a HEADERS or DATA
				// frame after the trailing HEADERS frame, is considered invalid."
				return nil, &connFrameError{
					typ:  typ,
					code: http3.H3FrameUnexpected,
					why:  "arrived outside the message content (RFC 9114 §4.1)",
				}
			}
			body = append(body, payload...)
		case http3.FrameSettings, http3.FrameCancelPush, http3.FrameMaxPushID, http3.FramePushPromise,
			0x02, 0x06, 0x08, 0x09:
			// Frames that belong on the control stream, plus the HTTP/2-carryover
			// types that belong nowhere. Each names H3_FRAME_UNEXPECTED here in RFC
			// 9114 by itself: SETTINGS §7.2.4, CANCEL_PUSH §7.2.3, MAX_PUSH_ID
			// §7.2.7, PUSH_PROMISE at a server §7.2.5, and 0x02/0x06/0x08/0x09
			// §7.2.8 ("These frame types MUST NOT be sent, and their receipt MUST be
			// treated as a connection error of type H3_FRAME_UNEXPECTED"; §11.2.1
			// Table 2 registers each as Reserved).
			//
			// GOAWAY is deliberately absent. §7.2.6 scopes its rule to one role — "A
			// client MUST treat a GOAWAY frame on a stream other than the control
			// stream as a connection error of type H3_FRAME_UNEXPECTED" — and this
			// is the server. Killing a connection the RFC does not say to kill is
			// the failure mode this switch exists to avoid in the other direction.
			return nil, &connFrameError{
				typ:  typ,
				code: http3.H3FrameUnexpected,
				why:  "is not permitted on a request stream (RFC 9114 §7.2)",
			}
		default:
			// Genuinely unknown types and the GREASE types of §7.2.8 (0x1f*N + 0x21)
			// are ignored, which §4.1 requires and an interop suite checks: "Frames
			// of unknown types (Section 9), including reserved frames (Section
			// 7.2.8) MAY be sent on a request or push stream before, after, or
			// interleaved with other frames described in this section."
		}
	}
	if !seen {
		return nil, http3.ErrH3Message
	}
	return buildRequest(fields, body)
}

// decodeFields decodes a QPACK field section under the static-table profile.
func decodeFields(section []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	err := qpack.NewDecoder().DecodeFieldSection(section, nil, func(name, value []byte) error {
		// name/value alias the decoder's scratch, so copy them.
		fields = append(fields, hpack.HeaderField{
			Name:  append([]byte(nil), name...),
			Value: append([]byte(nil), value...),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// buildRequest maps a decoded field section and body onto an http.Request
// (RFC 9114 §4.3.1: :method, :scheme, :path and :authority).
func buildRequest(fields []hpack.HeaderField, body []byte) (*http.Request, error) {
	var method, scheme, path, authority string
	header := http.Header{}
	for _, f := range fields {
		switch string(f.Name) {
		case ":method":
			method = string(f.Value)
		case ":scheme":
			scheme = string(f.Value)
		case ":path":
			path = string(f.Value)
		case ":authority":
			authority = string(f.Value)
		default:
			if len(f.Name) > 0 && f.Name[0] == ':' {
				return nil, http3.ErrH3Message // an unknown pseudo-header
			}
			header.Add(string(f.Name), string(f.Value))
		}
	}
	if method == "" || scheme == "" || path == "" {
		return nil, http3.ErrH3Message
	}
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, http3.ErrH3Message
	}
	req := &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/3.0",
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          authority,
		RequestURI:    path,
	}
	if authority != "" {
		req.URL.Host = authority
	}
	req.URL.Scheme = scheme
	return req, nil
}

// encodeResponse builds the response stream: a HEADERS frame with the QPACK field
// section, then a DATA frame with the body (RFC 9114 §4.1).
//
// fieldSectionLimit is the limit the field section is held to: the peer's
// SETTINGS_MAX_FIELD_SECTION_SIZE once its control stream has delivered one, and
// this server's own constant until then. §4.2.2 makes the peer's value advice to a
// sender — "An implementation that has received this parameter SHOULD NOT send an
// HTTP message header that exceeds the indicated size, as the peer will likely
// refuse to process it" — so a response over the limit is refused here rather than
// sent for the peer to discard.
func encodeResponse(rw *responseWriter, fieldSectionLimit uint64) ([]byte, error) {
	fields := make([]hpack.HeaderField, 0, len(rw.header)+1)
	// :status leads the field section (RFC 9114 §4.3.2).
	fields = append(fields, hpack.HeaderField{
		Name:  []byte(":status"),
		Value: []byte(strconv.Itoa(rw.status)),
	})
	for name, values := range rw.header {
		for _, v := range values {
			fields = append(fields, hpack.HeaderField{
				Name:  []byte(lowerASCII(name)), // field names are lowercase on the wire
				Value: []byte(v),
			})
		}
	}
	// The size §4.2.2 bounds is "calculated based on the uncompressed size of
	// fields, including the length of the name and value in bytes plus an overhead
	// of 32 bytes for each field" — NOT the length of the QPACK block on the wire,
	// which is smaller by however well the field section happened to compress and
	// so admits sections the peer will refuse. Summed on uint64 so a handler
	// setting a huge header cannot overflow it.
	var size uint64
	for i := range fields {
		size += uint64(len(fields[i].Name)) + uint64(len(fields[i].Value)) + fieldLineOverhead
	}
	if size > fieldSectionLimit {
		return nil, http3.ErrFieldSectionTooLarge
	}
	out := http3.AppendHeaders(nil, qpack.NewEncoder().EncodeFieldSection(nil, fields))
	if rw.body.Len() > 0 {
		out = http3.AppendData(out, rw.body.Bytes())
	}
	return out, nil
}

// lowerASCII lowercases an HTTP field name, which is ASCII by definition.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// responseWriter buffers a handler's response until the whole exchange can be
// framed. HTTP/3 sends the field section as one QPACK block, so the status and
// headers must be final before anything goes on the wire; streaming a body as it
// is written is a later phase.
type responseWriter struct {
	header      http.Header
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}
