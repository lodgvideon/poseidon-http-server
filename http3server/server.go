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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
	"github.com/lodgvideon/poseidon-http-client/quic"
	"github.com/lodgvideon/poseidon-http-server/internal/httpfields"
)

// Default limits. maxRequestBytes bounds a buffered request; maxFieldSection
// bounds a field section, the value advertised as SETTINGS_MAX_FIELD_SECTION_SIZE.
const (
	maxRequestBytes uint64 = 1 << 20
	maxFieldSection uint64 = 1 << 16
	maxStreamsBidi  uint64 = 100 // concurrent requests a client may have in flight
	maxStreamsUni   uint64 = 4   // client control + QPACK encoder/decoder, with slack
)

// h3RequestIncomplete is H3_REQUEST_INCOMPLETE, RFC 9114 §8.1: "The client's stream
// terminated without containing a fully formed request."
//
// It is spelled out here rather than taken from http3 because poseidon-http-client
// v0.13.0's §8.1 table does not define it. That table is otherwise the source for
// every code this package sends, so the omission is the dependency's, not a local
// preference — see poseidon-http-client#775, which also covers the other three §8.1
// codes missing from it (H3_GENERAL_PROTOCOL_ERROR 0x0101, H3_CONNECT_ERROR 0x010f,
// H3_VERSION_FALLBACK 0x0110). Replace this constant with http3.H3RequestIncomplete
// once that lands.
const h3RequestIncomplete uint64 = 0x010d

// Request-stream failures that carry a different verdict to the peer. RFC 9114 names
// a distinct reset code per condition (§4.1, §4.1.1), so the conditions have to stay
// distinguishable all the way from where they are detected to where the stream is
// aborted; before issue #180 they were all funnelled into one code at the call site.
var (
	// errRequestTooLarge: the request outgrew maxRequestBytes. Not a reset at all —
	// §4.1's "abort reading the request stream, send a complete response" path.
	errRequestTooLarge = errors.New("http3server: request exceeds the buffered-request limit")
	// errRequestIncomplete: the stream ended without a fully formed request, either
	// because the peer reset it mid-message or because it carried no HEADERS frame.
	errRequestIncomplete = errors.New("http3server: request stream ended without a complete message")
	// errRequestAbandoned: this server stopped waiting — its context was cancelled or
	// the connection ended — while the request was still arriving. Wrapped around the
	// underlying transport error rather than replacing it, so the cause survives for a
	// reader while requestAbortCode can still classify it.
	errRequestAbandoned = errors.New("http3server: the connection ended before the request did")
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
	//
	// # What it does not bound (issue #186)
	//
	// It bounds a connection whose peer has ACKNOWLEDGED what this server sent and
	// then goes quiet — the ordinary idle client. It does NOT bound one that leaves
	// something of this server's unacknowledged, because while a packet is in flight
	// the idle deadline is unreachable, not merely late.
	//
	// RFC 9000 §10.1 requires that "endpoints MUST increase the idle timeout period
	// to be at least three times the current Probe Timeout", and RFC 9002 §6.2.1
	// doubles that PTO on every expiry. The transport re-evaluates the deadline as
	// lastActivity+3*PTO on each probe, so at the k'th probe it sits 3*base*2^k
	// ahead of a clock that has only reached base*(2^k - 1): it recedes about twice
	// as fast as time passes and is never met. What ends the connection instead is
	// the transport abandoning its probe ladder after maxPTOBackoff=8 doublings, at
	// base*(2^9 - 1) — a poseidon-http-client constant, not a function of this field.
	//
	// Measured on loopback (http3server/idleprobe_manual_test.go, `-tags idleprobe`),
	// against a peer that completes the handshake and stops reading its socket, so
	// this server's HANDSHAKE_DONE and control-stream SETTINGS stay unacknowledged:
	//
	//	IdleTimeout:   1s        30s       600s      none (<0)
	//	held:          340.33s   340.33s   340.34s   340.34s
	//
	// All four identical to 10ms, and all ending in a read timeout rather than
	// quic.ErrIdleTimeout — the idle timer never fired. The last column is what
	// settles it: with no max_idle_timeout in effect there is no deadline to floor,
	// so anything blamed on the floor predicts no bound at all there, and the hold
	// is unchanged. Control connections whose peer acknowledged the opening flight
	// and then went quiet closed at 1.00s with quic.ErrIdleTimeout.
	//
	// 340.33s is 511*666ms: a server-role quic.Conn is built with no RTT sample
	// (quic/server.go NewServerConn), so its base PTO is the 2*kInitialRtt fallback.
	// The same ladder governs ordinary traffic at a realistic base: a peer that
	// sends one request and then stops reading held a 1s-IdleTimeout connection for
	// 17.32s. So the overrun is not confined to a pathological peer, and it is not
	// a multiple of the configured value — it is unrelated to it.
	//
	// This is the transport's to fix and is filed as poseidon-http-client#798; RFC
	// 9002 §6.2.1 says the relationship should run the other way — "The total length
	// of time over which consecutive PTOs expire is limited by the idle timeout."
	// A deadline invented in this package could not stand in for it: quic.Conn
	// exposes no last-activity accessor, and Poll returns nil on a probe expiry
	// exactly as it does on a received datagram (quic/conn_recv.go handleExpiry ends
	// in flush), so this package cannot tell an idle connection from a busy one. Any
	// timer it added would be a blind connection-lifetime cap that reaped healthy
	// long-lived requests too — which is why #143's own timer was rejected. Until
	// the transport lands the bound, front an internet-facing deployment with a rate
	// limiter, as the package doc already advises.
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
//
// That floor turned out to bind far harder than "cannot close too early": while
// anything is unacknowledged it outruns the clock and the idle timeout cannot close
// the connection at all. See Server.IdleTimeout and issue #186 — it is why the 1ms
// clamp is the least interesting thing about a small IdleTimeout.
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
		if errors.Is(err, errRequestTooLarge) {
			// Answered rather than aborted: see refuseOversizeRequest (issue #179).
			s.refuseOversizeRequest(rs, cs)
			return
		}
		_ = rs.Reset(requestAbortCode(err))
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
		_ = rs.Reset(requestAbortCode(err))
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

// requestAbortCode is the RFC 9114 error code a request stream is aborted with when
// err ended it before a handler could answer. Three conditions, three codes, and
// before issue #180 all three were sent as H3_REQUEST_CANCELLED or H3_MESSAGE_ERROR:
//
//   - The stream ended without a fully formed request — the peer reset it mid-message,
//     or it carried no HEADERS frame at all. §4.1: "If a client-initiated stream
//     terminates without enough of the HTTP message to provide a complete response,
//     the server SHOULD abort its response stream with the error code
//     H3_REQUEST_INCOMPLETE." §8.1 defines that code as "The client's stream
//     terminated without containing a fully formed request".
//   - The server gave up on it: the connection's context was cancelled, or the
//     transport ended the connection. §4.1.1: "When the server cancels a request
//     without performing any application processing, the request is considered
//     'rejected'. The server SHOULD abort its response stream with the error code
//     H3_REQUEST_REJECTED." No processing happened — §4.1.1 defines "processed" as
//     "some data from the stream was passed to some higher layer of software that
//     might have taken some action as a result", and the handler has not been reached
//     at either call site. That also earns the peer the retry licence the next
//     sentence grants: "The client can treat requests rejected by the server as though
//     they had never been sent at all, thereby allowing them to be retried later."
//     H3_REQUEST_CANCELLED, sent here before, is scoped by the sentence after that to
//     the opposite case: "When a server abandons a response after partial processing".
//   - Anything else reaching here is a message the decoder understood and refused —
//     a bad field section or an illegal pseudo-header. §4.1.2: "Malformed requests or
//     responses that are detected MUST be treated as a stream error of type
//     H3_MESSAGE_ERROR."
//
// errRequestTooLarge is deliberately not a case: that request is answered with a 413
// rather than aborted (refuseOversizeRequest), so a code for it here would name a
// RESET_STREAM that is never sent. serveRequest handles it before calling this.
//
// Pure, so the mapping is pinned by a unit test rather than by four live connections.
func requestAbortCode(err error) uint64 {
	switch {
	case errors.Is(err, errRequestIncomplete):
		return h3RequestIncomplete
	case errors.Is(err, errRequestAbandoned):
		return http3.H3RequestRejected
	default:
		return http3.H3MessageError
	}
}

// refuseOversizeRequest answers a request that outgrew maxRequestBytes instead of
// abandoning it (issue #179).
//
// # What went wrong before
//
// The oversize branch used to do one thing: rs.Reset. A RESET_STREAM aborts the
// SERVER's send direction (RFC 9000 §3.2) and says nothing to the peer's send
// direction, so the client kept writing. Meanwhile nothing called rs.Recv again, and
// consuming received bytes is the only thing that grants receive-flow-control credit
// (quic/stream.go recvLocked → onStreamConsumed), so the client ran out of credit and
// parked in WaitSendable. The reset did wake it — the transport signals the stream on
// receipt — but quic.Stream.Send returns ErrStreamReset only for the LOCAL send side,
// which a peer's RESET_STREAM does not touch, so the woken sender re-checked the same
// predicate and parked again. Measured: the peer's Do returned after 30.2s with "quic:
// idle timeout" and never learned the request was refused. On a peer advertising no
// max_idle_timeout, before #168, that was indefinite.
//
// STOP_SENDING is the frame that ends the peer's send direction (RFC 9000 §3.5), and
// it is what RFC 9114 §4.1 prescribes here: "When the server does not need to receive
// the remainder of the request, it MAY abort reading the request stream, send a
// complete response, and cleanly close the sending part of the stream. The error code
// H3_NO_ERROR SHOULD be used when requesting that the client stop sending on the
// request stream." The three steps below are those three, in that order.
//
// # Why a response and not a reset
//
// §4.1.1 opens with "When possible, it is RECOMMENDED that servers send an HTTP
// response with an appropriate status code rather than cancelling a request", and RFC
// 9110 §15.5.14 supplies the status: "The 413 (Content Too Large) status code
// indicates that the server is refusing to process a request because the request
// content is larger than the server is willing or able to process. The server MAY
// terminate the request, if the protocol version in use allows it" — HTTP/3 does, via
// the STOP_SENDING above. §4.1 also guarantees the response survives the abrupt end:
// "Clients MUST NOT discard complete responses as a result of having their request
// terminated abruptly."
//
// The alternatives are each wrong for a reason worth keeping:
//
//   - H3_REQUEST_REJECTED (0x010b) would be the correct code IF this cancelled the
//     request, and it is what the ctx-cancelled branch above sends. But §4.1.1's
//     retry licence — "The client can treat requests rejected by the server as though
//     they had never been sent at all, thereby allowing them to be retried later" —
//     invites the peer to resend the same oversize body forever. A 413 tells it why.
//   - H3_REQUEST_CANCELLED (0x010c), the code this branch used to send, is scoped by
//     §4.1.1 to the opposite case: "When a server abandons a response after partial
//     processing". No application processing happens here — the handler never runs.
//   - H3_EXCESSIVE_LOAD (0x0107) is a CONNECTION-scope verdict on a peer's behaviour
//     ("its peer is exhibiting a behavior that might be generating excessive load"),
//     and this package uses it that way already (control.go). One request larger than
//     one buffer is not a behaviour, and killing the connection would take every other
//     in-flight request on it with no §8.1 basis.
//
// A failure to encode or send the 413 falls back to H3_REQUEST_REJECTED: the peer
// then gets a cancellation with the code §4.1.1 gives an unprocessed request, rather
// than the silence this function exists to remove.
func (s *Server) refuseOversizeRequest(rs *quic.Stream, cs *connState) {
	// 1. Abort reading the request stream. This is the step whose absence was the bug:
	//    it is what unblocks a peer parked on flow control.
	_ = rs.StopSending(http3.H3NoError)

	// 2. Send a complete response. Built here rather than through the handler — §4.1.1
	//    counts passing "some data from the stream ... to some higher layer of software"
	//    as processing, and this request is refused before any of it is understood.
	rw := &responseWriter{header: http.Header{}, status: http.StatusRequestEntityTooLarge}
	rw.header.Set("Content-Type", "text/plain; charset=utf-8")
	rw.header.Set("Content-Length", strconv.Itoa(len(oversizeBody)))
	_, _ = rw.body.Write(oversizeBody)
	resp, err := encodeResponse(rw, cs.peerMaxFieldSection.Load())
	if err != nil {
		_ = rs.Reset(http3.H3RequestRejected)
		return
	}
	// 3. Cleanly close the sending part of the stream (the FIN).
	if _, err := rs.Send(resp, true); err != nil {
		_ = rs.Reset(http3.H3RequestRejected)
	}
}

// oversizeBody is the 413's content. Its length is what the Content-Length above
// states, so the two cannot drift: §4.1.2 makes a response whose Content-Length
// disagrees with the DATA frames malformed.
var oversizeBody = []byte("request body exceeds the server's limit\n")

// readRequestStream buffers a whole request. The connection's Poll loop feeds the
// stream; this waits on its readiness until the client signals the end with a FIN.
//
// The three ways it fails are three different verdicts to the peer (RFC 9114 §4.1,
// §4.1.1), so they are returned as three distinguishable errors rather than as one
// "it did not arrive" — see serveRequest, and issues #179 and #180.
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
			return nil, errRequestIncomplete // the peer aborted mid-message
		}
		if uint64(len(buf)) > maxRequestBytes {
			return nil, errRequestTooLarge
		}
		if finished {
			return buf, nil
		}
		if err := rs.WaitReadable(ctx); err != nil {
			// ctx cancelled, or the connection ended. Wrapped, not replaced: the code
			// this becomes is §4.1.1's H3_REQUEST_REJECTED whatever the cause, and the
			// cause is still worth carrying.
			return nil, fmt.Errorf("%w: %w", errRequestAbandoned, err)
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
	// typUnknown suppresses the type in the message. A frame whose header was
	// itself cut off has no type to name, and printing 0 there would name DATA.
	typUnknown bool
}

func (e *connFrameError) Error() string {
	if e.typUnknown {
		return "http3server: a frame " + e.why
	}
	return "http3server: frame type " + strconv.FormatUint(e.typ, 16) + " " + e.why
}

// truncatedFrame is RFC 9114 §7.1's verdict on bytes still unconsumed when the
// stream ended: "When a stream terminates cleanly, if the last frame on the
// stream was truncated, this MUST be treated as a connection error of type
// H3_FRAME_ERROR."
//
// rest is the tail the FrameReader could not turn into a frame. Its header is
// re-parsed only to name the type in the error; a header too short to parse is
// itself the truncation and simply goes unnamed.
func truncatedFrame(rest []byte) *connFrameError {
	e := &connFrameError{
		code: http3.H3FrameError,
		why:  "was truncated by the clean end of the stream (RFC 9114 §7.1)",
	}
	typ, _, _, err := http3.ParseFrameHeader(rest)
	if err != nil {
		e.typUnknown = true
		return e
	}
	e.typ = typ
	return e
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
			// ErrNeedMore is both "the buffer is spent" and "a frame is cut off",
			// and on this path the difference is the whole of RFC 9114 §7.1.
			// readRequestStream returns only once the peer sent FIN, so there is
			// never more to come: unconsumed bytes here are a truncated last
			// frame, which §7.1 makes a connection error of type H3_FRAME_ERROR.
			// Buffered() is what tells the two apart.
			//
			// Scoped to a message whose header section already arrived. A stream
			// that never produced one is #180's case, not this one — §8.1 defines
			// H3_REQUEST_INCOMPLETE as "the client's stream terminated without
			// containing a fully formed request", the stream is aborted with it
			// below, and TestDecodeRequest_NoHeadersIsIncomplete pins that. What
			// is fixed here is the case with teeth: a COMPLETE request header
			// followed by a body that was cut off was served to the handler as a
			// finished request, with the delivered bytes silently dropped and the
			// body reported as empty.
			if seen && fr.Buffered() > 0 {
				return nil, truncatedFrame(stream[len(stream)-fr.Buffered():])
			}
			break // consumed to the last octet: the message ends here
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
		// No header section arrived, so there is no message to call malformed. §4.1:
		// "If a client-initiated stream terminates without enough of the HTTP message
		// to provide a complete response, the server SHOULD abort its response stream
		// with the error code H3_REQUEST_INCOMPLETE" — §8.1 defines that code as "The
		// client's stream terminated without containing a fully formed request", which
		// is this and not §4.1.2's H3_MESSAGE_ERROR (issue #180). Every other way to
		// reach here without a HEADERS frame — DATA first, a control-stream frame — is
		// already a connection error above, so what is left is an empty stream, one
		// carrying only unknown/GREASE frames, or one cut off mid-frame.
		return nil, errRequestIncomplete
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
//
// It validates before it maps. §4.1 lists what makes a message malformed —
// "prohibited fields or pseudo-header fields, missing mandatory pseudo-header
// fields, invalid values for pseudo-header fields, pseudo-header fields after
// fields, an invalid sequence of HTTP messages, uppercase field names, [or]
// invalid characters in field names or values" — and §4.1.2 makes a detected
// malformed request a stream error of type H3_MESSAGE_ERROR, which is what
// requestAbortCode maps http3.ErrH3Message to.
//
// The checks live in internal/httpfields because they are the same checks
// RFC 9113 §8.2.1/§8.2.2/§8.3 puts on the HTTP/2 path, enforced there by
// conn/server_handler.go. Until issue #209 they were unexported inside conn/ and
// this function had none of them: an HTTP/3 request could carry
// Transfer-Encoding, a CRLF-split field value or an uppercase field name that
// the HTTP/2 front door of the same binary refuses — a smuggling and
// header-injection differential at the next HTTP/1.1 hop, not a conformance nit.
func buildRequest(fields []hpack.HeaderField, body []byte) (*http.Request, error) {
	// §4.2 — the character rules, the connection-specific-field ban
	// (Connection, Proxy-Connection, Keep-Alive, Transfer-Encoding, Upgrade) and
	// the TE-may-only-be-"trailers" rule, one pass over the section. isTrailer is
	// false: decodeRequest does not surface a trailer section to this function.
	for i := range fields {
		if httpfields.Prohibited(fields[i].Name, fields[i].Value, false) {
			return nil, http3.ErrH3Message
		}
	}
	// §4.3/§4.3.1 — pseudo-headers must be defined, unique, and ahead of every
	// regular field, and :authority carries no userinfo. The mandatory-field
	// checks below are deliberately kept as well: this helper exempts CONNECT
	// (§4.4), which this server does not implement, so dropping them would newly
	// admit a request shape that is currently refused.
	if !httpfields.ValidRequestPseudoHeaders(fields) {
		return nil, http3.ErrH3Message
	}

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
	if err := checkContentLength(header, len(body)); err != nil {
		return nil, err
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

// checkContentLength enforces RFC 9114 §4.1's content-length rule against the
// DATA that actually arrived: a message is malformed "if the value of the
// Content-Length header field does not equal the sum of the DATA frame lengths
// received".
//
// Before this the field was never read. req.ContentLength was set from the bytes
// the decoder had accumulated, so a request advertising `content-length: 100`
// and sending five was normalised into a self-consistent five-byte request that
// a handler could not tell from an honest one — while the original, disagreeing
// header stayed in req.Header for a proxying handler to forward. This server and
// any conformant intermediary in front of it would then disagree about where the
// message ends, which is the shape of a request-smuggling differential rather
// than a conformance nit.
//
// §4.1.2 makes a detected malformed request a stream error of type
// H3_MESSAGE_ERROR, which is what http3.ErrH3Message maps to in
// requestAbortCode. The connection is not at fault and survives.
func checkContentLength(header http.Header, received int) error {
	vs := header["Content-Length"]
	if len(vs) == 0 {
		return nil
	}
	// RFC 9110 §8.6 — a recipient may accept repeated Content-Length only when
	// every value is the same; differing values cannot be resolved into one
	// length, so the message is malformed rather than a matter of preference.
	for _, v := range vs[1:] {
		if v != vs[0] {
			return http3.ErrH3Message
		}
	}
	// §8.6 defines the value as 1*DIGIT. strconv alone is too permissive here —
	// it accepts a leading sign, so "+5" would pass as five and let a peer say
	// one thing to this server and another to the next hop, which is the exact
	// disagreement this function exists to prevent.
	if vs[0] == "" {
		return http3.ErrH3Message
	}
	for i := range len(vs[0]) {
		if vs[0][i] < '0' || vs[0][i] > '9' {
			return http3.ErrH3Message
		}
	}
	// 63 bits, not 64: the result is compared against an int64 length, and a
	// value that overflows into a negative would compare equal to nothing while
	// still parsing.
	declared, err := strconv.ParseUint(vs[0], 10, 63)
	if err != nil || declared != uint64(received) {
		return http3.ErrH3Message
	}
	return nil
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
		lower := lowerASCII(name) // field names are lowercase on the wire
		// RFC 9114 §4.2 and §4.3 — no connection-specific fields, and :status is
		// the only pseudo-header a response may carry. Dropped rather than
		// refused; see httpfields.ProhibitedInResponse. Without this a handler
		// setting Connection, Transfer-Encoding or a ':'-prefixed key had it
		// encoded verbatim into the field section.
		if httpfields.ProhibitedInResponse([]byte(lower)) {
			continue
		}
		for _, v := range values {
			fields = append(fields, hpack.HeaderField{
				Name:  []byte(lower),
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
	// A 1xx is not a final status (RFC 9114 §4.1), and §4.4 leaves HTTP/3 with
	// no 101 at all. Latching one here put `:status: 101` — or 100, or 103 — on
	// the wire as the whole response, with FIN, and no final response could
	// follow. Declining it lets the handler's real status land; sending interim
	// responses properly needs this writer to stop buffering the whole response
	// to the end, which is a separate change. See httpfields.InterimStatus.
	if httpfields.InterimStatus(status) {
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
