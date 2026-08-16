package http3server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// ---------------------------------------------------------------------------
// How a request that cannot be served ends (issues #179 and #180).
//
// RFC 9114 names a different outcome for each way a request stream can fail, and
// this server used to collapse them into two codes. The one with teeth is the
// oversize request (#179): it was aborted with a RESET_STREAM on the SERVER's send
// direction only, which RFC 9000 §3.2 scopes to that direction, so the peer went on
// sending into a server that had stopped granting it flow-control credit and learned
// nothing until the QUIC idle timeout. Measured before the fix, three runs: the
// peer's Do returned after ~30s with "quic: idle timeout" and no response. That is an
// unbounded wait a peer cannot tell from a slow server, which is a resource-exhaustion
// shape rather than a conformance nit.
// ---------------------------------------------------------------------------

// TestServer_OversizeRequestIsAnswered is #179's regression test: a request body over
// maxRequestBytes comes back as a 413, promptly, without reaching the handler.
//
// RFC 9114 §4.1: "When the server does not need to receive the remainder of the
// request, it MAY abort reading the request stream, send a complete response, and
// cleanly close the sending part of the stream. The error code H3_NO_ERROR SHOULD be
// used when requesting that the client stop sending on the request stream." RFC 9110
// §15.5.14 supplies the status: "The 413 (Content Too Large) status code indicates
// that the server is refusing to process a request because the request content is
// larger than the server is willing or able to process."
//
// The under-limit arm is the control, and it is not decoration: it runs first, on the
// SAME connection with the SAME client, so the only difference between the two arms is
// the body size. Without it a server that refused every request — or a harness that
// never connected — would pass the oversize assertion.
func TestServer_OversizeRequestIsAnswered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var handlerRuns atomic.Int64
	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRuns.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Read", strconv.FormatInt(n, 10))
		_, _ = w.Write([]byte("served"))
	}))
	conn := dialRawPeer(ctx, t, addr, pool)
	c, err := http3.NewClient(conn, nil)
	if err != nil {
		t.Fatalf("http3.NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Control arm: comfortably under maxRequestBytes.
	const underLimit = 512 << 10
	start := time.Now()
	resp, body, err := c.Do(ctx, &http3.Request{
		Method: "POST", Scheme: "https", Authority: "example.com", Path: "/under",
		Body: make([]byte, underLimit),
	})
	if err != nil {
		t.Fatalf("control arm (%d-byte body, under the %d-byte limit): Do = %v", underLimit, maxRequestBytes, err)
	}
	if resp.Status != http.StatusOK || string(body) != "served" {
		t.Fatalf("control arm: status=%d body=%q, want 200 and %q", resp.Status, body, "served")
	}
	if got := headerValue(resp.Headers, "x-read"); got != strconv.Itoa(underLimit) {
		t.Fatalf("control arm: handler read %s bytes, want %d", got, underLimit)
	}
	t.Logf("control  (%d bytes): status=%d in %v", underLimit, resp.Status, time.Since(start).Round(time.Millisecond))

	// Test arm: over maxRequestBytes.
	runsBefore := handlerRuns.Load()
	start = time.Now()
	resp, body, err = c.Do(ctx, &http3.Request{
		Method: "POST", Scheme: "https", Authority: "example.com", Path: "/over",
		Body: make([]byte, 2*maxRequestBytes),
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("oversize arm (%d-byte body): Do = %v (%T) after %v, want a 413. Before the fix this was "+
			"\"quic: idle timeout\" after ~30s: the server reset only its own send direction, which does not "+
			"stop the peer sending, and stopped granting receive credit, so the peer parked in a send until "+
			"the connection idled out (issue #179)",
			2*maxRequestBytes, err, err, elapsed.Round(time.Millisecond))
	}
	if resp.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize arm: status = %d, want %d (413 Content Too Large, RFC 9110 §15.5.14)",
			resp.Status, http.StatusRequestEntityTooLarge)
	}
	if runs := handlerRuns.Load(); runs != runsBefore {
		t.Errorf("the handler ran %d time(s) on the oversize request; §4.1.1 calls a request refused "+
			"without \"some data from the stream ... passed to some higher layer of software\" unprocessed, "+
			"and this one must never reach the handler", runs-runsBefore)
	}
	// §4.1.2 makes a response whose Content-Length disagrees with the DATA frames
	// malformed, so the refusal must not itself be one.
	if got, want := headerValue(resp.Headers, "content-length"), strconv.Itoa(len(body)); got != want {
		t.Errorf("413 content-length = %q but the body is %d bytes; §4.1.2 makes that malformed", got, len(body))
	}
	t.Logf("oversize (%d bytes): status=%d body=%q in %v", 2*maxRequestBytes, resp.Status, body,
		elapsed.Round(time.Millisecond))
}

// TestRequestAbortCode pins the §4.1 / §4.1.1 / §4.1.2 mapping (issue #180) as a pure
// function, which is both deterministic on every platform and strictly more
// discriminating than one live connection per case: every branch is reachable here,
// including the connection-ended one, which end to end races the connection teardown
// that produces it.
//
// The quoted definitions are §8.1's, written out so a wrong constant cannot make the
// test agree with the code.
func TestRequestAbortCode(t *testing.T) {
	t.Parallel()

	const (
		wireRequestRejected   uint64 = 0x010b // "A server rejected a request without performing any application processing."
		wireRequestIncomplete uint64 = 0x010d // "The client's stream terminated without containing a fully formed request."
		wireMessageError      uint64 = 0x010e // "An HTTP message was malformed and cannot be processed."
	)

	cases := []struct {
		name string
		err  error
		want uint64
	}{
		{"peer reset the stream mid-message", errRequestIncomplete, wireRequestIncomplete},
		{"stream carried no HEADERS frame", errRequestIncomplete, wireRequestIncomplete},
		{"the connection ended first", errRequestAbandoned, wireRequestRejected},
		{"the connection ended, wrapped cause", errors.Join(errRequestAbandoned, context.Canceled), wireRequestRejected},
		{"a malformed message", http3.ErrH3Message, wireMessageError},
	}
	for _, tc := range cases {
		if got := requestAbortCode(tc.err); got != tc.want {
			t.Errorf("%s: requestAbortCode(%v) = %#x, want %#x", tc.name, tc.err, got, tc.want)
		}
	}

	// The constant this package has to define itself, because the dependency's §8.1
	// table omits it. Checked against the RFC's number, not against the dependency.
	if h3RequestIncomplete != wireRequestIncomplete {
		t.Errorf("h3RequestIncomplete = %#x, want %#x (RFC 9114 §8.1)", h3RequestIncomplete, wireRequestIncomplete)
	}
	// And the two codes it must not be confused with — the ones this branch sent
	// before #180. If the dependency ever renumbers these, the table above is wrong
	// and this says so.
	if http3.H3RequestRejected != wireRequestRejected || http3.H3MessageError != wireMessageError {
		t.Errorf("dependency codes moved: H3_REQUEST_REJECTED=%#x H3_MESSAGE_ERROR=%#x, want %#x and %#x",
			http3.H3RequestRejected, http3.H3MessageError, wireRequestRejected, wireMessageError)
	}
	if http3.H3RequestCancelled == h3RequestIncomplete {
		t.Error("H3_REQUEST_CANCELLED and H3_REQUEST_INCOMPLETE are the same value; §8.1 gives them 0x010c and 0x010d")
	}
}

// TestDecodeRequest_NoHeadersIsIncomplete is the decoder half of #180: a stream that
// carried no header section is not a malformed message but an incomplete one.
//
// TestDecodeRequest_NoHeaders already pins that these are refused. This pins WHICH
// refusal, which is the whole of #180's second item — §4.1's "If a client-initiated
// stream terminates without enough of the HTTP message to provide a complete response,
// the server SHOULD abort its response stream with the error code
// H3_REQUEST_INCOMPLETE", against §4.1.2's H3_MESSAGE_ERROR for a message that exists
// and is invalid.
func TestDecodeRequest_NoHeadersIsIncomplete(t *testing.T) {
	t.Parallel()

	incomplete := map[string][]byte{
		"an empty stream":            nil,
		"only a GREASE frame":        http3.AppendFrameHeader(nil, 0x21, 0),
		"a truncated frame header":   {0x40},
		"a HEADERS frame cut short":  append(http3.AppendFrameHeader(nil, http3.FrameHeaders, 4096), encodeSection(validFields)...),
		"an unknown frame, no rules": append(http3.AppendFrameHeader(nil, 0x0e, 3), []byte("abc")...),
	}
	for name, stream := range incomplete {
		req, err := decodeRequest(stream)
		if req != nil {
			t.Errorf("%s: decodeRequest served a request", name)
			continue
		}
		if !errors.Is(err, errRequestIncomplete) {
			t.Errorf("%s: decodeRequest err = %v, want errRequestIncomplete so the stream is aborted with "+
				"H3_REQUEST_INCOMPLETE (RFC 9114 §4.1) rather than H3_MESSAGE_ERROR", name, err)
			continue
		}
		if got := requestAbortCode(err); got != h3RequestIncomplete {
			t.Errorf("%s: abort code = %#x, want %#x", name, got, h3RequestIncomplete)
		}
	}

	// The other side of the same fork: a header section that IS present and IS invalid
	// stays §4.1.2's H3_MESSAGE_ERROR. Without this, "return errRequestIncomplete for
	// every decode failure" passes the loop above.
	malformed := http3.AppendHeaders(nil, []byte{0xff, 0xff})
	req, err := decodeRequest(malformed)
	if req != nil || err == nil {
		t.Fatalf("premise: decodeRequest(garbage QPACK section) = (%v, %v), want a refusal", req, err)
	}
	if errors.Is(err, errRequestIncomplete) {
		t.Errorf("a garbage field section was reported as incomplete; §4.1.2 makes a message that is " +
			"present and invalid a stream error of type H3_MESSAGE_ERROR")
	}
	if got := requestAbortCode(err); got != http3.H3MessageError {
		t.Errorf("abort code for a garbage field section = %#x, want %#x (H3_MESSAGE_ERROR)",
			got, http3.H3MessageError)
	}
}

// wantStreamReset drives conn's Poll until the peer aborts rs and asserts the
// application error code it used (RFC 9000 §19.4, surfaced as RecvState's code).
func wantStreamReset(ctx context.Context, t *testing.T, conn *quic.Conn, rs *quic.Stream, want uint64, what string) {
	t.Helper()
	for {
		_, reset, code := rs.RecvState()
		if reset {
			if code != want {
				t.Errorf("%s: server reset the request stream with %#x, want %#x", what, code, want)
			}
			return
		}
		if err := conn.Poll(ctx); err != nil {
			t.Fatalf("%s: Poll = %v (%T) before the server reset the stream with %#x", what, err, err, want)
		}
	}
}

// TestServer_AbortsIncompleteRequestWithIncomplete is #180's end-to-end half: the code
// the peer actually observes on the two conditions §4.1 sends H3_REQUEST_INCOMPLETE
// for. A unit test on requestAbortCode cannot reach this — it pins the mapping, not
// that serveRequest reaches it with the right error, which is where both conditions
// used to be flattened into H3_REQUEST_CANCELLED and H3_MESSAGE_ERROR.
//
// A raw QUIC peer rather than the production client: the client opens a conforming
// stream and finishes its request, and the point is what a peer that does not gets
// told.
func TestServer_AbortsIncompleteRequestWithIncomplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	served := make(chan string, 4)
	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		served <- string(body)
	}))
	conn := dialRawPeer(ctx, t, addr, pool)
	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
		t.Fatalf("Send control: %v", err)
	}

	// The §8.1 wire values, written out rather than read from the production constants:
	// asserting against h3RequestIncomplete would move with it, so a wrong constant
	// would make this test agree with the bug instead of catching it.
	const (
		wireRequestIncomplete uint64 = 0x010d
		wireMessageError      uint64 = 0x010e
	)

	// 1. A stream that ends — cleanly, with a FIN — carrying no HEADERS frame at all.
	empty, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := empty.Send(nil, true); err != nil {
		t.Fatalf("Send FIN: %v", err)
	}
	wantStreamReset(ctx, t, conn, empty, wireRequestIncomplete, "a stream with no HEADERS frame")

	// 2. A stream the peer abandons part-way through the header section.
	partial, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// A HEADERS frame header declaring 4096 bytes, with far fewer sent and no FIN, so
	// the server is still waiting for the rest when the reset lands.
	if _, err := partial.Send(http3.AppendFrameHeader(nil, http3.FrameHeaders, 4096), false); err != nil {
		t.Fatalf("Send partial HEADERS: %v", err)
	}
	if err := partial.Reset(http3.H3RequestCancelled); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	wantStreamReset(ctx, t, conn, partial, wireRequestIncomplete, "a stream reset mid-message")

	// 3. The fork's other side, over the same connection: a header section that is
	// present and invalid is still §4.1.2's H3_MESSAGE_ERROR.
	bad, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := bad.Send(http3.AppendHeaders(nil, []byte{0xff, 0xff}), true); err != nil {
		t.Fatalf("Send malformed HEADERS: %v", err)
	}
	wantStreamReset(ctx, t, conn, bad, wireMessageError, "a garbage field section")

	select {
	case body := <-served:
		t.Errorf("the handler ran with body %q; none of these three streams carried a servable request", body)
	default:
	}
}

// TestServer_PeerWithNoControlStreamIsIdleClosed is the evidence for issue #143, which
// asks whether anything bounds a client that never opens its control stream.
//
// It does, and the bound is not an HTTP/3 timer: it is QUIC's max_idle_timeout, which
// #168 made this server advertise. The idle timer is armed at connection creation and
// restarted only by a received packet (RFC 9000 §10.1: "the connection is silently
// closed and its state is discarded when it remains idle for longer than the minimum
// of the max_idle_timeout value advertised by both endpoints"), and it consults no
// HTTP/3 state at all — so a peer that opens no stream of any kind is reaped exactly
// like any other idle peer, with no control-stream deadline needed.
//
// What is asserted is that serveConn RETURNS, which is the thing #143 says is
// unbounded: the goroutine, its connState and the QUIC state all go with it. The
// sibling TestServer_SilentPeerIsIdleClosed asserts the other end — the PEER's timer,
// after a conforming control stream — so neither covers this.
//
// The peer runs its QUIC transport (it polls, so it acknowledges) and opens no HTTP/3
// stream. That IS the case #143 describes, and the distinction is load-bearing: a peer
// that also stops acknowledging is not idle-closed on this timescale at all, because
// §10.1 floors the idle period at "three times the current Probe Timeout" and the
// current PTO backs off exponentially while the server's own SETTINGS sit
// unacknowledged. Measured: with the same 1s advertised here, serveConn was still
// running after 150s, and returned at 340s in a longer run. That is a transport-level
// hole rather than a control-stream one — a control-stream deadline would not close it
// either, since the same peer can open a conforming control stream and then stop
// reading — and it is filed as issue #186.
func TestServer_PeerWithNoControlStreamIsIdleClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const serverIdle = time.Second
	cert, pool := testCert(t)
	srv := &Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		IdleTimeout: serverIdle,
	}
	l, err := quic.Listen("127.0.0.1:0", srv.TLSConfig, srv.transportParams())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// serveConn rather than Serve: its return is the observation, and this package's
	// own test binary is the only place that can watch for it.
	reaped := make(chan struct{})
	go func() {
		c, aerr := l.Accept(ctx)
		if aerr != nil {
			return
		}
		srv.serveConn(ctx, c)
		close(reaped)
	}()

	// A peer that advertises no idle timeout of its own, so the only one in effect is
	// the server's (§10.1). It opens no control stream and no request stream — ever.
	conn := dialRawPeerIdle(ctx, t, l.Addr().String(), pool, 0)
	go func() {
		for conn.Poll(ctx) == nil { //nolint:revive // driving the peer's transport is the whole body
		}
	}()

	start := time.Now()
	select {
	case <-reaped:
		t.Logf("serveConn returned after %v (server advertised %v)",
			time.Since(start).Round(time.Millisecond), serverIdle)
	case <-time.After(25 * time.Second):
		t.Fatalf("serveConn still running %v after a peer completed the handshake and opened no HTTP/3 "+
			"stream at all; RFC 9000 §10.1's idle timeout is what bounds this (issue #143)", time.Since(start))
	}
}
