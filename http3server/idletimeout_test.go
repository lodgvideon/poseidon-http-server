package http3server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// ---------------------------------------------------------------------------
// max_idle_timeout (issue #168).
//
// RFC 9000 §18.2: "max_idle_timeout (0x01):  The maximum idle timeout is a value in
// milliseconds that is encoded as an integer; see (Section 10.1).  Idle timeout is
// disabled when both endpoints omit this transport parameter or specify a value of
// 0."
//
// §10.1: "If a max_idle_timeout is specified by either endpoint in its transport
// parameters (Section 18.2), the connection is silently closed and its state is
// discarded when it remains idle for longer than the minimum of the max_idle_timeout
// value advertised by both endpoints.  Each endpoint advertises a max_idle_timeout,
// but the effective value at an endpoint is computed as the minimum of the two
// advertised values (or the sole advertised value, if only one endpoint advertises a
// non-zero value)."
//
// This server advertised none, so against a peer that also advertised none there was
// no idle timeout at all and a silent peer held a serveConn goroutine, a connState
// and its QUIC state for the life of the process. RFC 9114 §5.1 puts the reaping
// expectation on exactly this mechanism — "If the QUIC connection remains idle (no
// packets received) for longer than this duration, the peer will assume that the
// connection has been closed" — and tells servers not to substitute their own
// keep-alive for it: "Servers SHOULD NOT actively keep connections open."
// ---------------------------------------------------------------------------

// advertisedIdleTimeout returns the max_idle_timeout srv puts on the wire, read back
// out of the encoded transport parameters rather than off the struct: the parameter
// is omitted entirely when the value is zero (RFC 9000 §18.2), so the encoding is
// where "advertises none" and "advertises a value" actually differ.
func advertisedIdleTimeout(t *testing.T, srv *Server) time.Duration {
	t.Helper()
	raw := quic.AppendServerTransportParams(nil, srv.transportParams(), []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	tp, err := quic.ParseTransportParams(raw)
	if err != nil {
		t.Fatalf("ParseTransportParams: %v", err)
	}
	return tp.MaxIdleTimeout
}

// TestServer_AdvertisesMaxIdleTimeout pins the parameter on the wire, which is the
// only place it exists: ServerTransportParams.MaxIdleTimeout is a uint64 of
// milliseconds and AppendServerTransportParams emits nothing when it is zero, so a
// server that leaves it unset is indistinguishable on the wire from one that has no
// opinion — which is the bug.
//
// This is a pure function of the Server value, so it is deterministic on every
// platform and strictly more discriminating than one live connection per case.
func TestServer_AdvertisesMaxIdleTimeout(t *testing.T) {
	t.Parallel()

	if got := advertisedIdleTimeout(t, &Server{}); got != defaultIdleTimeout {
		t.Errorf("a default Server advertises max_idle_timeout %v, want %v — a zero parameter is omitted "+
			"(RFC 9000 §18.2), which leaves a peer that also advertises none with no idle timeout at all",
			got, defaultIdleTimeout)
	}
	if got := advertisedIdleTimeout(t, &Server{IdleTimeout: 45 * time.Second}); got != 45*time.Second {
		t.Errorf("IdleTimeout=45s advertises %v, want 45s", got)
	}
	// A positive timeout below the parameter's millisecond resolution must not round
	// down to zero, which §18.2 reads as "no timeout" rather than "a short one".
	if got := advertisedIdleTimeout(t, &Server{IdleTimeout: 100 * time.Microsecond}); got != time.Millisecond {
		t.Errorf("IdleTimeout=100µs advertises %v, want 1ms: rounding a positive timeout down to zero "+
			"disables the idle timeout (RFC 9000 §18.2)", got)
	}
	// The documented opt-out stays available, and stays explicit.
	if got := advertisedIdleTimeout(t, &Server{IdleTimeout: -1}); got != 0 {
		t.Errorf("IdleTimeout=-1 advertises %v, want the parameter omitted", got)
	}
	// The listener ListenAndServe builds is the one under test: transportParams is
	// its only source of parameters, so this pins the production path and not a
	// parallel one.
	if got := (&Server{}).transportParams(); got.MaxStreamsBidi != maxStreamsBidi || got.MaxStreamsUni != maxStreamsUni {
		t.Errorf("transportParams dropped a stream limit: %+v", got)
	}
}

// TestServer_SilentPeerIsIdleClosed is the behavioural half: a peer that advertises
// NO max_idle_timeout, completes the handshake, opens a conforming control stream and
// then goes silent.
//
// What is asserted is the peer's own idle timer, not a frame the server sends. That
// is deliberate, and it is what RFC 9000 §10.1 promises: the effective value at an
// endpoint is the minimum of the two advertised values, so a peer that advertised
// nothing can only acquire a 1-second idle timeout from the value THIS SERVER put in
// its transport parameters. Before the fix the peer's effective timeout was zero and
// §10.1 left the idle timeout disabled, so this cannot pass by accident or by timing.
//
// The server's own close is deliberately NOT asserted: §10.1 makes it silent — "the
// connection is silently closed and its state is discarded" — so there is nothing on
// the wire to observe, and asserting one would be asserting what the RFC declines to
// promise.
func TestServer_SilentPeerIsIdleClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const serverIdle = time.Second
	addr, pool := serveTestServer(ctx, t, &Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		IdleTimeout: serverIdle,
	})
	conn := dialRawPeerIdle(ctx, t, addr, pool, 0) // the peer of #168: advertises none

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
		t.Fatalf("Send control: %v", err)
	}

	// Generous relative to serverIdle: RFC 9000 §10.1 floors the effective period at
	// three PTOs, so the close is bounded below by the server's value and above by
	// whatever loss recovery the runner's timers imply — never by 30s of nothing.
	pollCtx, pollCancel := context.WithTimeout(ctx, 25*time.Second)
	defer pollCancel()
	start := time.Now()
	for {
		err := conn.Poll(pollCtx)
		if err == nil {
			continue
		}
		if errors.Is(err, quic.ErrIdleTimeout) {
			t.Logf("idle-closed after %v of silence (server advertised %v)",
				time.Since(start).Round(time.Millisecond), serverIdle)
			return
		}
		t.Fatalf("Poll = %v (%T) after %v, want quic.ErrIdleTimeout: this peer advertised no "+
			"max_idle_timeout, so RFC 9000 §10.1 gives it one only if the server advertised one",
			err, err, time.Since(start).Round(time.Millisecond))
	}
}

// TestServer_IdleTimeoutDoesNotBreakAnExchange is the guard on the other direction.
// An idle timeout that fires during an ordinary request would be a far worse bug than
// the one it fixes, so the default server still serves a request end to end — the
// timer restarts on every packet received (§10.1), which is why a busy connection is
// never idle.
func TestServer_IdleTimeoutDoesNotBreakAnExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTestServer(ctx, t, &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("alive"))
		}),
	})
	conn := dialRawPeer(ctx, t, addr, pool)
	c, err := http3.NewClient(conn, nil)
	if err != nil {
		t.Fatalf("http3.NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	resp, body, err := c.Do(ctx, &http3.Request{
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusOK || string(body) != "alive" {
		t.Errorf("status=%d body=%q, want 200 and %q", resp.Status, body, "alive")
	}
}
