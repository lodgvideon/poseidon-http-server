package http3server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Critical streams (issue #144).
//
// These drive a REAL QUIC listener through dialRawPeer (clientsettings_test.go),
// because the production HTTP/3 client never commits the violation: it opens its
// control and QPACK streams and keeps all three open for the life of the
// connection. A test that handed the server the verdict itself would pass either
// way.
// ---------------------------------------------------------------------------

// TestServer_ClosedControlStreamIsConnectionError asserts H3_CLOSED_CRITICAL_STREAM.
// RFC 9114 §6.2.1: "The sender MUST NOT close the control stream, and the receiver
// MUST NOT request that the sender close the control stream. If either control
// stream is closed at any point, this MUST be treated as a connection error of type
// H3_CLOSED_CRITICAL_STREAM."
//
// The peer here is conforming right up to the FIN: stream type 0x00, SETTINGS as
// the first frame, then it ends the stream. So a server that reads the control
// stream but never asks whether it is still open — which is what #128 shipped —
// serves this connection normally.
func TestServer_ClosedControlStreamIsConnectionError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	frame := http3.AppendClientControlStream(nil, []http3.Setting{{ID: http3.SettingMaxFieldSectionSize, Value: 4096}})
	if _, err := ctl.Send(frame, true); err != nil { // FIN: §6.2.1 forbids this
		t.Fatalf("Send: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3ClosedCriticalStream)
}

// TestServer_ClosedQPACKStreamIsConnectionError asserts the same rule for the QPACK
// instruction streams. RFC 9204 §4.2: "The sender MUST NOT close either of these
// streams, and the receiver MUST NOT request that the sender close either of these
// streams. Closure of either unidirectional stream type MUST be treated as a
// connection error of type H3_CLOSED_CRITICAL_STREAM."
//
// The peer's conforming alternative is spelled out in the same section — "An
// endpoint MAY avoid creating an encoder stream if it will not be used" — so
// opening one and then closing it is a choice, not a necessity, and this server
// advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY=0 precisely so a peer can take it.
func TestServer_ClosedQPACKStreamIsConnectionError(t *testing.T) {
	for name, typ := range map[string]uint64{
		"encoder": http3.StreamTypeQPACKEncoder,
		"decoder": http3.StreamTypeQPACKDecoder,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			conn := dialRawPeer(ctx, t, addr, pool)

			s, err := conn.OpenUniStream()
			if err != nil {
				t.Fatalf("OpenUniStream: %v", err)
			}
			if _, err := s.Send(http3.AppendClientQPACKStream(nil, typ), true); err != nil { // FIN
				t.Fatalf("Send: %v", err)
			}

			wantConnClosed(ctx, t, conn, http3.H3ClosedCriticalStream)
		})
	}
}

// TestServer_ConformingPeerSurvivesRepeatedServicing is the regression guard the
// #144 ticket asked for, in the only form a peer can actually observe. A critical
// stream that is merely OPEN and idle must never trip the check, and the check runs
// on every servicing pass — so a wrong reading of "closed" (treating an empty Recv
// as end-of-stream, say) would kill every conforming connection on its second pass.
//
// The peer is the production client, which opens a control stream and both QPACK
// streams and keeps all three open. Two requests separated by an idle gap force
// many servicing passes between them; both must be answered on the same connection.
//
// What this deliberately does NOT assert: that the server tolerates the client's
// own Close(). That close is a QUIC CONNECTION_CLOSE, not a FIN on any stream, and
// once it is sent the peer has no way to observe what the server concluded — the
// same class of unobservable assertion that failed #128's CI.
func TestServer_ConformingPeerSurvivesRepeatedServicing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := dialWithSettings(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), []http3.Setting{{ID: http3.SettingMaxFieldSectionSize, Value: maxFieldSection}})

	for i := range 2 {
		if i > 0 {
			time.Sleep(200 * time.Millisecond) // idle: many servicing passes with no new bytes
		}
		resp, body, err := c.Do(ctx, &http3.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"})
		if err != nil {
			t.Fatalf("request %d: Do = %v, want the connection still serving: the peer's control and "+
				"QPACK streams are open, so no critical stream has been closed", i, err)
		}
		if resp.Status != http.StatusOK || string(body) != "ok" {
			t.Fatalf("request %d: status=%d body=%q, want 200 %q", i, resp.Status, body, "ok")
		}
	}
}
