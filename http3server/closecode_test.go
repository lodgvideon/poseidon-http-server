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

// TestServer_OrdinaryTeardownIsAnApplicationClose covers part of #212 group E.
//
// serveConn tore the connection down with quic.Conn.Close, which is
// CloseWithError(false, …) — the TRANSPORT CONNECTION_CLOSE (frame 0x1c) carrying
// transport code 0x00. RFC 9114 §8 requires an endpoint to say why it closed with
// an §8.1 code, and §5.2 names the one for an ordinary teardown: "An endpoint
// that completes a graceful shutdown SHOULD use the H3_NO_ERROR error code when
// closing the connection."
//
// The difference matters to the peer rather than to a spec checklist: a transport
// close is also what it sees when the transport itself fails, so every normal
// shutdown of this server was indistinguishable from the connection dying
// underneath it.
func TestServer_OrdinaryTeardownIsAnApplicationClose(t *testing.T) {
	outer, cancelOuter := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOuter()

	// The server's own context, so cancelling it ends the connection the ordinary
	// way rather than through any error path.
	serveCtx, stopServer := context.WithCancel(outer)
	defer stopServer()

	addr, pool := serveTest(serveCtx, t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	conn := dialRawPeer(outer, t, addr, pool)

	// One real request first. Cancelling before the listener has handed the
	// connection to serveConn would stop Serve's accept loop and leave nobody to
	// close anything — a green-looking test that proved nothing about the close
	// code. A completed exchange is the proof that serveConn is running.
	cl, err := http3.NewClient(conn, nil)
	if err != nil {
		t.Fatalf("http3.NewClient: %v", err)
	}
	resp, body, err := cl.Do(outer, &http3.Request{
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
	})
	if err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	if resp.Status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("warm-up: status=%d body=%q", resp.Status, body)
	}

	stopServer()

	// Read the verdict from the peer's own view. Polling the quic.Conn directly
	// races the http3 client, which owns this connection and tears its socket down
	// as soon as it sees the CONNECTION_CLOSE — that produced "use of closed
	// network connection" rather than the code. A second request surfaces the
	// connection's terminating error instead.
	var closed *quic.PeerClosedError
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, _, err = cl.Do(outer, &http3.Request{
			Method: "GET", Scheme: "https", Authority: "example.com", Path: "/after",
		})
		if err == nil {
			if time.Now().After(deadline) {
				t.Fatal("the server kept serving after its context was cancelled")
			}
			continue
		}
		if errors.As(err, &closed) {
			break
		}
		t.Fatalf("after shutdown: Do = %v (%T), want an HTTP/3 connection error carrying "+
			"the code the server closed with", err, err)
	}

	if !closed.App {
		t.Errorf("server sent a TRANSPORT close (code %#x); §8 requires an application close "+
			"carrying an §8.1 code, or the peer cannot tell a graceful shutdown from the "+
			"transport failing underneath it", closed.Code)
	}
	if closed.Code != http3.H3NoError {
		t.Errorf("server closed with %#x, want H3_NO_ERROR %#x — §5.2: \"An endpoint that "+
			"completes a graceful shutdown SHOULD use the H3_NO_ERROR error code when "+
			"closing the connection\"", closed.Code, http3.H3NoError)
	}
}

// TestServer_ErrorCloseKeepsItsOwnCode is the control for the above. The deferred
// application close runs on every exit from serveConn, including after an error
// path already closed with its own §8.1 code — so this pins that the transport's
// first-error-wins latch holds and H3_NO_ERROR does not overwrite the real
// reason. Without it, "close with H3_NO_ERROR on the way out" would look correct
// while erasing every diagnostic this package sends.
func TestServer_ErrorCloseKeepsItsOwnCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, send := controlPeer(ctx, t)
	// A DATA frame on the control stream: §7.2.1 makes it H3_FRAME_UNEXPECTED.
	send(http3.AppendFrameHeader(nil, http3.FrameData, 0))
	wantConnClosed(ctx, t, conn, http3.H3FrameUnexpected)
}
