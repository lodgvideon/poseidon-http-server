package integration

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// TestE2E_HandlerPanic_IsolatedAndServerSurvives verifies per-request panic
// isolation: a handler that panics must NOT crash the server process. The
// panicking request fails (500 or a stream reset), but the server keeps
// serving subsequent requests — mirroring net/http's per-request recovery.
func TestE2E_HandlerPanic_IsolatedAndServerSurvives(t *testing.T) {
	ts := startTestServer(t, server.HandlerFunc(func(_ context.Context, req *server.Request, w server.ResponseWriter) error {
		if req.Path == "/panic" {
			panic("boom: handler panic under test")
		}
		_ = w.WriteHeaders(http.StatusOK, nil)
		_, _ = w.Write([]byte("ok"))
		return nil
	}))

	// 1) The panicking request must not hang or crash the server. The client
	//    either gets a 500 (panic before any write) or a stream/transport
	//    error — both acceptable; the only unacceptable outcome is the whole
	//    server going down (proven by step 2).
	if resp, err := ts.client.Get(ts.URL() + "/panic"); err == nil {
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("panic request status = %d, want 500 (or a transport error)", resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// 2) The server must still serve a normal request afterwards.
	resp, err := ts.client.Get(ts.URL() + "/ok")
	if err != nil {
		t.Fatalf("server did not survive handler panic — follow-up request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("follow-up status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("follow-up body = %q, want %q", body, "ok")
	}
}
