package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// TestE2E_HandlerContext_CancelledOnClientReset verifies that the handler's
// context is cancelled when the client resets the stream (here, by cancelling
// its request, which makes the HTTP/2 transport send RST_STREAM). Before the
// ctx-threading fix the handler ran on a context that was never cancelled by a
// client reset, so a handler blocked on slow work could not abort.
func TestE2E_HandlerContext_CancelledOnClientReset(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})

	ts := startTestServer(t, server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		if req.Path != "/slow" {
			_ = w.WriteHeaders(http.StatusOK, nil)
			return nil
		}
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled) // the fix: client reset cancels the handler ctx
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil // fix absent: ctx never fires, handler runs to timeout
		}
	}))

	reqCtx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, ts.URL()+"/slow", http.NoBody)
	go func() {
		if resp, err := ts.client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}

	// Cancel the client request → HTTP/2 transport sends RST_STREAM.
	cancel()

	select {
	case <-cancelled:
		// handler context fired — ctx threading works
	case <-time.After(3 * time.Second):
		t.Fatal("handler context was NOT cancelled after the client reset the stream")
	}
}

// TestE2E_HandlerContext_CancelledOnServerClose verifies the connection-context
// path: closing the server cancels in-flight handler contexts (connCtx ->
// per-stream ctx), so handlers drain promptly on shutdown.
func TestE2E_HandlerContext_CancelledOnServerClose(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})

	ts := startTestServer(t, server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		if req.Path != "/slow" {
			_ = w.WriteHeaders(http.StatusOK, nil)
			return nil
		}
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	}))

	go func() {
		if resp, err := ts.client.Get(ts.URL() + "/slow"); err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}

	_ = ts.poseidon.Close() // close the server → connCtx cancels in-flight handlers

	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("handler context was NOT cancelled after the server closed")
	}
}
