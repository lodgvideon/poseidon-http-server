package integration

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// TestShutdown_NoWaitGroupRace_UnderConcurrentLoad stresses the graceful-drain
// window: many streams are in flight (some buffered in the accept channel, not
// yet dispatched) when Shutdown runs. The inFlight WaitGroup's Add — now in the
// accept path under s.mu — must be synchronized with Shutdown's Wait (Shutdown
// sets s.shutdown/s.closed under the same lock before waiting), or an Add racing
// the returning Wait panics ("WaitGroup is reused before previous Wait has
// returned"). The `-race` build in CI flags the concurrent Add/Wait directly.
func TestShutdown_NoWaitGroupRace_UnderConcurrentLoad(t *testing.T) {
	ts := startTestServer(t, server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		time.Sleep(5 * time.Millisecond) // keep streams in flight across the drain
		_ = w.WriteHeaders(200, nil)
		_, _ = w.Write([]byte("ok"))
		return nil
	}))

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := ts.client.Get(ts.URL() + "/"); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}

	// Begin graceful shutdown while requests are still arriving / in flight.
	time.Sleep(2 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A clean drain returns nil; a deadline under heavy load is acceptable. The
	// assertion is simply that Shutdown does not panic on a WaitGroup misuse.
	if err := ts.poseidon.Shutdown(ctx); err != nil {
		t.Logf("Shutdown returned: %v", err)
	}
	wg.Wait()
}
