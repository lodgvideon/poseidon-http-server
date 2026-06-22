package grpcserver

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestHealthServer_Status(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()

	// Unknown service → ServiceUnknown.
	if got := h.Status("foo"); got != ServingStatusServiceUnknown {
		t.Fatalf("unknown service = %v, want %v", got, ServingStatusServiceUnknown)
	}

	// Set and get.
	h.SetServingStatus("foo", ServingStatusServing)
	if got := h.Status("foo"); got != ServingStatusServing {
		t.Fatalf("after SetServingStatus = %v, want %v", got, ServingStatusServing)
	}

	// Update.
	h.SetServingStatus("foo", ServingStatusNotServing)
	if got := h.Status("foo"); got != ServingStatusNotServing {
		t.Fatalf("after update = %v, want %v", got, ServingStatusNotServing)
	}
}

func TestHealthServer_Shutdown(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	h.SetServingStatus("svc1", ServingStatusServing)
	h.SetServingStatus("svc2", ServingStatusServing)

	h.Shutdown()

	if got := h.Status("svc1"); got != ServingStatusNotServing {
		t.Fatalf("svc1 after Shutdown = %v, want %v", got, ServingStatusNotServing)
	}
	if got := h.Status("svc2"); got != ServingStatusNotServing {
		t.Fatalf("svc2 after Shutdown = %v, want %v", got, ServingStatusNotServing)
	}
}

func TestHealthServer_WatchReceivesUpdates(t *testing.T) {
	h := NewHealthServer()
	h.SetServingStatus("svc1", ServingStatusUnknown)

	// Subscribe.
	ch := h.subscribe("svc1")
	defer h.unsubscribe("svc1", ch)

	// Push update.
	h.SetServingStatus("svc1", ServingStatusServing)

	select {
	case s := <-ch:
		if s != ServingStatusServing {
			t.Fatalf("watcher got %v, want %v", s, ServingStatusServing)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not receive update")
	}
}

func TestEncodeHealthCheckResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status ServingStatus
		want   []byte
	}{
		{"unknown", ServingStatusUnknown, []byte{0x08, 0x00}},
		{"serving", ServingStatusServing, []byte{0x08, 0x01}},
		{"not_serving", ServingStatusNotServing, []byte{0x08, 0x02}},
		{"service_unknown", ServingStatusServiceUnknown, []byte{0x08, 0x03}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := encodeHealthCheckResponse(tt.status)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("byte[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDecodeHealthCheckRequest(t *testing.T) {
	t.Parallel()

	// Encode "my.Svc" as field 1, length-delimited.
	// tag = (1 << 3) | 2 = 0x0a
	// length = 6
	service := "my.Svc"
	data := []byte{0x0a, byte(len(service))}
	data = append(data, service...)

	got := decodeHealthCheckRequest(data)
	if got != service {
		t.Fatalf("decodeHealthCheckRequest = %q, want %q", got, service)
	}

	// Empty payload → empty string.
	if got := decodeHealthCheckRequest(nil); got != "" {
		t.Fatalf("nil payload = %q, want empty", got)
	}
}

func TestHealthServer_RegisterHealthService(t *testing.T) {
	r := NewServiceRegistrar()
	h := NewHealthServer()
	h.SetServingStatus("test.Service", ServingStatusServing)
	h.RegisterHealthService(r)

	// Verify the health service is registered.
	r.mu.RLock()
	_, checkRegistered := r.methods[healthPathCheck]
	_, watchRegistered := r.methods[healthPathWatch]
	r.mu.RUnlock()

	if !checkRegistered {
		t.Fatal("Check method not registered")
	}
	if !watchRegistered {
		t.Fatal("Watch method not registered")
	}
}

func TestHealthServer_WatchHandler(t *testing.T) {
	h := NewHealthServer()
	h.SetServingStatus("svc1", ServingStatusServing)

	// Drive the REAL registered Watch server-stream handler (not an inline copy
	// that could drift from production), so this test actually exercises the
	// subscribe-before-send ordering.
	r := NewServiceRegistrar()
	h.RegisterHealthService(r)
	watch := r.methods[healthPathWatch].serverS
	if watch == nil {
		t.Fatal("Watch server-stream handler not registered")
	}

	received := make(chan ServingStatus, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = watch(ctx, encodeHealthCheckRequest("svc1"), func(data []byte) error {
			received <- ServingStatus(data[1])
			return nil
		})
	}()

	// Wait for the initial status.
	select {
	case s := <-received:
		if s != ServingStatusServing {
			t.Fatalf("initial watch status = %v, want %v", s, ServingStatusServing)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not receive initial status")
	}

	// An update pushed AFTER the stream reported its initial status must be
	// delivered. Because the handler subscribes BEFORE sending the initial
	// status, this update cannot be lost — which makes the test deterministic
	// (the old send-then-subscribe order dropped it under load, hanging here for
	// the full timeout).
	h.SetServingStatus("svc1", ServingStatusNotServing)

	select {
	case s := <-received:
		if s != ServingStatusNotServing {
			t.Fatalf("update watch status = %v, want %v", s, ServingStatusNotServing)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not receive update")
	}
}

// ---------------------------------------------------------------------------
// HealthServer via the registered Handler (Batch 5 of coverage push)
// ---------------------------------------------------------------------------

// TestHealthServer_CheckHandler_KnownService drives the registered Check
// unary handler for a known service and verifies the response.
func TestHealthServer_CheckHandler_KnownService(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	h.SetServingStatus("svc.known", ServingStatusServing)
	r := NewServiceRegistrar()
	h.RegisterHealthService(r)

	handler, ok := r.methods[healthPathCheck]
	if !ok {
		t.Fatal("Check handler not registered")
	}

	resp, err := handler.unary(context.Background(), encodeHealthCheckRequest("svc.known"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(resp) != 2 || resp[0] != 0x08 || resp[1] != byte(ServingStatusServing) {
		t.Errorf("Check response = % x, want 0x08 0x01", resp)
	}
}

// TestHealthServer_CheckHandler_UnknownService checks that an unknown
// service returns ServingStatusServiceUnknown (the only way to hit this
// branch from outside).
func TestHealthServer_CheckHandler_UnknownService(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	r := NewServiceRegistrar()
	h.RegisterHealthService(r)

	handler := r.methods[healthPathCheck]
	resp, err := handler.unary(context.Background(), encodeHealthCheckRequest("svc.unknown"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(resp) != 2 || resp[0] != 0x08 || resp[1] != byte(ServingStatusServiceUnknown) {
		t.Errorf("Check(unknown) = % x, want 0x08 0x03", resp)
	}
}

// TestHealthServer_Watch_BufferFull exercises the non-blocking send
// branch (health.go:74-80). The watcher channel has buffer 4; calling
// SetServingStatus 5+ times in a row fills it, the 5th call hits the
// `default:` case, and SetServingStatus must NOT block.
func TestHealthServer_Watch_BufferFull(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	// Subscribe first so the watcher is registered.
	ch := h.subscribe("svc.full")

	// Pre-fill the buffer (capacity 4) with 4 status updates.
	for range 4 {
		h.SetServingStatus("svc.full", ServingStatusServing)
	}

	// Channel is now full. The 5th SetServingStatus must not block —
	// it hits the `default:` branch and returns immediately. We use
	// a timer to assert it returns within a reasonable bound.
	done := make(chan struct{})
	go func() {
		h.SetServingStatus("svc.full", ServingStatusNotServing)
		close(done)
	}()
	select {
	case <-done:
		// Expected: non-blocking send dropped the update.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SetServingStatus blocked despite full watcher channel")
	}

	// Drain one item from the buffer to confirm it has at least the
	// expected 4 capacity-fill items.
	select {
	case <-ch:
		// good
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected at least one buffered status")
	}
}

// TestHealthServer_UnsubscribeCleanup verifies that unsubscribe removes
// the watcher channel from the registry and closes it.
func TestHealthServer_UnsubscribeCleanup(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	ch := h.subscribe("svc.unsub")
	if got := len(h.watchers["svc.unsub"]); got != 1 {
		t.Fatalf("watchers len = %d, want 1", got)
	}

	h.unsubscribe("svc.unsub", ch)

	h.mu.RLock()
	defer h.mu.RUnlock()
	if got := len(h.watchers["svc.unsub"]); got != 0 {
		t.Errorf("watchers len after unsubscribe = %d, want 0", got)
	}
	// The channel should be closed (a read returns the zero value).
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("unsubscribed channel still has a value")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("unsubscribed channel not closed")
	}
}

// TestHealthServer_UnsubscribeUnknownChannel is a no-op safety check:
// unsubscribing a channel that was never subscribed should not panic.
func TestHealthServer_UnsubscribeUnknownChannel(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	other := make(chan ServingStatus, 1)
	h.unsubscribe("svc.nothing", other) // should be a safe no-op
}

// TestHealthServer_ConcurrentSetAndUnsubscribe stresses the watcher fan-out
// against concurrent subscribe/unsubscribe to guard the "send on closed
// channel" panic: SetServingStatus must notify watchers under the same lock
// unsubscribe uses to close their channels, so a Watch client that churns
// subscriptions while statuses change cannot crash the server. Without that
// discipline this test panics within milliseconds (run it under -race in CI).
func TestHealthServer_ConcurrentSetAndUnsubscribe(t *testing.T) {
	t.Parallel()

	h := NewHealthServer()
	const svc = "race.svc"
	const iters = 10_000

	var wg sync.WaitGroup
	// Status setters fanning out to whatever watchers are currently registered.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				h.SetServingStatus(svc, ServingStatusNotServing)
				h.SetServingStatus(svc, ServingStatusServing)
			}
		}()
	}
	// Watchers churning subscribe -> unsubscribe (which closes the channel).
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				ch := h.subscribe(svc)
				h.unsubscribe(svc, ch)
			}
		}()
	}
	wg.Wait()
	// Reaching here without a panic is the assertion.
}
