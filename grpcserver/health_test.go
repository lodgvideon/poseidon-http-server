package grpcserver

import (
	"context"
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
	case <-time.After(time.Second):
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

	// Test the Watch server-streaming handler directly.
	received := make(chan ServingStatus, 4)
	reqPayload := encodeHealthCheckRequest("svc1")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handler := func(_ context.Context, req []byte, send func([]byte) error) error {
		serviceName := decodeHealthCheckRequest(req)

		// Send initial status.
		status := h.Status(serviceName)
		if err := send(encodeHealthCheckResponse(status)); err != nil {
			return err
		}

		// Subscribe to updates.
		ch := h.subscribe(serviceName)
		defer h.unsubscribe(serviceName, ch)

		for {
			select {
			case <-ctx.Done():
				return nil
			case s, ok := <-ch:
				if !ok {
					return nil
				}
				if err := send(encodeHealthCheckResponse(s)); err != nil {
					return err
				}
			}
		}
	}

	go func() {
		handler(ctx, reqPayload, func(data []byte) error {
			status := ServingStatus(data[1])
			received <- status
			return nil
		})
	}()

	// Wait for initial status.
	select {
	case s := <-received:
		if s != ServingStatusServing {
			t.Fatalf("initial watch status = %v, want %v", s, ServingStatusServing)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not receive initial status")
	}

	// Push an update.
	h.SetServingStatus("svc1", ServingStatusNotServing)

	select {
	case s := <-received:
		if s != ServingStatusNotServing {
			t.Fatalf("update watch status = %v, want %v", s, ServingStatusNotServing)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not receive update")
	}
}
