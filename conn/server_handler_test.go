package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// --- Direct handler method tests for uncovered paths ---

func TestServerConnHandler_OnPriority(t *testing.T) {
	h := &serverConnHandler{
		streams: &streamRegistry{m: make(map[uint32]*ServerStream)},
		dec:     hpack.NewDecoder(),
	}
	// OnPriority should be a no-op for servers.
	err := h.OnPriority(frame.FrameHeader{StreamID: 1}, frame.Priority{})
	if err != nil {
		t.Fatalf("OnPriority: %v", err)
	}
}

func TestServerConnHandler_OnPushPromise(t *testing.T) {
	h := &serverConnHandler{
		streams: &streamRegistry{m: make(map[uint32]*ServerStream)},
		dec:     hpack.NewDecoder(),
	}
	// Server receiving PUSH_PROMISE is a protocol error.
	err := h.OnPushPromise(frame.FrameHeader{StreamID: 1}, 3, nil, 0)
	if err == nil {
		t.Fatal("OnPushPromise should return error (protocol violation)")
	}
}

func TestServerConnHandler_OnGoAway(t *testing.T) {
	h := &serverConnHandler{
		streams: &streamRegistry{m: make(map[uint32]*ServerStream)},
		dec:     hpack.NewDecoder(),
	}
	// Server receiving GOAWAY — graceful shutdown signal from client.
	err := h.OnGoAway(frame.FrameHeader{}, 0, frame.ErrCodeNoError, nil)
	if err != nil {
		t.Fatalf("OnGoAway: %v", err)
	}
}

func TestStreamRegistry_LookupMiss(t *testing.T) {
	r := &streamRegistry{m: make(map[uint32]*ServerStream)}
	s := r.lookupStream(99)
	if s != nil {
		t.Fatal("expected nil for unregistered stream")
	}
}

func TestStreamRegistry_Remove(t *testing.T) {
	r := &streamRegistry{m: make(map[uint32]*ServerStream)}
	s := newServerStream(1, 8, nil, 65535)
	r.registerStream(1, s)
	r.removeStream(1)
	if r.lookupStream(1) != nil {
		t.Fatal("expected nil after remove")
	}
}
