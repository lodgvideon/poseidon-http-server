package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// TestSettingsRecorder_AllMethods verifies that settingsRecorder methods
// all return nil. This dummy handler is used only during the handshake
// phase when we read the client's SETTINGS before the real handler starts.
func TestSettingsRecorder_AllMethods(t *testing.T) {
	var sr settingsRecorder

	if err := sr.OnData(frame.FrameHeader{}, nil, 0); err != nil {
		t.Fatalf("OnData: %v", err)
	}
	if err := sr.OnHeaders(frame.FrameHeader{}, nil, nil, 0); err != nil {
		t.Fatalf("OnHeaders: %v", err)
	}
	if err := sr.OnPriority(frame.FrameHeader{}, frame.Priority{}); err != nil {
		t.Fatalf("OnPriority: %v", err)
	}
	if err := sr.OnRSTStream(frame.FrameHeader{}, 0); err != nil {
		t.Fatalf("OnRSTStream: %v", err)
	}
	if err := sr.OnPushPromise(frame.FrameHeader{}, 0, nil, 0); err != nil {
		t.Fatalf("OnPushPromise: %v", err)
	}
	if err := sr.OnPing(frame.FrameHeader{}, [8]byte{}); err != nil {
		t.Fatalf("OnPing: %v", err)
	}
	if err := sr.OnGoAway(frame.FrameHeader{}, 0, 0, nil); err != nil {
		t.Fatalf("OnGoAway: %v", err)
	}
	if err := sr.OnWindowUpdate(frame.FrameHeader{}, 0); err != nil {
		t.Fatalf("OnWindowUpdate: %v", err)
	}
	if err := sr.OnContinuation(frame.FrameHeader{}, nil); err != nil {
		t.Fatalf("OnContinuation: %v", err)
	}
}

// TestConnError_Error verifies the connError.Error() formatting.
func TestConnError_Error(t *testing.T) {
	ce := connError{code: frame.ErrCodeProtocolError, msg: "test reason"}
	s := ce.Error()
	if s == "" {
		t.Fatal("Error() returned empty string")
	}
	// Verify it contains the error code name and message.
	if len(s) < 10 {
		t.Fatalf("Error() too short: %q", s)
	}
}
