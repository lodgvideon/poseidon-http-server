package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

func oneSetting(id frame.SettingID, value uint32) frame.SettingsParams {
	var sp frame.SettingsParams
	sp.Pairs[0] = frame.SettingPair{ID: id, Value: value}
	sp.N = 1
	return sp
}

// --- inbound SETTINGS validation (RFC 9113 §6.5.2) ---

func TestServerConn_Settings_BadEnablePush_ProtocolError(t *testing.T) {
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		_ = cliFr.WriteSettings(oneSetting(frame.SettingEnablePush, 2)) // must be 0 or 1
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR for SETTINGS_ENABLE_PUSH=2", code)
	}
}

func TestServerConn_Settings_InitialWindowOverflow_FlowControlError(t *testing.T) {
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		_ = cliFr.WriteSettings(oneSetting(frame.SettingInitialWindowSize, 0x80000000)) // > 2^31-1
	})
	if code != frame.ErrCodeFlowControlError {
		t.Fatalf("GOAWAY code = %v, want FLOW_CONTROL_ERROR for INITIAL_WINDOW_SIZE overflow", code)
	}
}

func TestServerConn_Settings_BadMaxFrameSize_ProtocolError(t *testing.T) {
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		_ = cliFr.WriteSettings(oneSetting(frame.SettingMaxFrameSize, 1024)) // < 16384
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR for MAX_FRAME_SIZE=1024", code)
	}
}

// --- inbound client stream-ID validation (RFC 9113 §5.1.1) ---

func vHeaders() []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
	}
}

func TestServerConn_StreamID_Even_ProtocolError(t *testing.T) {
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 2, vHeaders(), true) // even client stream ID is illegal
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR for even stream ID", code)
	}
}

func TestServerConn_StreamID_Decreasing_ProtocolError(t *testing.T) {
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 3, vHeaders(), true) // ok: 3 > 0
		sendReq(t, cliFr, 1, vHeaders(), true) // illegal: 1 <= 3 (idle-stream reuse)
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR for decreasing stream ID", code)
	}
}
