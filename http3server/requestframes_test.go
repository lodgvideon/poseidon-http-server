package http3server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Request-stream frame legality (issue #145).
//
// The production HTTP/3 client puts only HEADERS and DATA on a request stream, so
// the end-to-end test here drives a REAL QUIC listener through dialRawPeer
// (clientsettings_test.go) and hand-rolls the offending stream.
// ---------------------------------------------------------------------------

// pushPromiseFrame returns a PUSH_PROMISE frame carrying push ID 0 and an empty
// field section. http3 has no Append helper for it — a client has no legitimate
// reason to build one — so it is assembled from the frame header here.
func pushPromiseFrame() []byte {
	return append(http3.AppendFrameHeader(nil, http3.FramePushPromise, 1), 0x00)
}

// TestDecodeRequest_ControlFramesAreConnectionErrors pins the frame-legality switch
// on a request stream. Each of these frame types names H3_FRAME_UNEXPECTED in RFC
// 9114 by itself:
//
//   - SETTINGS, §7.2.4: "SETTINGS frames MUST NOT be sent on any stream other than
//     the control stream. If an endpoint receives a SETTINGS frame on a different
//     stream, the endpoint MUST respond with a connection error of type
//     H3_FRAME_UNEXPECTED."
//   - CANCEL_PUSH, §7.2.3: "Receiving a CANCEL_PUSH frame on a stream other than
//     the control stream MUST be treated as a connection error of type
//     H3_FRAME_UNEXPECTED."
//   - MAX_PUSH_ID, §7.2.7: "Receipt of a MAX_PUSH_ID frame on any other stream MUST
//     be treated as a connection error of type H3_FRAME_UNEXPECTED."
//   - PUSH_PROMISE, §7.2.5: "A client MUST NOT send a PUSH_PROMISE frame. A server
//     MUST treat the receipt of a PUSH_PROMISE frame as a connection error of type
//     H3_FRAME_UNEXPECTED."
//   - 0x02/0x06/0x08/0x09, §7.2.8: the HTTP/2-carryover types (§11.2.1 Table 2
//     registers each as "Reserved") — "These frame types MUST NOT be sent, and
//     their receipt MUST be treated as a connection error of type
//     H3_FRAME_UNEXPECTED."
//
// This is a unit test on the pure decoder for the same reason
// TestEncodeResponse_MeasuresFieldSectionUncompressed is one: the categorisation is
// a pure function of the frame type, so testing it as one is deterministic on every
// platform AND strictly more discriminating than one live connection per case would
// be. TestServer_SettingsOnRequestStreamClosesConnection covers the other half —
// that the verdict actually reaches the connection.
func TestDecodeRequest_ControlFramesAreConnectionErrors(t *testing.T) {
	t.Parallel()

	headers := http3.AppendHeaders(nil, encodeSection(validFields))
	illegal := map[string][]byte{
		"SETTINGS":      http3.AppendSettings(nil, nil),
		"CANCEL_PUSH":   http3.AppendCancelPush(nil, 0),
		"MAX_PUSH_ID":   http3.AppendMaxPushID(nil, 0),
		"PUSH_PROMISE":  pushPromiseFrame(),
		"reserved 0x02": http3.AppendFrameHeader(nil, 0x02, 0),
		"reserved 0x06": http3.AppendFrameHeader(nil, 0x06, 0),
		"reserved 0x08": http3.AppendFrameHeader(nil, 0x08, 0),
		"reserved 0x09": http3.AppendFrameHeader(nil, 0x09, 0),
	}
	for name, frame := range illegal {
		// After a valid HEADERS frame, so the failure cannot be the request being
		// unroutable — the request is complete and the offending frame follows it.
		stream := append(append([]byte(nil), headers...), frame...)
		req, err := decodeRequest(stream)
		if req != nil {
			t.Errorf("%s on a request stream: decodeRequest returned a request; §7.2 makes this frame "+
				"a connection error, not a served request", name)
		}
		var cfe *connFrameError
		if !errors.As(err, &cfe) {
			t.Errorf("%s on a request stream: decodeRequest err = %v (%T), want a *connFrameError "+
				"carrying H3_FRAME_UNEXPECTED", name, err, err)
			continue
		}
		if cfe.code != http3.H3FrameUnexpected {
			t.Errorf("%s on a request stream: close code = %#x, want %#x (H3_FRAME_UNEXPECTED)",
				name, cfe.code, http3.H3FrameUnexpected)
		}
	}
}

// TestDecodeRequest_UnknownFramesAreStillIgnored is the other half of the switch,
// and the reason it cannot be "reject everything but HEADERS and DATA". RFC 9114
// §4.1: "Frames of unknown types (Section 9), including reserved frames
// (Section 7.2.8) MAY be sent on a request or push stream before, after, or
// interleaved with other frames described in this section." The GREASE types
// (§7.2.8: "Frame types of the format 0x1f * N + 0x21 ... are reserved to exercise
// the requirement that unknown types be ignored") are exactly what an interop suite
// sends to check this, so a server that closes on them is broken in the opposite
// direction — and that is the more dangerous direction, because it kills live
// traffic rather than tolerating a frame nobody sends.
func TestDecodeRequest_UnknownFramesAreStillIgnored(t *testing.T) {
	t.Parallel()

	headers := http3.AppendHeaders(nil, encodeSection(validFields))
	tolerated := map[string][]byte{
		"GREASE 0x21":        http3.AppendFrameHeader(nil, 0x21, 0), // 0x1f*0 + 0x21
		"GREASE 0x40":        http3.AppendFrameHeader(nil, 0x40, 0), // 0x1f*1 + 0x21
		"unknown 0x0e":       http3.AppendFrameHeader(nil, 0x0e, 0), // unassigned
		"unknown w/ payload": append(http3.AppendFrameHeader(nil, 0x0e, 3), []byte("abc")...),
	}
	for name, frame := range tolerated {
		stream := append(append([]byte(nil), headers...), frame...)
		req, err := decodeRequest(stream)
		if err != nil {
			t.Errorf("%s on a request stream: decodeRequest err = %v, want the frame ignored and the "+
				"request served (§4.1, §9)", name, err)
			continue
		}
		if req.Method != "GET" {
			t.Errorf("%s: decoded method = %q, want GET", name, req.Method)
		}
	}
}

// TestServer_SettingsOnRequestStreamClosesConnection asserts the verdict reaches
// the connection. This is the half a pure decoder test cannot reach: decodeRequest
// runs on a per-request goroutine, and before this fix that goroutine had no path
// to the connection at all, so the closest it could do was reset the stream and
// serve on. RFC 9114 §7.2.4 requires more: "If an endpoint receives a SETTINGS
// frame on a different stream, the endpoint MUST respond with a connection error of
// type H3_FRAME_UNEXPECTED."
//
// The peer opens a conforming control stream first, so the only rule in play is the
// request-stream one.
func TestServer_SettingsOnRequestStreamClosesConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
		t.Fatalf("Send control: %v", err)
	}

	rs, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// A complete, valid request, then SETTINGS where it does not belong. FIN, so the
	// server reads the whole stream rather than waiting for more.
	stream := http3.AppendHeaders(nil, encodeSection(validFields))
	stream = http3.AppendSettings(stream, nil)
	if _, err := rs.Send(stream, true); err != nil {
		t.Fatalf("Send request: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3FrameUnexpected)
}
