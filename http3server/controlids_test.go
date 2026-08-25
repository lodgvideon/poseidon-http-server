package http3server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// ---------------------------------------------------------------------------
// The identifier rules on the control stream (#212 group D).
//
// GOAWAY, CANCEL_PUSH and MAX_PUSH_ID used to fall into readControl's default
// branch and be discarded, on the reasoning that this server never pushes so a
// push-ID frame has nothing to control. That is right about push FULFILMENT and
// wrong about the push-ID SPACE: §5.2 and §7.2.7 make a receiver responsible for
// the identifiers being monotonic whether or not it uses them, and §7.2.3 makes
// a CANCEL_PUSH for an unpromised Push ID an error outright. H3_ID_ERROR was
// emitted nowhere in the package.
// ---------------------------------------------------------------------------

// controlPeer dials a raw peer and opens a conforming control stream, returning
// the connection and a send function that appends further frames to it.
func controlPeer(ctx context.Context, t *testing.T) (*quic.Conn, func(frames ...[]byte)) {
	t.Helper()
	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)
	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
		t.Fatalf("sending the control stream: %v", err)
	}
	return conn, func(frames ...[]byte) {
		t.Helper()
		var buf []byte
		for _, f := range frames {
			buf = append(buf, f...)
		}
		if _, err := ctl.Send(buf, false); err != nil {
			t.Fatalf("sending control frames: %v", err)
		}
	}
}

func TestControlStream_IdentifierRules(t *testing.T) {
	cases := []struct {
		name   string
		frames [][]byte
		want   uint64
		why    string
	}{
		{
			// §7.2.3: a CANCEL_PUSH for a Push ID no PUSH_PROMISE mentioned. This
			// server never promises, so every CANCEL_PUSH is one.
			name:   "CANCEL_PUSH for an unpromised push",
			frames: [][]byte{http3.AppendCancelPush(nil, 0)},
			want:   http3.H3IDError,
			why:    "§7.2.3",
		},
		{
			name:   "CANCEL_PUSH for a high push id",
			frames: [][]byte{http3.AppendCancelPush(nil, 1_000_000)},
			want:   http3.H3IDError,
			why:    "§7.2.3",
		},
		{
			// §7.1: a payload that terminates before the identified fields. The
			// Push ID varint is mandatory, so a zero-length payload is malformed
			// framing, and framing outranks the identifier question.
			name:   "CANCEL_PUSH with no push id at all",
			frames: [][]byte{http3.AppendFrameHeader(nil, http3.FrameCancelPush, 0)},
			want:   http3.H3FrameError,
			why:    "§7.1",
		},
		{
			// §7.1: additional bytes after the identified fields.
			name: "MAX_PUSH_ID with trailing bytes",
			frames: [][]byte{append(
				http3.AppendFrameHeader(nil, http3.FrameMaxPushID, 3), 0x00, 0xff, 0xff,
			)},
			want: http3.H3FrameError,
			why:  "§7.1",
		},
		{
			// §7.2.7: "A server MUST treat receipt of a MAX_PUSH_ID frame that
			// contains a smaller value than previously received as a connection
			// error of type H3_ID_ERROR."
			name: "MAX_PUSH_ID going backwards",
			frames: [][]byte{
				http3.AppendMaxPushID(nil, 10),
				http3.AppendMaxPushID(nil, 9),
			},
			want: http3.H3IDError,
			why:  "§7.2.7",
		},
		{
			// §5.2: "Receiving a GOAWAY containing a larger identifier than
			// previously received MUST be treated as a connection error of type
			// H3_ID_ERROR."
			name: "GOAWAY going forwards",
			frames: [][]byte{
				http3.AppendGoaway(nil, 4),
				http3.AppendGoaway(nil, 8),
			},
			want: http3.H3IDError,
			why:  "§5.2",
		},
		{
			name:   "GOAWAY with trailing bytes",
			frames: [][]byte{append(http3.AppendFrameHeader(nil, http3.FrameGoaway, 2), 0x00, 0x00)},
			want:   http3.H3FrameError,
			why:    "§7.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("expecting %#x per RFC 9114 %s", tc.want, tc.why)
			sendControlAndWantClose(t, tc.want, tc.frames...)
		})
	}
}

// sendControlAndWantClose opens a conforming control stream, appends frames to
// it, and asserts the server closes the connection with want. Both tables below
// drive it; the shared ctx/timeout and peer setup are the parts that would
// otherwise drift between them.
func sendControlAndWantClose(t *testing.T, want uint64, frames ...[]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, send := controlPeer(ctx, t)
	send(frames...)
	wantConnClosed(ctx, t, conn, want)
}

// TestControlStream_LegalIdentifierSequencesSurvive is the negative control, and
// it is not decoration: without it, "close the connection on every push-ID frame"
// passes every case above.
//
// A live connection cannot be asserted by silence, so each case sends its legal
// sequence and THEN one frame that must close the connection with a different,
// known code. Arriving at that code proves the connection was still being served
// when it got there — and that the legal frames did not produce H3_ID_ERROR.
func TestControlStream_LegalIdentifierSequencesSurvive(t *testing.T) {
	cases := map[string][][]byte{
		"MAX_PUSH_ID rising": {
			http3.AppendMaxPushID(nil, 1),
			http3.AppendMaxPushID(nil, 10),
			http3.AppendMaxPushID(nil, 1000),
		},
		"MAX_PUSH_ID repeating the same value": {
			http3.AppendMaxPushID(nil, 7),
			http3.AppendMaxPushID(nil, 7),
		},
		"GOAWAY falling": {
			http3.AppendGoaway(nil, 12),
			http3.AppendGoaway(nil, 8),
			http3.AppendGoaway(nil, 0),
		},
		"GOAWAY repeating the same value": {
			http3.AppendGoaway(nil, 4),
			http3.AppendGoaway(nil, 4),
		},
		"a GREASE frame is still ignored": {
			http3.AppendFrameHeader(nil, 0x1f*7+0x21, 0),
		},
	}

	for name, legal := range cases {
		t.Run(name, func(t *testing.T) {
			// The legal sequence, then a DATA frame — which §7.2.1 makes
			// H3_FRAME_UNEXPECTED on a control stream, a code none of the rules
			// under test can produce. Reaching THAT code proves the legal frames
			// did not close the connection first with H3_ID_ERROR.
			sendControlAndWantClose(t, http3.H3FrameUnexpected,
				append(legal, http3.AppendFrameHeader(nil, http3.FrameData, 0))...)
		})
	}
}

// ---------------------------------------------------------------------------
// The varint payload parser, without a network
// ---------------------------------------------------------------------------

func TestSingleVarintPayload(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload []byte
		want    uint64
		ok      bool
	}{
		{"one-byte varint", []byte{0x07}, 7, true},
		{"one-byte maximum", []byte{0x3f}, 63, true},
		{"two-byte varint", []byte{0x40, 0x40}, 64, true},
		{"four-byte varint", []byte{0x80, 0x00, 0x40, 0x00}, 16384, true},
		{"eight-byte varint", []byte{0xc0, 0, 0, 0, 0, 0, 0, 0x01}, 1, true},
		{"zero", []byte{0x00}, 0, true},

		// §7.1, both directions.
		{"empty payload", nil, 0, false},
		{"truncated two-byte", []byte{0x40}, 0, false},
		{"truncated eight-byte", []byte{0xc0, 0, 0}, 0, false},
		{"trailing byte", []byte{0x07, 0x00}, 0, false},
		{"two varints", []byte{0x01, 0x02}, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := singleVarintPayload(tc.payload)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("value = %d, want %d", got, tc.want)
			}
		})
	}
}
