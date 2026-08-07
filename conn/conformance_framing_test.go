package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for frame-level error reporting.
//
// Governing text, copied verbatim from rfc9113.txt as fetched from
// rfc-editor.org:
//
//	§5.4 (rfc9113.txt:1159) — "If a frame causes a connection error, that error
//	MUST be reported."
//
//	§4.2 (rfc9113.txt:513) — "An endpoint MUST send an error code of
//	FRAME_SIZE_ERROR if a frame exceeds the size defined in
//	SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is
//	too small to contain mandatory frame data."
//
//	§5.4.1 (rfc9113.txt:1173) — "After sending the GOAWAY frame for an error
//	condition, the endpoint MUST close the TCP connection."
//
// These are the violations the frame codec itself detects. The codec reports
// them as plain sentinel errors carrying no HTTP/2 error code, so deciding
// which code the peer is owed — and whether the violation is scoped to one
// stream or to the whole connection — is the receiving server's job.

// rawFrame builds a wire-format frame by hand. The client-side *frame.Framer
// deliberately cannot emit the malformed frames these tests need: WriteRSTStream
// always writes 4 octets, WritePriority always 5, and WriteWindowUpdate rejects
// a zero increment outright.
func rawFrame(typ frame.FrameType, flags frame.Flags, streamID uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0] = byte(len(payload) >> 16)
	b[1] = byte(len(payload) >> 8)
	b[2] = byte(len(payload))
	b[3] = byte(typ)
	b[4] = byte(flags)
	binary.BigEndian.PutUint32(b[5:9], streamID&0x7fffffff)
	copy(b[9:], payload)
	return b
}

// rawHeader builds a frame header that lies about its payload length. Used to
// drive the one case where the reader cannot resynchronise.
func rawHeader(typ frame.FrameType, streamID, length uint32) []byte {
	b := make([]byte, 9)
	b[0] = byte(length >> 16)
	b[1] = byte(length >> 8)
	b[2] = byte(length)
	b[3] = byte(typ)
	binary.BigEndian.PutUint32(b[5:9], streamID&0x7fffffff)
	return b
}

// runRawProbe is runRSTProbe with two additions the framing tests need: the raw
// net.Conn, so the attack can write bytes no Framer would produce, and the
// server options, so the advertised MAX_FRAME_SIZE can be varied.
func runRawProbe(t *testing.T, opts ServerConnOptions, attack func(cli net.Conn, cliFr *frame.Framer)) fieldRSTCapture {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()

	result := make(chan fieldRSTCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			rc := &fieldRSTCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), rc); err != nil {
						return
					}
					if rc.sawRST || rc.sawGoAway {
						return
					}
				}
			}()
			attack(cli, cliFr)
			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
			select {
			case result <- *rc:
			default:
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, opts.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	// Never block on `done` unconditionally. These tests write frames a
	// conformant peer would not send, and net.Pipe is synchronous: if the server
	// abandons the connection without closing it, the client's write blocks
	// forever and the whole package times out instead of reporting one failure.
	waitDone := func() {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	select {
	case rc := <-result:
		waitDone()
		return rc
	case <-time.After(4 * time.Second):
		waitDone()
		return fieldRSTCapture{}
	}
}

// TestConformance_RFC9113_Sec54_CodecErrorsAreReportedWithAnErrorCode pins
// rfc9113.txt:1159 and rfc9113.txt:513 across every structural violation the
// frame codec detects on the read path.
//
// Each of these arrives at the reader loop as a plain sentinel error from the
// codec, not as a connError raised by one of this package's own handler
// callbacks. Reporting is what distinguishes the two: a sentinel that is not
// mapped to an HTTP/2 error code leaves the peer with a connection that simply
// stops responding and no way to learn why.
func TestConformance_RFC9113_Sec54_CodecErrorsAreReportedWithAnErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		want  frame.ErrCode
	}{
		// §4.2 (rfc9113.txt:513) — "too small to contain mandatory frame data".
		{"RST_STREAM_length_3", rawFrame(frame.FrameRSTStream, 0, 1, []byte{0, 0, 0}), frame.ErrCodeFrameSizeError},
		{"PING_length_7", rawFrame(frame.FramePing, 0, 0, make([]byte, 7)), frame.ErrCodeFrameSizeError},
		{"WINDOW_UPDATE_length_3", rawFrame(frame.FrameWindowUpdate, 0, 0, []byte{0, 0, 1}), frame.ErrCodeFrameSizeError},
		{"GOAWAY_length_4", rawFrame(frame.FrameGoAway, 0, 0, make([]byte, 4)), frame.ErrCodeFrameSizeError},

		// §6.5 (rfc9113.txt:1795) — "A SETTINGS frame with a length other than a
		// multiple of 6 octets MUST be treated as a connection error (Section
		// 5.4.1) of type FRAME_SIZE_ERROR."
		{"SETTINGS_length_3", rawFrame(frame.FrameSettings, 0, 0, []byte{0, 0, 0}), frame.ErrCodeFrameSizeError},
		// §6.5 (rfc9113.txt:1790) — "Receipt of a SETTINGS frame with the ACK flag
		// set and a length field value other than 0 MUST be treated as a
		// connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
		{"SETTINGS_ACK_with_payload", rawFrame(frame.FrameSettings, frame.FlagSettingsAck, 0, []byte{0}), frame.ErrCodeFrameSizeError},

		// §6.1/§6.2/§6.7/§6.8 — frames that must or must not carry a stream id.
		{"DATA_on_stream_0", rawFrame(frame.FrameData, 0, 0, []byte("x")), frame.ErrCodeProtocolError},
		{"HEADERS_on_stream_0", rawFrame(frame.FrameHeaders, frame.FlagHeadersEndHeaders, 0, []byte{0x82}), frame.ErrCodeProtocolError},
		{"RST_STREAM_on_stream_0", rawFrame(frame.FrameRSTStream, 0, 0, []byte{0, 0, 0, 0}), frame.ErrCodeProtocolError},
		{"SETTINGS_on_stream_1", rawFrame(frame.FrameSettings, 0, 1, nil), frame.ErrCodeProtocolError},
		{"PING_on_stream_1", rawFrame(frame.FramePing, 0, 1, make([]byte, 8)), frame.ErrCodeProtocolError},
		{"GOAWAY_on_stream_1", rawFrame(frame.FrameGoAway, 0, 1, make([]byte, 8)), frame.ErrCodeProtocolError},
		{"CONTINUATION_on_stream_0", rawFrame(frame.FrameContinuation, frame.FlagContinuationEndHeaders, 0, nil), frame.ErrCodeProtocolError},

		// §6.1 (rfc9113.txt:1420) — "If the length of the padding is the length of
		// the frame payload or greater, the recipient MUST treat this as a
		// connection error (Section 5.4.1) of type PROTOCOL_ERROR."
		{"DATA_pad_length_eats_payload", rawFrame(frame.FrameData, frame.FlagDataPadded, 1, []byte{0xff, 'a'}), frame.ErrCodeProtocolError},
		{"HEADERS_pad_length_eats_payload", rawFrame(frame.FrameHeaders, frame.FlagHeadersEndHeaders|frame.FlagHeadersPadded, 1, []byte{0xff, 0x82}), frame.ErrCodeProtocolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
				_, _ = cli.Write(tc.frame)
			})
			if !rc.sawGoAway {
				t.Fatalf("no GOAWAY for %s; RFC 9113 §5.4 requires that a frame causing a "+
					"connection error be reported (sawRST=%v)", tc.name, rc.sawRST)
			}
			if rc.goAwayCode != tc.want {
				t.Errorf("GOAWAY code = %v, want %v", rc.goAwayCode, tc.want)
			}
		})
	}
}

// TestConformance_RFC9113_Sec42_OversizedFrame_GoAwayFrameSizeError pins
// rfc9113.txt:513 for the one case the connection cannot survive: the codec
// rejects the frame on its header, before the payload has been consumed, so the
// byte stream is no longer frame-aligned and there is nothing to resynchronise
// to. The error must still be reported.
func TestConformance_RFC9113_Sec42_OversizedFrame_GoAwayFrameSizeError(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
		_, _ = cli.Write(rawHeader(frame.FrameData, 1, 16385))
	})
	if !rc.sawGoAway {
		t.Fatalf("no GOAWAY for a frame exceeding SETTINGS_MAX_FRAME_SIZE")
	}
	if rc.goAwayCode != frame.ErrCodeFrameSizeError {
		t.Errorf("GOAWAY code = %v, want FRAME_SIZE_ERROR", rc.goAwayCode)
	}
}

// TestConformance_RFC9113_Sec42_AdvertisedMaxFrameSizeIsAccepted reads
// rfc9113.txt:513 the other way round: a frame is oversized only relative to
// "the size defined in SETTINGS_MAX_FRAME_SIZE", which is the value this server
// advertised. Rejecting what we asked for is the same defect seen from the
// receiving end.
func TestConformance_RFC9113_Sec42_AdvertisedMaxFrameSizeIsAccepted(t *testing.T) {
	// Twice the 16,384 default, so the frame is only acceptable if the Framer's
	// read cap tracks what SETTINGS advertised — but still inside the 65,535
	// flow-control window, so this test measures frame size and nothing else.
	const big = 1 << 15
	opts := ServerConnOptions{AdvertisedSettings: AdvertisedSettings{MaxFrameSize: big}}
	rc := runRawProbe(t, opts, func(cli net.Conn, cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, false)
		_, _ = cli.Write(rawFrame(frame.FrameData, frame.FlagDataEndStream, 1, make([]byte, big)))
	})
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v) for a DATA frame of exactly the size this server advertised "+
			"in SETTINGS_MAX_FRAME_SIZE", rc.goAwayCode)
	}
}

// TestConformance_RFC9113_Sec63_MalformedPriorityLength_IsAStreamError pins
// rfc9113.txt:1519 — "A PRIORITY frame with a length other than 5 octets MUST
// be treated as a stream error (Section 5.4.2) of type FRAME_SIZE_ERROR."
//
// The load-bearing half of this test is the third assertion: §5.4.2 scoping is
// only meaningful if the rest of the multiplexed connection survives.
func TestConformance_RFC9113_Sec63_MalformedPriorityLength_IsAStreamError(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer) {
		// Stream 1 must exist first. §6.4 (rfc9113.txt:1596) forbids sending
		// RST_STREAM for an idle stream outright, so the stream-error scoping of
		// §6.3 can only apply to a stream that has been opened.
		sendReq(t, cliFr, 1, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("POST")},
			{Name: []byte(":scheme"), Value: []byte("https")},
			{Name: []byte(":path"), Value: []byte("/")},
		}, false)
		_, _ = cli.Write(rawFrame(frame.FramePriority, 0, 1, []byte{0, 0, 0, 0}))
	})
	if !rc.sawRST {
		t.Fatalf("no RST_STREAM for a 4-octet PRIORITY frame (sawGoAway=%v code=%v)",
			rc.sawGoAway, rc.goAwayCode)
	}
	if rc.rstCode != frame.ErrCodeFrameSizeError {
		t.Errorf("RST_STREAM code = %v, want FRAME_SIZE_ERROR", rc.rstCode)
	}
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v) for a malformed PRIORITY; §6.3 scopes this to the stream", rc.goAwayCode)
	}
}

// TestConformance_RFC9113_Sec691_ZeroWindowUpdateScopeSplit pins both clauses of
// rfc9113.txt:2125 — "A receiver MUST treat the receipt of a WINDOW_UPDATE frame
// with a flow-control window increment of 0 as a stream error (Section 5.4.2) of
// type PROTOCOL_ERROR; errors on the connection flow-control window MUST be
// treated as a connection error (Section 5.4.1)."
//
// The two sub-cases are what stops the fix over-correcting: scoping every zero
// increment to a stream passes the first and fails the second.
func TestConformance_RFC9113_Sec691_ZeroWindowUpdateScopeSplit(t *testing.T) {
	zero := rawFrame(frame.FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0})

	t.Run("on_a_stream_is_a_stream_error", func(t *testing.T) {
		rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer) {
			// Open stream 1: on an IDLE stream §5.1 makes any WINDOW_UPDATE a
			// connection error, which would mask the scoping this sub-case measures.
			sendReq(t, cliFr, 1, []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("POST")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/")},
			}, false)
			_, _ = cli.Write(zero)
		})
		if !rc.sawRST {
			t.Fatalf("no RST_STREAM for WINDOW_UPDATE with a zero increment on stream 1 "+
				"(sawGoAway=%v code=%v)", rc.sawGoAway, rc.goAwayCode)
		}
		if rc.rstCode != frame.ErrCodeProtocolError {
			t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR", rc.rstCode)
		}
		if rc.sawGoAway {
			t.Errorf("GOAWAY(%v); a zero increment on a stream is a stream error", rc.goAwayCode)
		}
	})

	t.Run("on_the_connection_is_a_connection_error", func(t *testing.T) {
		rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
			_, _ = cli.Write(rawFrame(frame.FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 0}))
		})
		if !rc.sawGoAway {
			t.Fatalf("no GOAWAY for WINDOW_UPDATE with a zero increment on stream 0")
		}
		if rc.goAwayCode != frame.ErrCodeProtocolError {
			t.Errorf("GOAWAY code = %v, want PROTOCOL_ERROR", rc.goAwayCode)
		}
	})
}

// TestConformance_RFC9113_Sec610_MalformedFrameDuringOpenFieldBlock pins §6.10
// against §6.3: while a field block is open, "any frame other than a
// CONTINUATION frame on the same stream" is a connection error of type
// PROTOCOL_ERROR (rfc9113.txt:2263). That outranks §6.3's stream scoping, and
// the codec rejects the malformed PRIORITY on length before guardHeaderBlock can
// ever see it — so the reader loop is the only place left that can tell the
// difference.
//
// This test is a regression guard on the fix itself: stream-scoped recovery
// without the open-block gate passes every other test in this file and fails
// this one.
func TestConformance_RFC9113_Sec610_MalformedFrameDuringOpenFieldBlock(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer) {
		// HEADERS without END_HEADERS leaves a field block open.
		if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      1,
			BlockFragment: []byte{0x82},
			EndHeaders:    false,
		}); err != nil {
			t.Logf("write HEADERS: %v", err)
			return
		}
		_, _ = cli.Write(rawFrame(frame.FramePriority, 0, 1, []byte{0, 0, 0, 0}))
	})
	if !rc.sawGoAway {
		t.Fatalf("no GOAWAY for a malformed frame arriving inside an open field block "+
			"(sawRST=%v code=%v)", rc.sawRST, rc.rstCode)
	}
	if rc.goAwayCode != frame.ErrCodeProtocolError {
		t.Errorf("GOAWAY code = %v, want PROTOCOL_ERROR", rc.goAwayCode)
	}
	if rc.sawRST {
		t.Errorf("RST_STREAM(%v) inside an open field block; §6.10 makes this a "+
			"connection error whatever the frame was", rc.rstCode)
	}
}

// TestConformance_RFC9113_Sec541_ConnectionErrorClosesTheTransport pins
// rfc9113.txt:1173 — "After sending the GOAWAY frame for an error condition, the
// endpoint MUST close the TCP connection."
//
// Without it the reader goroutine is gone, so nothing is ever read from the
// socket again, but the socket itself survives: a peer that deliberately trips a
// connection error leaks one file descriptor per attempt.
func TestConformance_RFC9113_Sec541_ConnectionErrorClosesTheTransport(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ready := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// A SETTINGS frame whose length is not a multiple of 6.
			if _, err := cli.Write(rawFrame(frame.FrameSettings, 0, 0, []byte{0, 0, 0})); err != nil {
				t.Logf("write: %v", err)
			}
			close(ready)
			for {
				if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
					closed <- err
					return
				}
			}
		})
	}()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	<-ready
	select {
	case err := <-closed:
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("read ended on a deadline, not on a close: %v", err)
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Logf("transport ended with %v (accepted: any close)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("the transport was still open 3s after the server sent GOAWAY for a " +
			"connection error; RFC 9113 §5.4.1 requires it be closed")
	}
}
