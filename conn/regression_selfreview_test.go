package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Regression guards for defects the adversarial review of the RFC 9113 branch
// found in the fixes themselves. Each one was introduced by a conformance fix
// and would have shipped without these.

// TestRegression_ResetStreamIsClosedForWriting guards the trap in the
// half-closed (remote) guards: they reset the stream, but a handler goroutine
// already holding the *ServerStream would still have been allowed to write its
// response afterwards — putting HEADERS on the wire behind an RST_STREAM, the
// exact §5.1 violation the guard exists to prevent.
//
// What closes the stream for writing is ss.advance(stReset), which both reset
// paths now perform — writeServerRSTStream unconditionally, writeRSTStreamID
// whenever the identifier resolves to a live stream. (The line that stood here,
// "resetting by identifier alone cannot close the stream for writing", stopped
// being true in #67, the change that introduced the reset bit; a mutation
// swapping this call site for writeRSTStreamID is now a no-op, which is how it
// was noticed.)
//
// THE ORDER IS THE TEST, and it used to be a race (issue #153). The property
// only exists for a handler that is ALREADY holding the stream when the reset
// lands, so the DATA frame that provokes the reset must not be written until
// AcceptStream has handed the stream over. Writing it immediately after the
// HEADERS, as this test did, let the reader loop reset stream 1 while it was
// still sitting in the accept queue; AcceptStream then correctly refused to
// deliver a stream that was already dead (deliverable(), issue #133) and blocked
// until the 5s budget expired. 36 of 500 runs under -race on Linux, every one of
// them failing at exactly 5.00s on the AcceptStream setup line rather than on
// anything this test exists to check, and none with a DATA RACE to show for it.
//
// The wait on the reset is likewise a signal and not a budget. markStreamDone
// cancels the stream context, writeServerRSTStream defers it, and that call sets
// stReset before anything goes on the wire — so a cancelled context means the
// reset is recorded, whereas "the client wrote the DATA frame" only meant the
// server had not necessarily looked at it yet. That weaker signal is what forced
// the old 2s poll-until-it-fails loop, and the loop is what cost this test its
// teeth: SendHeaders was called with endStream=true, so its FIRST call closed
// the stream for writing by itself, and the second returned ErrStreamClosed
// whether or not the reset had any part in it. With ss.advance(stReset) deleted
// from writeServerRSTStream — the one line this test names in its own comment —
// the old test passed 30 of 30.
func TestRegression_ResetStreamIsClosedForWriting(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Closed once AcceptStream has delivered stream 1, which is the moment a real
	// handler would be holding it. Until then the client must not provoke the
	// reset, or there is no handler for the property to be about.
	accepted := make(chan struct{})
	// Closed when the assertions are done, so the client holds the connection open
	// for exactly as long as the test needs it. Without this, pipeClient's deferred
	// Close tears the connection down, and connection teardown cancels stream
	// contexts too (issue #139) — the test would then be waiting on a signal that
	// no longer means "reset".
	held := make(chan struct{})
	defer close(held)

	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Drain first: net.Pipe is synchronous, so the RST_STREAM below would
			// otherwise park the server's reader goroutine on an unread pipe.
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
						return
					}
				}
			}()
			sendReq(t, cliFr, 1, goodHeaders("/"), true) // END_STREAM
			<-accepted
			// DATA after END_STREAM: the server must reset the stream.
			_, _ = cli.Write(rawFrame(frame.FrameData, 0, 1, []byte("x")))
			<-held
		})
	}()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	close(accepted)

	// Wait for the reset to be RECORDED, not merely provoked. ctx.Done here is a
	// failsafe against a hang, never part of the passing path: if it fires, the
	// server did not reset a stream that received DATA after END_STREAM, which is
	// a §5.1 failure in its own right and says so.
	select {
	case <-stream.Context().Done():
	case <-ctx.Done():
		t.Fatalf("stream context still live: the server never reset stream 1 after DATA " +
			"arrived on it past END_STREAM, which §5.1 requires as a STREAM_CLOSED stream error")
	}

	// The handler now tries to respond, as a real one would, exactly once.
	// endStream=false on purpose: a write that succeeds must not be able to close
	// the stream by itself and so disguise itself as the refusal being asserted.
	werr := stream.SendHeaders(ctx, []hpack.HeaderField{
		{Name: []byte(":status"), Value: []byte("200")},
	}, false)
	if !errors.Is(werr, ErrStreamClosed) {
		t.Errorf("SendHeaders on a stream the server had just reset returned %v, want "+
			"ErrStreamClosed; §5.1 forbids sending anything but PRIORITY on a closed stream", werr)
	}
}

// TestRegression_PushStreamsAreReleasedWhenTheirResponseEnds guards the §5.1.2
// push concurrency check. A pushed stream is half-closed (remote) from birth —
// the client never sends on it — so markLocalEnd is what completes it. Without
// that, markStreamDone was never reached, every pushed stream stayed in the
// registry for the life of the connection, and the new concurrency counter
// therefore refused every push after the first MaxConcurrentStreams, however
// many were actually open.
func TestRegression_PushStreamsAreReleasedWhenTheirResponseEnds(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Start draining first: net.Pipe is synchronous, and the SETTINGS below
			// makes the server write an ACK that would otherwise have no reader.
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
						return
					}
				}
			}()
			// Advertise a small limit so the §5.1.2 counter is live.
			var p frame.SettingsParams
			p.Pairs[0] = frame.SettingPair{ID: frame.SettingMaxConcurrentStreams, Value: 2}
			p.N = 1
			if err := cliFr.WriteSettings(p); err != nil {
				t.Logf("client SETTINGS: %v", err)
				return
			}
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			time.Sleep(750 * time.Millisecond) // keep the pipe alive while pushes run
		})
	}()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Five pushes, each completed before the next begins: never more than one
	// push stream is open, so none of them may be refused.
	for i := range 5 {
		ps, perr := stream.Push(ctx, goodHeaders("/asset"))
		if perr != nil {
			t.Fatalf("push #%d refused: %v — completed pushes are still being counted "+
				"against the peer's concurrent stream limit", i+1, perr)
		}
		if serr := ps.SendHeaders(ctx, []hpack.HeaderField{
			{Name: []byte(":status"), Value: []byte("200")},
		}, true); serr != nil {
			t.Fatalf("push #%d response: %v", i+1, serr)
		}
	}
}

// TestRegression_MalformedFrameOnIdleStreamIsAConnectionError guards the
// stream-scoped recovery added for §6.3 and §6.9.1. Recovering by sending
// RST_STREAM is right for a live stream and forbidden for an idle one: §6.4
// says "RST_STREAM frames MUST NOT be sent for a stream in
// the 'idle' state", and a conformant peer receiving one MUST answer
// GOAWAY(PROTOCOL_ERROR) — killing the connection the recovery meant to save.
func TestRegression_MalformedFrameOnIdleStreamIsAConnectionError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		want  frame.ErrCode
	}{
		// The connection error keeps the code that names the actual violation:
		// §4.2 mandates FRAME_SIZE_ERROR for a frame that is the
		// wrong size, and §6.9.1 PROTOCOL_ERROR for a zero increment. Only the
		// SCOPE changes on an idle stream, not the diagnosis.
		{"PRIORITY_wrong_length", rawFrame(frame.FramePriority, 0, 1, []byte{0, 0, 0, 0}), frame.ErrCodeFrameSizeError},
		{"WINDOW_UPDATE_zero_increment", rawFrame(frame.FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0}), frame.ErrCodeProtocolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
				_, _ = cli.Write(tc.frame) // stream 1 was never opened
			})
			if rc.sawRST {
				t.Errorf("RST_STREAM(%v) for an idle stream; §6.4 forbids sending one there, "+
					"and a conformant peer must answer it with GOAWAY(PROTOCOL_ERROR)", rc.rstCode)
			}
			if !rc.sawGoAway {
				t.Fatalf("no GOAWAY for a malformed frame on an idle stream")
			}
			if rc.goAwayCode != tc.want {
				t.Errorf("GOAWAY code = %v, want %v", rc.goAwayCode, tc.want)
			}
		})
	}
}

// TestRegression_HeaderFieldsSurviveDynamicTableEviction guards the field-copy
// discipline in emitHeaderBlock.
//
// hpack.Decoder's field slices are valid only for the duration of the visit
// call: they alias its scratch buffer, or the dynamic table's arena, which is
// rewritten in place when an insertion evicts the table empty. Retaining them
// meant a later field in the same block could silently overwrite an earlier one
// — and since the §8.2.1 name checks run inside the callback, on the
// pre-overwrite bytes, it was a validation bypass as well as corruption.
//
// The block below fills the 4096-octet dynamic table exactly, then on the next
// stream references that entry and immediately inserts another, forcing the
// eviction that resets the arena.
func TestRegression_HeaderFieldsSurviveDynamicTableEviction(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	big := make([]byte, 4059)
	for i := range big {
		big[i] = 'v'
	}

	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			enc := hpack.NewEncoder()
			send := func(id uint32, fields []hpack.HeaderField) {
				block := enc.EncodeBlock(nil, fields)
				w := make(chan error, 1)
				go func() {
					w <- cliFr.WriteHeaders(frame.WriteHeadersParams{
						StreamID: id, BlockFragment: block, EndHeaders: true, EndStream: true,
					})
				}()
				<-w
			}
			// Entry size 5 + 4059 + 32 = 4096: fills the table exactly.
			send(1, append(goodHeaders("/"), hpack.HeaderField{Name: []byte("x-big"), Value: big}))
			// Reference x-big, then insert another entry, which evicts it.
			send(3, append(goodHeaders("/"),
				hpack.HeaderField{Name: []byte("x-big"), Value: big},
				hpack.HeaderField{Name: []byte("a"), Value: []byte("bc")}))
			for {
				if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
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

	for range 2 {
		stream, aerr := sc.AcceptStream(ctx)
		if aerr != nil {
			t.Fatalf("AcceptStream: %v", aerr)
		}
		ev, rerr := stream.Recv(ctx)
		if rerr != nil {
			t.Fatalf("Recv: %v", rerr)
		}
		for _, f := range ev.Headers {
			if string(f.Name) != "x-big" {
				continue
			}
			if len(f.Value) != len(big) || string(f.Value) != string(big) {
				t.Fatalf("stream %d: x-big value corrupted (len %d, want %d) — decoded field "+
					"slices were retained past their visit callback and rewritten by a later "+
					"dynamic-table eviction", stream.id, len(f.Value), len(big))
			}
		}
	}
}
