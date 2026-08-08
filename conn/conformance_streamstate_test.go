package conn

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the stream state machine (RFC 9113 §5.1) and for the
// connection-level flow-control accounting §6.9 makes unconditional.
//
//	§5.1 (rfc9113.txt:1000), idle — "Receiving any frame other than HEADERS or
//	PRIORITY on a stream in this state MUST be treated as a connection error
//	(Section 5.4.1) of type PROTOCOL_ERROR."
//
//	§5.1 (rfc9113.txt:1044), half-closed (remote) — "If an endpoint receives
//	additional frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a
//	stream that is in this state, it MUST respond with a stream error (Section
//	5.4.2) of type STREAM_CLOSED."
//
//	§6.9.1 (rfc9113.txt:2113) — "A receiver MUST count the padding and the entire
//	size of a frame ... against its connection-level flow-control window even if
//	the frame is in error."
//
// Distinguishing idle from closed is the whole difficulty: the streams map holds
// only live streams, so a lookup miss means idle, closed, reset or refused
// indifferently — and the RFC demands a connection error for the first and at
// most a stream error for the rest.

// flowCapture records every WINDOW_UPDATE the server sends, plus the
// first RST_STREAM and GOAWAY. fieldRSTCapture drops window updates, which is
// exactly what these tests measure.
// Guarded by mu throughout: the reader goroutine fills it while the probe body
// polls it to decide when to send the next frame.
type flowCapture struct {
	fieldRSTCapture
	mu               sync.Mutex
	connIncrements   []uint32
	streamIncrements map[uint32]uint32
	rstSeen          bool
}

func newFlowCapture() *flowCapture {
	return &flowCapture{streamIncrements: map[uint32]uint32{}}
}

func (c *flowCapture) OnWindowUpdate(fh frame.FrameHeader, inc uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fh.StreamID == 0 {
		c.connIncrements = append(c.connIncrements, inc)
		return nil
	}
	c.streamIncrements[fh.StreamID] += inc
	return nil
}

func (c *flowCapture) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	c.mu.Lock()
	c.rstSeen = true
	c.mu.Unlock()
	return c.fieldRSTCapture.OnRSTStream(fh, code)
}

func (c *flowCapture) sawReset() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rstSeen
}

func (c *flowCapture) connTotal() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n uint32
	for _, v := range c.connIncrements {
		n += v
	}
	return n
}

func (c *flowCapture) streamTotal(id uint32) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streamIncrements[id]
}

// runWindowProbe drives a client that keeps reading while it writes, and returns
// everything the server sent. Unlike runRawProbe it does not stop at the first
// RST_STREAM: the frames under test arrive after one.
func runWindowProbe(t *testing.T, opts ServerConnOptions, attack func(cli net.Conn, cliFr *frame.Framer, seen *flowCapture)) *flowCapture {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := newFlowCapture()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), seen); err != nil {
						return
					}
				}
			}()
			attack(cli, cliFr, seen)
			// Let anything still in flight land before the pipe is torn down.
			select {
			case <-readDone:
			case <-time.After(500 * time.Millisecond):
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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not finish")
	}
	return seen
}

func goodHeaders(path string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte(path)},
	}
}

// TestConformance_RFC9113_Sec51_IdleStream_NonHeadersFrame_ConnectionError pins
// rfc9113.txt:1000 and its restatement for RST_STREAM at §6.4 (:1596): "If a
// RST_STREAM frame identifying an idle stream is received, the recipient MUST
// treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
//
// Every one of these was silently ignored: lookupStream missed and the callback
// returned nil.
func TestConformance_RFC9113_Sec51_IdleStream_NonHeadersFrame_ConnectionError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"DATA_on_idle_odd_stream", rawFrame(frame.FrameData, 0, 7, []byte("body"))},
		{"RST_STREAM_on_idle_odd_stream", rawFrame(frame.FrameRSTStream, 0, 7, []byte{0, 0, 0, 8})},
		{"WINDOW_UPDATE_on_idle_odd_stream", rawFrame(frame.FrameWindowUpdate, 0, 7, []byte{0, 0, 0, 1})},
		{"DATA_on_never_pushed_even_stream", rawFrame(frame.FrameData, 0, 2, []byte("body"))},
		{"WINDOW_UPDATE_on_never_pushed_even_stream", rawFrame(frame.FrameWindowUpdate, 0, 2, []byte{0, 0, 0, 1})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
				_, _ = cli.Write(tc.frame)
			})
			if !rc.sawGoAway {
				t.Fatalf("no GOAWAY for %s; §5.1 makes a frame other than HEADERS or "+
					"PRIORITY on an idle stream a connection error (sawRST=%v)", tc.name, rc.sawRST)
			}
			if rc.goAwayCode != frame.ErrCodeProtocolError {
				t.Errorf("GOAWAY code = %v, want PROTOCOL_ERROR", rc.goAwayCode)
			}
		})
	}
}

// TestConformance_RFC9113_Sec51_PriorityOnIdleStreamIsPermitted is the negative
// control for the test above, and the reason it is not one blanket rule: §5.1
// names PRIORITY alongside HEADERS as the two frames an idle stream accepts, and
// §5.1.1 adds that PRIORITY "does not open a stream". Over-correcting the idle
// check into a connection killer would break every client that prioritises
// before requesting.
func TestConformance_RFC9113_Sec51_PriorityOnIdleStreamIsPermitted(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer) {
		_, _ = cli.Write(rawFrame(frame.FramePriority, 0, 9, []byte{0, 0, 0, 0, 15}))
		// A legitimate request afterwards must still be served.
		sendReq(t, cliFr, 1, goodHeaders("/after-priority"), true)
	})
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v) for PRIORITY on an idle stream, which §5.1 permits", rc.goAwayCode)
	}
	if rc.sawRST {
		t.Errorf("RST_STREAM(%v) for PRIORITY on an idle stream", rc.rstCode)
	}
}

// TestConformance_RFC9113_Sec51_HalfClosedRemote_DataAfterEndStream pins
// rfc9113.txt:1044. The stream stays registered after END_STREAM because the
// server has not yet written its response — that is the half-closed (remote)
// state — and body bytes arriving in it used to be delivered to the handler
// behind its own EOF.
func TestConformance_RFC9113_Sec51_HalfClosedRemote_DataAfterEndStream(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, goodHeaders("/"), true) // END_STREAM
		_, _ = cli.Write(rawFrame(frame.FrameData, 0, 1, []byte("smuggled")))
	})
	if !rc.sawRST {
		t.Fatalf("no RST_STREAM for DATA after END_STREAM (sawGoAway=%v code=%v)",
			rc.sawGoAway, rc.goAwayCode)
	}
	if rc.rstCode != frame.ErrCodeStreamClosed {
		t.Errorf("RST_STREAM code = %v, want STREAM_CLOSED", rc.rstCode)
	}
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v); §5.1 scopes half-closed (remote) violations to the stream",
			rc.goAwayCode)
	}
}

// TestConformance_RFC9113_Sec51_HalfClosedRemote_HeadersAfterEndStream covers
// the same rule for a field section, and guards the trap that makes rejecting
// one safe at all.
//
// The rejected block is encoded so it inserts into the client encoder's dynamic
// table; a later request on stream 3 then references that entry by index. If the
// server resets the stream before feeding the block to its shared decoder, its
// table falls one entry behind and stream 3 decodes something else — silently,
// on a different stream, long after the mistake.
func TestConformance_RFC9113_Sec51_HalfClosedRemote_HeadersAfterEndStream(t *testing.T) {
	rc := runRawProbe(t, ServerConnOptions{}, func(_ net.Conn, cliFr *frame.Framer) {
		enc := hpack.NewEncoder() // one persistent encoder, as a real client has

		send := func(id uint32, fields []hpack.HeaderField, endStream bool) {
			block := enc.EncodeBlock(nil, fields)
			w := make(chan error, 1)
			go func() {
				w <- cliFr.WriteHeaders(frame.WriteHeadersParams{
					StreamID: id, BlockFragment: block, EndHeaders: true, EndStream: endStream,
				})
			}()
			<-w
		}

		send(1, goodHeaders("/"), true)
		// A second field section on stream 1, whose x-mark field the encoder adds
		// to its dynamic table.
		send(1, []hpack.HeaderField{{Name: []byte("x-mark"), Value: []byte("v1")}}, true)
		// Stream 3 repeats x-mark: the encoder emits it as an index into the entry
		// added above, so this only decodes correctly if the rejected block reached
		// the server's decoder.
		send(3, append(goodHeaders("/after"), hpack.HeaderField{Name: []byte("x-mark"), Value: []byte("v1")}), true)
	})
	if !rc.sawRST {
		t.Fatalf("no RST_STREAM for a field section after END_STREAM (sawGoAway=%v code=%v)",
			rc.sawGoAway, rc.goAwayCode)
	}
	if rc.rstCode != frame.ErrCodeStreamClosed {
		t.Errorf("RST_STREAM code = %v, want STREAM_CLOSED", rc.rstCode)
	}
	if rc.sawGoAway && rc.goAwayCode == frame.ErrCodeCompressionError {
		t.Errorf("GOAWAY(COMPRESSION_ERROR): the rejected field section was not fed to the " +
			"shared HPACK decoder, so its dynamic table desynced from the client's encoder")
	}
}

// TestConformance_RFC9113_Sec69_DataOnRetiredStreamCountsAgainstConnectionWindow
// pins rfc9113.txt:2113. The stream-level window dies with the stream; the
// connection-level one does not, and the peer has already spent those octets
// from its own send window.
//
// Left unaccounted this is not a bookkeeping nit but a stall: connection credit
// is consumed and never refunded, so a peer that keeps sending body bytes after
// a reset drains the window to zero and wedges every stream on the connection.
func TestConformance_RFC9113_Sec69_DataOnRetiredStreamCountsAgainstConnectionWindow(t *testing.T) {
	const chunk = 16384
	seen := runWindowProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer, seen *flowCapture) {
		// A field value carrying CR is malformed (RFC 9110 §5.5), so the server
		// answers RST_STREAM(PROTOCOL_ERROR) and retires stream 1.
		sendReq(t, cliFr, 1, append(goodHeaders("/"),
			hpack.HeaderField{Name: []byte("x-bad"), Value: []byte("a\rb")}), false)
		deadline := time.After(2 * time.Second)
		for !seen.sawReset() {
			select {
			case <-deadline:
				t.Error("server never reset the malformed stream")
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		// Two full frames: 32768 octets, exactly recvWindowRefundThreshold, so a
		// conformant receiver owes a connection WINDOW_UPDATE.
		for range 2 {
			_, _ = cli.Write(rawFrame(frame.FrameData, 0, 1, make([]byte, chunk)))
		}
	})

	if got := seen.connTotal(); got < 2*chunk {
		t.Errorf("connection WINDOW_UPDATE total = %d, want >= %d; DATA on a retired stream "+
			"was never counted against the connection window, so its credit is gone for good",
			got, 2*chunk)
	}
	if inc := seen.streamTotal(1); inc > 0 {
		t.Errorf("WINDOW_UPDATE(stream 1, %d) for a stream that no longer exists; "+
			"§5.1 forbids sending frames other than PRIORITY on a closed stream", inc)
	}
}

// TestConformance_RFC9113_Sec69_LiveStreamRefundsOnlyWhatWasRead pins the split
// between the two windows, which is not symmetric and must not be made so.
//
// The CONNECTION window is refunded on receipt: §6.9.1 requires every
// flow-controlled frame be counted there whatever becomes of its stream, and
// withholding it until some application reads would let one slow handler wedge
// every other stream on the connection.
//
// The PER-STREAM window is refunded on CONSUMPTION. Refunding it on receipt was
// what made SETTINGS_INITIAL_WINDOW_SIZE meaningless — see
// TestConformance_RFC9113_Sec521_WindowBoundsUnconsumedData, which is the
// failure that produced.
func TestConformance_RFC9113_Sec69_LiveStreamRefundsOnlyWhatWasRead(t *testing.T) {
	const chunk = 16384
	seen := runWindowProbe(t, ServerConnOptions{}, func(cli net.Conn, cliFr *frame.Framer, _ *flowCapture) {
		sendReq(t, cliFr, 1, goodHeaders("/upload"), false)
		for range 2 {
			_, _ = cli.Write(rawFrame(frame.FrameData, 0, 1, make([]byte, chunk)))
		}
	})
	// Nothing in this probe accepts the stream, so nothing has read the body.
	if got := seen.connTotal(); got < 2*chunk {
		t.Errorf("connection WINDOW_UPDATE total = %d, want >= %d: the connection window "+
			"is owed for every flow-controlled frame that arrives", got, 2*chunk)
	}
	if got := seen.streamTotal(1); got != 0 {
		t.Errorf("stream 1 WINDOW_UPDATE total = %d, want 0: no application has read "+
			"these bytes, so the peer is owed no fresh per-stream credit", got)
	}
}
