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

// Conformance tests for oversized request field sections.
//
// RFC 9110 §5.4: "A server that receives a request header field line, field
// value, or set of fields larger than it wishes to process MUST respond with an
// appropriate 4xx (Client Error) status code. Ignoring such header fields would
// increase the server's vulnerability to request smuggling attacks."
//
// The server answered with no status at all: it tore the whole connection down
// with GOAWAY(PROTOCOL_ERROR), which tells the client nothing about its request
// and kills every unrelated stream in flight. The 4xx chosen is 431 (Request
// Header Fields Too Large, RFC 6585 §5) — note that 431 is not defined in
// RFC 9110, which requires only "an appropriate 4xx".
//
// The limit the server "wishes to process" is SETTINGS_MAX_HEADER_LIST_SIZE,
// which RFC 9113 §6.5.2 defines over the UNCOMPRESSED field list, hence the
// per-field accounting rather than a check on the encoded block.

// respState is what a probe observed. Kept free of the mutex so it can be
// copied out of the capture without vet objecting.
type respState struct {
	status     string
	streamID   uint32
	sawHeaders bool
	goAwayCode frame.ErrCode
	sawGoAway  bool
}

// respCapture records response HEADERS and GOAWAY.
//
// Guarded: the reader runs in its own goroutine and the probe may give up on a
// timeout while it is still going, so the snapshot has to be taken under the
// same lock the callbacks write under.
type respCapture struct {
	mu  sync.Mutex
	st  respState
	dec *hpack.Decoder
}

func (c *respCapture) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dec == nil {
		c.dec = hpack.NewDecoder()
	}
	c.st.streamID, c.st.sawHeaders = fh.StreamID, true
	return c.dec.DecodeBlock(hb, hpack.FieldVisitor(func(f hpack.HeaderField) error {
		if string(f.Name) == ":status" {
			c.st.status = string(f.Value)
		}
		return nil
	}))
}

func (c *respCapture) OnGoAway(_ frame.FrameHeader, _ uint32, code frame.ErrCode, _ []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st.goAwayCode, c.st.sawGoAway = code, true
	return nil
}

func (c *respCapture) snapshot() respState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (c *respCapture) goneAway() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.sawGoAway
}

func (c *respCapture) OnData(frame.FrameHeader, []byte, uint8) error            { return nil }
func (c *respCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (c *respCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error       { return nil }
func (c *respCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (c *respCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (c *respCapture) OnPing(frame.FrameHeader, [8]byte) error                   { return nil }
func (c *respCapture) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (c *respCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (c *respCapture) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (c *respCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }

// runRespProbe drives the client with attack and returns the first response
// HEADERS and/or GOAWAY the server sends.
func runRespProbe(t *testing.T, opts ServerConnOptions, attack func(cliFr *frame.Framer)) respState {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()

	result := make(chan respState, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			rc := &respCapture{}
			go func() {
				defer close(readDone)
				// Read until the connection goes or the deadline: on the
				// flood path the 431 arrives BEFORE the GOAWAY, so stopping at
				// the first frame would hide the teardown under test.
				for {
					if _, err := cliFr.ReadFrame(context.Background(), rc); err != nil {
						return
					}
					if rc.goneAway() {
						return
					}
				}
			}()
			attack(cliFr)
			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
			select {
			case result <- rc.snapshot():
			default:
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, opts)
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case rc := <-result:
		<-done
		return rc
	case <-time.After(4 * time.Second):
		<-done
		return respState{}
	}
}

func bigFieldRequest(padTo int) []hpack.HeaderField {
	h := []hpack.HeaderField{
		hf(":method", "GET"),
		hf(":scheme", "https"),
		hf(":path", "/"),
		hf(":authority", "example.com"),
	}
	// Distinct names so the encoder cannot collapse them to indexed references:
	// the point is an oversized UNCOMPRESSED list, not an oversized block.
	for i := 0; len(h)*32 < padTo; i++ {
		name := "x-pad-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
		h = append(h, hf(name, "0123456789012345678901234567890123456789"))
	}
	return h
}

// TestConformance_RFC9110_Sec54_OversizedFieldsGet431 pins the MUST: an
// answer, on the stream, and the connection left alone.
func TestConformance_RFC9110_Sec54_OversizedFieldsGet431(t *testing.T) {
	opts := ServerConnOptions{}.defaulted()
	opts.AdvertisedSettings.MaxHeaderListSize = 4 << 10

	rc := runRespProbe(t, opts, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, bigFieldRequest(8<<10), true)
	})

	if !rc.sawHeaders {
		t.Fatalf("no response HEADERS for an oversized field section (goaway=%v code=%v); "+
			"RFC 9110 §5.4 requires an appropriate 4xx", rc.sawGoAway, rc.goAwayCode)
	}
	if rc.status != "431" {
		t.Errorf(":status = %q, want 431 (RFC 6585 §5)", rc.status)
	}
	if rc.streamID != 1 {
		t.Errorf("response on stream %d, want 1", rc.streamID)
	}
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v): an oversized request is one stream's problem, not the "+
			"connection's — unrelated streams in flight must survive", rc.goAwayCode)
	}
}

// TestConformance_RFC9110_Sec54_WithinLimitUnaffected is the control: the
// budget must not fire on an ordinary request.
func TestConformance_RFC9110_Sec54_WithinLimitUnaffected(t *testing.T) {
	opts := ServerConnOptions{}.defaulted()
	opts.AdvertisedSettings.MaxHeaderListSize = 32 << 10

	rc := runRespProbe(t, opts, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, vHeaders(), true)
	})
	if rc.status == "431" {
		t.Error("431 for a request well inside the advertised limit")
	}
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v) for an ordinary request", rc.goAwayCode)
	}
}

// TestConformance_RFC9110_Sec54_ContinuationFloodAnswers431 covers the hard
// CVE-2024-27316 cap, where the server refuses to keep decoding at all. The
// connection still has to go — that is the whole defence — but the client is
// owed a status first, and a large well-formed block is not a protocol error,
// so the GOAWAY code is ENHANCE_YOUR_CALM rather than PROTOCOL_ERROR.
func TestConformance_RFC9110_Sec54_ContinuationFloodAnswers431(t *testing.T) {
	opts := ServerConnOptions{}.defaulted()
	opts.AdvertisedSettings.MaxHeaderListSize = 4 << 10

	rc := runRespProbe(t, opts, func(cliFr *frame.Framer) {
		enc := hpack.NewEncoder()
		block := enc.EncodeBlock(nil, vHeaders())
		_ = cliFr.WriteHeaders(frame.WriteHeadersParams{
			StreamID: 1, BlockFragment: block, EndHeaders: false, EndStream: false,
		})
		// CONTINUATION frames with no END_HEADERS, past the compressed cap.
		//
		// Written from a goroutine on purpose: net.Pipe is synchronous, so once
		// the server stops reading — which is the behaviour under test — a
		// blocking write here would never return and the probe would hang
		// instead of reporting.
		go func() {
			pad := make([]byte, 2<<10)
			for range 8 {
				if err := cliFr.WriteContinuation(1, false, pad); err != nil {
					return
				}
			}
		}()
	})

	if !rc.sawGoAway {
		t.Fatalf("no GOAWAY for a CONTINUATION flood; the connection must go")
	}
	if rc.goAwayCode != frame.ErrCodeEnhanceYourCalm {
		t.Errorf("GOAWAY code = %v, want ENHANCE_YOUR_CALM — an oversized but "+
			"well-formed field block is not a protocol violation", rc.goAwayCode)
	}
}
