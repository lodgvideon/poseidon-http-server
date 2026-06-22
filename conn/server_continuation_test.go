package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// runGoAwayProbe drives the client side with `attack`, captures the first
// GOAWAY the server emits, and returns its error code (0 on timeout). It
// mirrors the rapid-reset harness: a background reader observes server frames
// while `attack` writes the offending sequence.
func runGoAwayProbe(t *testing.T, opts ServerConnOptions, attack func(cliFr *frame.Framer)) frame.ErrCode {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()

	gotGoAway := make(chan goAwayCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			gc := &goAwayCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), gc); err != nil {
						return
					}
					if gc.code != 0 {
						select {
						case gotGoAway <- *gc:
						default:
						}
						return
					}
				}
			}()
			attack(cliFr)
			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
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
	case gc := <-gotGoAway:
		<-done
		return gc.code
	case <-time.After(4 * time.Second):
		<-done
		return 0
	}
}

// TestServerConn_Continuation_Interleaving_EmitsProtocolError verifies RFC 9113
// §6.10: a frame other than CONTINUATION arriving inside an open header block
// (HEADERS without END_HEADERS) is a connection PROTOCOL_ERROR.
func TestServerConn_Continuation_Interleaving_EmitsProtocolError(t *testing.T) {
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
	})
	code := runGoAwayProbe(t, ServerConnOptions{}.defaulted(), func(cliFr *frame.Framer) {
		_ = cliFr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      1,
			BlockFragment: block,
			EndHeaders:    false, // header block left open
			EndStream:     false,
		})
		// Illegal interleave: a WINDOW_UPDATE inside the open header block.
		_ = cliFr.WriteWindowUpdate(0, 256)
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR (0x1) for frame interleaved in a header block", code)
	}
}

// TestServerConn_Continuation_OversizedBlock_EmitsProtocolError verifies the
// CONTINUATION-flood (CVE-2024-27316) defense: a header block whose accumulated
// compressed size exceeds the cap is rejected with a connection PROTOCOL_ERROR
// instead of growing memory without bound.
func TestServerConn_Continuation_OversizedBlock_EmitsProtocolError(t *testing.T) {
	enc := hpack.NewEncoder()
	first := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
	})
	// Advertise a small MaxHeaderListSize so a single CONTINUATION trips the cap.
	opts := ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxHeaderListSize: 4096},
	}.defaulted()
	junk := make([]byte, 5000) // pushes the block past the 4096 cap

	code := runGoAwayProbe(t, opts, func(cliFr *frame.Framer) {
		_ = cliFr.WriteHeaders(frame.WriteHeadersParams{
			StreamID:      1,
			BlockFragment: first,
			EndHeaders:    false,
			EndStream:     false,
		})
		// Still no END_HEADERS — the flood pattern. The cap trips here.
		_ = cliFr.WriteContinuation(1, false, junk)
	})
	if code != frame.ErrCodeProtocolError {
		t.Fatalf("GOAWAY code = %v, want PROTOCOL_ERROR (0x1) for oversized header block", code)
	}
}
