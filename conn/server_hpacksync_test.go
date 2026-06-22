package conn

import (
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestServerConnHandler_RefusedStream_KeepsHPACKDecoderSynced is the regression
// guard for the blocker the adversarial review caught: a stream refused over
// MaxConcurrentStreams must still feed its HEADERS block to the shared HPACK
// decoder, or the decoder's dynamic table desyncs from the client's encoder and
// every subsequent stream on the connection decodes corrupt headers.
//
// It drives the handler with ONE shared encoder (incremental indexing, like a
// real persistent client): stream 1 introduces x-trace, the refused stream adds
// a second x-trace value that SHIFTS the dynamic-table indices, then a later
// accepted stream sends an indexed reference that resolves correctly only if the
// refused block was decoded. The pre-fix code returned before decoding the
// refused block, so this test would observe "A" instead of "B".
func TestServerConnHandler_RefusedStream_KeepsHPACKDecoderSynced(t *testing.T) {
	mock := &mockConnOps{
		streams:     make(map[uint32]*ServerStream),
		refuseAfter: 1, // only one concurrent stream allowed
	}
	h := newServerConnHandler(mock, hpack.NewDecoder(), 0)
	enc := hpack.NewEncoder() // one shared encoder across all streams

	hdr := func(id uint32) frame.FrameHeader {
		return frame.FrameHeader{StreamID: id, Flags: frame.FlagHeadersEndHeaders}
	}
	block := func(traceVal string) frame.HeaderBlock {
		return enc.EncodeBlock(nil, []hpack.HeaderField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte("x-trace"), Value: []byte(traceVal)},
		})
	}

	// Stream 1 (accepted): introduces x-trace:A into the encoder AND decoder
	// dynamic tables.
	if err := h.OnHeaders(hdr(1), block("A"), nil, 0); err != nil {
		t.Fatalf("OnHeaders(1): %v", err)
	}

	// Stream 3 (refused — len already 1): the encoder adds x-trace:B, shifting
	// x-trace:A down by one dynamic-table index. The decoder MUST process this
	// block too, or its table diverges from the encoder's.
	if err := h.OnHeaders(hdr(3), block("B"), nil, 0); err != nil {
		t.Fatalf("OnHeaders(3) refused path returned error: %v", err)
	}
	if _, ok := mock.streams[3]; ok {
		t.Fatal("refused stream 3 should not have been registered")
	}

	// Free a slot so the next stream is accepted.
	mock.markStreamDone(1)

	// Stream 5 (accepted): x-trace:B is now in the encoder's dynamic table, so
	// it is sent as an INDEXED reference. It decodes to "B" only if the decoder
	// processed the refused stream 3; otherwise the index resolves to "A".
	if err := h.OnHeaders(hdr(5), block("B"), nil, 0); err != nil {
		t.Fatalf("OnHeaders(5): %v", err)
	}
	s5 := mock.streams[5]
	if s5 == nil {
		t.Fatal("stream 5 should have been registered")
	}

	select {
	case ev := <-s5.events:
		var got string
		found := false
		for _, hf := range ev.Headers {
			if string(hf.Name) == "x-trace" {
				got, found = string(hf.Value), true
			}
		}
		if !found {
			t.Fatal("x-trace header missing from stream 5")
		}
		if got != "B" {
			t.Fatalf("x-trace on stream 5 decoded as %q, want %q — HPACK decoder desynced after the refused stream", got, "B")
		}
	default:
		t.Fatal("stream 5 produced no header event")
	}
}
