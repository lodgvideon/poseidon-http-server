package conn

import (
	"net"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// Conformance tests for HPACK decoding failures.
//
//	RFC 9113 §4.3 — "A decoding error in a field block MUST be
//	treated as a connection error (Section 5.4.1) of type COMPRESSION_ERROR."
//
// The rule is absolute for a reason that is easy to miss: field blocks are
// decoded against one dynamic table shared by every stream on the connection.
// Once a block fails to decode, that table has diverged from the peer's encoder
// and no later stream on the connection can be trusted — so there is no such
// thing as containing the damage to one stream.

// TestConformance_RFC9113_Sec43_HPACKDecodeError_IsAConnectionError pins
// RFC 9113 §4.3. A corrupt field block must produce GOAWAY(COMPRESSION_ERROR),
// never RST_STREAM.
//
// The distinction is not cosmetic. RST_STREAM(CANCEL) is what this server used
// to send, and CANCEL tells a client its request was cancelled — an invitation
// to retry on a connection whose HPACK state is already unrecoverable.
func TestConformance_RFC9113_Sec43_HPACKDecodeError_IsAConnectionError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		// 0xbf = indexed field, index 63. The static table ends at 61 and the
		// dynamic table is empty on a fresh connection, so this cannot resolve.
		{"indexed_field_out_of_range", []byte{0xbf}},
		// 0x00 starts a literal without indexing whose name is a length-prefixed
		// string; 0x7f announces a 127-octet name that is not there.
		{"truncated_string_literal", []byte{0x00, 0x7f}},
		// 0x00 with a Huffman-coded name (0x80 flag) of 1 octet: 0xff is a prefix
		// of the EOS symbol, not a decodable code.
		{"invalid_huffman_sequence", []byte{0x00, 0x81, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := runRawProbe(t, ServerConnOptions{}, func(cli net.Conn, _ *frame.Framer) {
				_, _ = cli.Write(rawFrame(frame.FrameHeaders,
					frame.FlagHeadersEndHeaders|frame.FlagHeadersEndStream, 1, tc.block))
			})
			if !rc.sawGoAway {
				t.Fatalf("no GOAWAY for a field block that cannot be decoded "+
					"(sawRST=%v rstCode=%v); RFC 9113 §4.3 makes this a connection error",
					rc.sawRST, rc.rstCode)
			}
			if rc.goAwayCode != frame.ErrCodeCompressionError {
				t.Errorf("GOAWAY code = %v, want COMPRESSION_ERROR", rc.goAwayCode)
			}
			if rc.sawRST {
				t.Errorf("RST_STREAM(%v) for a decoding error; resetting one stream implies "+
					"the connection is still usable, and after an HPACK failure it is not",
					rc.rstCode)
			}
		})
	}
}
