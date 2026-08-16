package conn

import (
	"bytes"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Regression guard for an HPACK Huffman table defect that once shipped in this
// server's codec dependency: the RFC 7541 Appendix B entry for symbol 249 read
// {0xfffffe, 28} where the RFC gives {0xffffffe, 28}. The declared bit length
// was right and the code was one hex digit short, which made the table
// non-prefix-free — the truncated code begins 00001, and 00001 is already the
// complete 5-bit code for '1' (0x31). A header value containing byte 0xf9
// therefore encoded to bits that decoded back as a different, longer byte
// string with err == nil: silent corruption rather than a decode error, in both
// directions, and on HTTP/3 as well as HTTP/2 since qpack reuses this table.
//
// The upstream fix predates the version this repository pins — it was already
// present at v0.11.0, the version the accompanying bump moves off — so these
// tests are green on arrival and are a guard, not a fix. They exist because
// nothing else here would catch a recurrence: every conformance and integration
// suite in this repository uses header values from the ASCII range, which the
// short codes cover, so the whole high half of the alphabet is untested.
//
// Deliberately written against hpack.HuffmanEncode/HuffmanDecode rather than
// against hpack.Encoder. That is the load-bearing detail, not a shortcut:
// hpack.Encoder never emits the Huffman form — its encodeStringLiteral is
// called with huffman=false on every path, because for most header values the
// coded form is longer than the literal. An Encoder -> Decoder round trip
// therefore never touches the Huffman table at all, and passes just as happily
// with the table corrupted. Do not "simplify" these into an Encoder round trip;
// that would silently remove the only coverage this codec has here.
//
// Both tests were confirmed to fail against the historical table before being
// committed: with symbol 249 reverted to {0xfffffe, 28},
// TestHuffmanRoundTrip_Byte0xF9 reports
// "round trip changed the value: encoded 0fffffef -> decoded 31fd, want f9".

// huffmanRoundTrip encodes in, decodes it back, and requires the value to
// survive unchanged. It also requires HuffmanEncodedLen to agree with the byte
// count HuffmanEncode actually produced: a misdeclared bit length shows up
// there even in the cases where the decode happens to resynchronise.
func huffmanRoundTrip(t *testing.T, in []byte) {
	t.Helper()
	encoded := hpack.HuffmanEncode(nil, in)
	if got, want := hpack.HuffmanEncodedLen(in), len(encoded); got != want {
		t.Errorf("HuffmanEncodedLen(%x) = %d, but HuffmanEncode produced %d bytes", in, got, want)
	}
	decoded, err := hpack.HuffmanDecode(nil, encoded)
	if err != nil {
		t.Fatalf("HuffmanDecode(HuffmanEncode(%x)) failed: %v", in, err)
	}
	if !bytes.Equal(decoded, in) {
		t.Fatalf("round trip changed the value: encoded %x -> decoded %x, want %x", encoded, decoded, in)
	}
}

// TestHuffmanRoundTrip_Byte0xF9 pins the exact byte the defect corrupted, alone
// and embedded in a realistic header value.
func TestHuffmanRoundTrip_Byte0xF9(t *testing.T) {
	huffmanRoundTrip(t, []byte{0xf9})
	huffmanRoundTrip(t, []byte("x-trace-id-\xf9-suffix"))
	// Repeated, so a mis-decode compounds rather than cancelling out.
	huffmanRoundTrip(t, bytes.Repeat([]byte{0xf9}, 8))
}

// TestHuffmanRoundTrip_AllByteValues sweeps the whole alphabet. Symbol 249 is
// the entry that was wrong, but pinning only that one guards the single
// transcription error already known about; this guards every other entry
// against the same class of typo.
func TestHuffmanRoundTrip_AllByteValues(t *testing.T) {
	for b := range 256 {
		huffmanRoundTrip(t, []byte{byte(b)})
		// Pairs as well: a code whose length is misdeclared can still round
		// trip in isolation, because the trailing EOS padding absorbs the
		// discrepancy at the byte boundary. A following symbol removes that
		// slack — this is the arm that caught the historical table with a hard
		// "invalid Huffman code" rather than a silent value change.
		huffmanRoundTrip(t, []byte{byte(b), byte(255 - b)})
	}
}
