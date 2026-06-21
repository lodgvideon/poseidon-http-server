package grpcserver

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzDecodeLP feeds arbitrary bytes to the gRPC length-prefixed-message
// decoder. The decoder must NEVER panic: on malformed, truncated, or
// oversized input it must return an error; on well-formed input it must
// return a message whose declared length matches its payload.
func FuzzDecodeLP(f *testing.F) {
	// Seed corpus: valid + boundary inputs.
	mkLP := func(flag byte, n uint32, payload []byte) []byte {
		hdr := make([]byte, 5)
		hdr[0] = flag
		binary.BigEndian.PutUint32(hdr[1:5], n)
		return append(hdr, payload...)
	}

	f.Add([]byte(nil))                              // empty
	f.Add([]byte{0x00})                             // 1 byte, truncated header
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})           // 4 bytes, truncated header
	f.Add(mkLP(FlagNone, 0, nil))                   // valid zero-length message
	f.Add(mkLP(FlagNone, 5, []byte("hello")))       // valid message
	f.Add(mkLP(FlagCompressed, 3, []byte("abc")))   // valid compressed flag
	f.Add(mkLP(FlagNone, 4, []byte("ab")))          // declared len > available
	f.Add(mkLP(0xFF, 1, []byte("x")))               // unknown flag byte
	f.Add(mkLP(FlagNone, 0xFFFFFFFF, []byte("ab"))) // oversized length claim
	// maxRecvMessageSize boundary (4 MiB) with no payload following.
	f.Add(mkLP(FlagNone, maxRecvMessageSize, nil))
	f.Add(mkLP(FlagNone, maxRecvMessageSize+1, nil)) // just over the limit

	f.Fuzz(func(t *testing.T, data []byte) {
		// Streaming reader path.
		r := bytes.NewReader(data)
		msg, err := DecodeLP(r)
		if err == nil {
			// On success, payload length must be consistent and bounded.
			if len(msg.Payload) > maxRecvMessageSize {
				t.Fatalf("DecodeLP returned payload exceeding maxRecvMessageSize: %d", len(msg.Payload))
			}
			// A successful decode must have consumed the 5-byte header plus
			// exactly len(Payload) bytes; verify there is enough input.
			if len(data) < 5+len(msg.Payload) {
				t.Fatalf("DecodeLP succeeded but input %d shorter than header+payload %d",
					len(data), 5+len(msg.Payload))
			}
		}

		// Byte-slice path: must also never panic and must agree on length.
		msg2, n, err2 := DecodeLPFromBytes(data)
		if err2 == nil {
			if n < grpcMessageHeader || n > len(data) {
				t.Fatalf("DecodeLPFromBytes returned out-of-range consumed=%d for input len=%d", n, len(data))
			}
			if n != grpcMessageHeader+len(msg2.Payload) {
				t.Fatalf("DecodeLPFromBytes consumed=%d but header+payload=%d", n, grpcMessageHeader+len(msg2.Payload))
			}
		}

		// Round-trip: anything we successfully decode must re-encode to the
		// same wire bytes (header + payload) the decoder consumed.
		if err == nil {
			enc := EncodeLP(nil, msg)
			want := data[:5+len(msg.Payload)]
			if !bytes.Equal(enc, want) {
				t.Fatalf("EncodeLP round-trip mismatch:\n enc=%x\nwant=%x", enc, want)
			}
		}
	})
}

// FuzzTrailersToStatus fuzzes the gRPC status-trailer parser. It must never
// panic on arbitrary grpc-status / grpc-message values (the grpc-status value
// is parsed as an integer and arbitrary text must yield a well-formed status,
// not a crash).
func FuzzTrailersToStatus(f *testing.F) {
	f.Add("0", "")
	f.Add("13", "internal error")
	f.Add("", "")
	f.Add("not-a-number", "boom")
	f.Add("-1", "negative")
	f.Add("4294967296", "overflow uint32")
	f.Add("99999999999999999999999999", "overflow int64")
	f.Add("16", "unauthenticated")
	f.Add("\x00\x01\x02", "binary status")

	f.Fuzz(func(t *testing.T, statusVal, msgVal string) {
		trailers := [][2]string{
			{HeaderGRPCStatus, statusVal},
			{HeaderGRPCMessage, msgVal},
		}
		st := TrailersToStatus(trailers)
		// Error() must be callable without panicking and must produce a
		// non-empty string (it always interpolates the code name).
		if got := st.Error(); got == "" {
			t.Fatalf("RPCStatus.Error() returned empty string for status=%q msg=%q", statusVal, msgVal)
		}
		// Code.String() must never panic for any code value.
		_ = st.Code.String()
	})
}
