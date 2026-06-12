package grpcserver

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestEncodeDecodeLP round-trips a message.
func TestEncodeDecodeLP(t *testing.T) {
	msg := LPMessage{Flag: FlagNone, Payload: []byte("hello grpc")}
	encoded := EncodeLP(nil, msg)

	decoded, err := DecodeLP(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Flag != msg.Flag {
		t.Errorf("flag = %d, want %d", decoded.Flag, msg.Flag)
	}
	if string(decoded.Payload) != string(msg.Payload) {
		t.Errorf("payload = %q, want %q", string(decoded.Payload), string(msg.Payload))
	}
}

// TestEncodeDecodeLP_Empty tests zero-length payload.
func TestEncodeDecodeLP_Empty(t *testing.T) {
	msg := LPMessage{Flag: FlagNone, Payload: nil}
	encoded := EncodeLP(nil, msg)

	decoded, err := DecodeLP(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Payload != nil {
		t.Errorf("payload = %v, want nil", decoded.Payload)
	}
}

// TestEncodeDecodeLP_Compressed tests the compressed flag.
func TestEncodeDecodeLP_Compressed(t *testing.T) {
	msg := LPMessage{Flag: FlagCompressed, Payload: []byte("compressed-data")}
	encoded := EncodeLP(nil, msg)

	decoded, err := DecodeLP(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Flag != FlagCompressed {
		t.Errorf("flag = %d, want %d", decoded.Flag, FlagCompressed)
	}
}

// TestDecodeLP_Multiple reads multiple messages from one stream.
func TestDecodeLP_Multiple(t *testing.T) {
	var buf []byte
	buf = EncodeLP(buf, LPMessage{Flag: 0, Payload: []byte("msg1")})
	buf = EncodeLP(buf, LPMessage{Flag: 0, Payload: []byte("msg2")})
	buf = EncodeLP(buf, LPMessage{Flag: 1, Payload: []byte("msg3")})

	r := bytes.NewReader(buf)

	m1, err := DecodeLP(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(m1.Payload) != "msg1" {
		t.Errorf("msg1 = %q", string(m1.Payload))
	}

	m2, err := DecodeLP(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(m2.Payload) != "msg2" {
		t.Errorf("msg2 = %q", string(m2.Payload))
	}

	m3, err := DecodeLP(r)
	if err != nil {
		t.Fatal(err)
	}
	if m3.Flag != 1 || string(m3.Payload) != "msg3" {
		t.Errorf("msg3 = flag=%d payload=%q", m3.Flag, string(m3.Payload))
	}

	// EOF after all messages.
	_, err = DecodeLP(r)
	if !errors.Is(err, io.EOF) {
		t.Errorf("after end: err = %v, want EOF", err)
	}
}

// TestDecodeLP_TooLarge verifies size limit.
func TestDecodeLP_TooLarge(t *testing.T) {
	// Encode a message claiming 100 bytes but provide them.
	large := make([]byte, 200)
	large[0] = 0 // flag
	large[1] = 0 // length big-endian: 100
	large[2] = 0
	large[3] = 0
	large[4] = 100

	_, err := DecodeLPWithLimit(bytes.NewReader(large), 50)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("err = %v, want ErrMessageTooLarge", err)
	}
}

// TestDecodeLPFromBytes tests byte-slice decoder.
func TestDecodeLPFromBytes(t *testing.T) {
	msg := LPMessage{Flag: 0, Payload: []byte("bytes-test")}
	encoded := EncodeLP(nil, msg)

	decoded, n, err := DecodeLPFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(encoded) {
		t.Errorf("consumed = %d, want %d", n, len(encoded))
	}
	if string(decoded.Payload) != "bytes-test" {
		t.Errorf("payload = %q", string(decoded.Payload))
	}
}

// TestDecodeLPFromBytes_Truncated verifies error on incomplete data.
func TestDecodeLPFromBytes_Truncated(t *testing.T) {
	_, _, err := DecodeLPFromBytes([]byte{0x00, 0x00}) // too short
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("err = %v, want ErrInvalidHeader", err)
	}
}

// TestEncodeLP_Append verifies EncodeLP appends to dst.
func TestEncodeLP_Append(t *testing.T) {
	dst := []byte("prefix-")
	result := EncodeLP(dst, LPMessage{Flag: 0, Payload: []byte("data")})

	if string(result[:7]) != "prefix-" {
		t.Error("prefix lost")
	}
	if string(result[12:]) != "data" {
		t.Errorf("payload = %q", string(result[12:]))
	}
}

// BenchmarkEncodeLP measures encoding throughput.
func BenchmarkEncodeLP(b *testing.B) {
	msg := LPMessage{Flag: 0, Payload: make([]byte, 1024)}
	b.ResetTimer()
	for range b.N {
		_ = EncodeLP(nil, msg)
	}
}

// BenchmarkDecodeLP measures decoding throughput.
func BenchmarkDecodeLP(b *testing.B) {
	msg := LPMessage{Flag: 0, Payload: make([]byte, 1024)}
	encoded := EncodeLP(nil, msg)
	b.ResetTimer()
	for range b.N {
		_, _ = DecodeLP(bytes.NewReader(encoded))
	}
}
