package grpcserver

import (
	"encoding/binary"
	"errors"
	"io"
)

// ---------------------------------------------------------------------------
// gRPC Length-Prefixed Message framing (RFC spec: gRPC over HTTP/2)
//
// Wire format per message:
//   +------------------+--------------------+
//   | Compress-Flag(1) | Message-Length(4)   | Message(N)        |
//   +------------------+--------------------+-------------------+
//   | 0x00 or 0x01     | big-endian uint32  | protobuf bytes    |
//   +------------------+--------------------+-------------------+
// ---------------------------------------------------------------------------

const (
	// grpcMessageHeader is the 5-byte prefix: 1 flag + 4 length.
	grpcMessageHeader = 5

	// maxRecvMessageSize is the default maximum receive message size (4 MB).
	maxRecvMessageSize = 4 * 1024 * 1024

	// FlagNone means no compression.
	FlagNone byte = 0x00

	// FlagCompressed means the payload is compressed.
	FlagCompressed byte = 0x01
)

var (
	// ErrMessageTooLarge is returned when a message exceeds MaxRecvMessageSize.
	ErrMessageTooLarge = errors.New("grpcserver: message too large")

	// ErrInvalidHeader is returned when the LP header is malformed.
	ErrInvalidHeader = errors.New("grpcserver: invalid message header")
)

// LPMessage is a decoded gRPC Length-Prefixed Message.
type LPMessage struct {
	Flag    byte   // 0x00 = raw, 0x01 = compressed
	Payload []byte // message bytes (may be compressed)
}

// EncodeLP encodes a gRPC Length-Prefixed Message into dst.
// dst is grown if needed. Returns the written slice.
func EncodeLP(dst []byte, msg LPMessage) []byte {
	n := len(msg.Payload)
	// Prepend header: flag(1) + length(4)
	buf := make([]byte, 0, grpcMessageHeader+n)
	buf = append(buf, msg.Flag)
	buf = append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	buf = append(buf, msg.Payload...)
	return append(dst, buf...)
}

// DecodeLP reads one gRPC Length-Prefixed Message from r.
// Returns the decoded message or an error.
func DecodeLP(r io.Reader) (LPMessage, error) {
	return DecodeLPWithLimit(r, maxRecvMessageSize)
}

// DecodeLPWithLimit reads one LP message with a custom max size.
func DecodeLPWithLimit(r io.Reader, maxSize int) (LPMessage, error) {
	hdr := make([]byte, grpcMessageHeader)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return LPMessage{}, err
	}

	flag := hdr[0]
	length := int(binary.BigEndian.Uint32(hdr[1:5]))

	if length > maxSize {
		return LPMessage{}, ErrMessageTooLarge
	}
	if length == 0 {
		return LPMessage{Flag: flag, Payload: nil}, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return LPMessage{}, err
	}

	return LPMessage{Flag: flag, Payload: payload}, nil
}

// DecodeLPFromBytes decodes one LP message from a byte slice.
// Returns the message and the number of bytes consumed.
func DecodeLPFromBytes(data []byte) (LPMessage, int, error) {
	if len(data) < grpcMessageHeader {
		return LPMessage{}, 0, ErrInvalidHeader
	}

	flag := data[0]
	length := int(binary.BigEndian.Uint32(data[1:5]))

	// Enforce the message-size limit consistently with DecodeLP/DecodeLPWithLimit
	// so the byte-slice path cannot return an over-limit payload. Checking this
	// before the comparison below also avoids any grpcMessageHeader+length overflow.
	if length > maxRecvMessageSize {
		return LPMessage{}, 0, ErrMessageTooLarge
	}
	if len(data) < grpcMessageHeader+length {
		return LPMessage{}, 0, ErrInvalidHeader
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		copy(payload, data[grpcMessageHeader:grpcMessageHeader+length])
	}

	return LPMessage{Flag: flag, Payload: payload}, grpcMessageHeader + length, nil
}
