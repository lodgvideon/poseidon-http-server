package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// connError is a connection-fatal error returned by frame handler methods.
// When returned from a Handler callback the connection reader loop will
// send GOAWAY with the embedded error code and tear down the connection.
type connError struct {
	code frame.ErrCode
	msg  string
}

func (e connError) Error() string {
	return fmt.Sprintf("conn: connection error code=%v: %s", e.code, e.msg)
}

// transportErr reports whether err is the connection ending rather than the
// peer misbehaving: EOF, a closed socket or pipe, a deadline, a cancelled
// context. Nothing is owed to a peer that is already gone.
func transportErr(err error) bool {
	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// codecErrCode maps a frame-codec error to the HTTP/2 error code the peer is
// owed for it. ok is false only for a transport-level failure, where the
// connection is already gone.
//
// The codec detects a whole class of protocol violations the server's own
// handler callbacks never see — a frame larger than SETTINGS_MAX_FRAME_SIZE, a
// wrong-length RST_STREAM/PING/WINDOW_UPDATE, a SETTINGS length that is not a
// multiple of 6, a pad length that eats its own payload, a frame carrying a
// stream identifier the type forbids. It reports each as a plain sentinel
// carrying no error code, because only the receiver can decide what an error
// means for its role. RFC 9113 §5.4 — "If a frame causes a
// connection error, that error MUST be reported" — makes deciding mandatory,
// and this table is that decision.
//
// The default arm is deliberate rather than defensive. Not every rejection the
// codec makes is reachable by name: a pad length that eats its own payload is
// rejected with an `internal/bytesx` sentinel that no consumer can import
// (poseidon-http-client#402), so matching it by identity is impossible from
// here. PROTOCOL_ERROR is the right answer for "the peer sent something the
// codec refused and we cannot name it more precisely" — and it means a codec
// that grows a new sentinel reports something correct rather than nothing.
//
// Cold path: reached once per connection, or once per malformed frame.
func codecErrCode(err error) (frame.ErrCode, bool) {
	if transportErr(err) {
		return 0, false
	}
	switch {
	// RFC 9113 §4.2 — "An endpoint MUST send an error code of
	// FRAME_SIZE_ERROR if a frame exceeds the size defined in
	// SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or
	// is too small to contain mandatory frame data."
	//
	// ErrShortRead is a size error, not a truncated read: a genuinely truncated
	// transport read surfaces as io.ErrUnexpectedEOF from io.ReadFull inside the
	// codec. It is returned only when a frame is too small to hold its mandatory
	// fields (GOAWAY under 8 octets, HEADERS+PRIORITY under 5, PUSH_PROMISE
	// under 4) — the third clause of §4.2 verbatim.
	//
	// ErrSettingsLength is reported for two conditions upstream: a length that
	// is not a multiple of 6 (this code is right) and a legal frame carrying
	// more than 16 entries, which the codec cannot represent. The second is a
	// codec defect tracked at poseidon-http-client#401; such a frame is rejected
	// today either way, so naming a reason is still better than silence.
	case errors.Is(err, frame.ErrFrameTooLarge),
		errors.Is(err, frame.ErrPriorityWrongLength),
		errors.Is(err, frame.ErrRSTWrongLength),
		errors.Is(err, frame.ErrPingWrongLength),
		errors.Is(err, frame.ErrWindowWrongLength),
		errors.Is(err, frame.ErrSettingsLength),
		errors.Is(err, frame.ErrSettingsAck),
		errors.Is(err, frame.ErrShortRead):
		return frame.ErrCodeFrameSizeError, true

	// §6.1/§6.2/§6.4/§6.5/§6.7/§6.8/§6.9 each make a frame carrying a stream
	// identifier its type forbids — or omitting one its type requires — a
	// connection error of type PROTOCOL_ERROR; §6.1 says the
	// same of a pad length that is "the length of the frame payload or greater".
	case errors.Is(err, frame.ErrInvalidStreamID),
		errors.Is(err, frame.ErrInvalidPadding),
		errors.Is(err, frame.ErrZeroIncrement),
		errors.Is(err, frame.ErrProtocolError):
		return frame.ErrCodeProtocolError, true
	}
	return frame.ErrCodeProtocolError, true
}
