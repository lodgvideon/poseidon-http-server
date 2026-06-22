package grpcserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

func TestParseGRPCTimeout(t *testing.T) {
	hdr := func(v string) []hpack.HeaderField {
		return []hpack.HeaderField{{Name: []byte(HeaderGRPCTimeout), Value: []byte(v)}}
	}
	cases := []struct {
		val  string
		want time.Duration
		ok   bool
	}{
		{"100m", 100 * time.Millisecond, true},
		{"1S", time.Second, true},
		{"5H", 5 * time.Hour, true},
		{"30M", 30 * time.Minute, true},
		{"250u", 250 * time.Microsecond, true},
		{"99n", 99 * time.Nanosecond, true},
		{"99999999H", time.Duration(math.MaxInt64), true}, // overflow -> capped, not negative
		{"abc", 0, false},                                 // non-numeric value
		{"10x", 0, false},                                 // unknown unit
		{"S", 0, false},                                   // missing value
		{"", 0, false},                                    // empty
	}
	for _, c := range cases {
		got, ok := parseGRPCTimeout(hdr(c.val))
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseGRPCTimeout(%q) = (%v,%v), want (%v,%v)", c.val, got, ok, c.want, c.ok)
		}
	}
	// Absent header.
	if _, ok := parseGRPCTimeout(nil); ok {
		t.Error("parseGRPCTimeout(nil) ok = true, want false")
	}
}

func TestErrToStatus_ContextAndLimit(t *testing.T) {
	if got := errToStatus(context.DeadlineExceeded).Code; got != DeadlineExceeded {
		t.Errorf("DeadlineExceeded -> %v, want DeadlineExceeded", got)
	}
	if got := errToStatus(context.Canceled).Code; got != Canceled {
		t.Errorf("Canceled -> %v, want Canceled", got)
	}
	if got := errToStatus(ErrMessageTooLarge).Code; got != ResourceExhausted {
		t.Errorf("ErrMessageTooLarge -> %v, want ResourceExhausted", got)
	}
	// A plain error still maps to Internal.
	if got := errToStatus(errors.New("boom")).Code; got != Internal {
		t.Errorf("plain error -> %v, want Internal", got)
	}
}

func TestStreamReceiver_RejectsCompressed_Buffered(t *testing.T) {
	body := EncodeLP(nil, LPMessage{Flag: FlagCompressed, Payload: []byte("gzipped")})
	recv := streamReceiver(&server.Request{Body: body})
	_, err := recv()
	if errToStatus(err).Code != Unimplemented {
		t.Fatalf("compressed buffered message: status = %v, want Unimplemented", errToStatus(err).Code)
	}
}

func TestStreamReceiver_RejectsCompressed_Streaming(t *testing.T) {
	body := EncodeLP(nil, LPMessage{Flag: FlagCompressed, Payload: []byte("gzipped")})
	recv := streamReceiver(&server.Request{BodyReader: io.NopCloser(bytes.NewReader(body))})
	_, err := recv()
	if errToStatus(err).Code != Unimplemented {
		t.Fatalf("compressed streaming message: status = %v, want Unimplemented", errToStatus(err).Code)
	}
}

func TestStreamReceiver_EnforcesRecvLimit_Streaming(t *testing.T) {
	// LP header declaring a length one byte over the 4 MiB limit; the limit is
	// checked before any payload is read, so no payload bytes are needed.
	over := uint32(maxRecvMessageSize + 1)
	hdr := []byte{FlagNone, byte(over >> 24), byte(over >> 16), byte(over >> 8), byte(over)}
	recv := streamReceiver(&server.Request{BodyReader: io.NopCloser(bytes.NewReader(hdr))})
	_, err := recv()
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized streaming message: err = %v, want ErrMessageTooLarge", err)
	}
}
