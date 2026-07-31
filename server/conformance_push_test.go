package server

import (
	"errors"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the PUSH_PROMISE field set.
//
// RFC 9113 §8.4 (rfc9113.txt:2811):
//
//	"The header fields in PUSH_PROMISE and any subsequent CONTINUATION frames
//	 MUST be a valid and complete set of request header fields (Section 8.3.1).
//	 ... If a client receives a PUSH_PROMISE that does not include a complete
//	 and valid set of header fields ... it MUST respond on the promised stream
//	 with a stream error (Section 5.4.2) of type PROTOCOL_ERROR."
//
// RFC 9110 §4.2.1 (rfc9110.txt:1106) / §4.2.2 (:1135):
//
//	"A sender MUST NOT generate an "http" URI with an empty host identifier."
//
// The promise carried :method, :path and :scheme but never :authority, so the
// promised request's target URI had an empty host. The consequence is not
// theoretical: a conformant client MUST reset every such promised stream.

func pseudoValue(fields []hpack.HeaderField, name string) (string, int) {
	value, count := "", 0
	for _, f := range fields {
		if string(f.Name) == name {
			value = string(f.Value)
			count++
		}
	}
	return value, count
}

// TestConformance_RFC9113_Sec84_PushPromiseCarriesAuthority pins :2812. The
// promised request belongs to the same origin as the request that triggered it,
// so its authority is the originating request's.
func TestConformance_RFC9113_Sec84_PushPromiseCarriesAuthority(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &responseWriter{
		sw:  &mockPusher{stream: stream},
		req: &Request{Scheme: "https", Path: "/", Authority: "example.com"},
	}

	// The mock always returns its sentinel after capturing the promise.
	if _, err := w.Push("/style.css", nil); err != nil && !errors.Is(err, errMockPushNotUsed) {
		t.Fatalf("Push: %v", err)
	}
	if len(stream.headerSets) != 1 {
		t.Fatalf("headerSets len = %d, want 1", len(stream.headerSets))
	}
	got, n := pseudoValue(stream.headerSets[0], ":authority")
	if n != 1 {
		t.Fatalf(":authority appeared %d times in the promise, want exactly 1 "+
			"(RFC 9113 §8.4 — a complete and valid set of request header fields)", n)
	}
	if got != "example.com" {
		t.Errorf(":authority = %q, want the originating request's authority", got)
	}
}

// TestConformance_RFC9113_Sec84_PushPromiseCallerAuthorityWins guards against
// emitting the pseudo-header twice, which RFC 9113 §8.3 (:2624) makes malformed
// on its own.
func TestConformance_RFC9113_Sec84_PushPromiseCallerAuthorityWins(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &responseWriter{
		sw:  &mockPusher{stream: stream},
		req: &Request{Scheme: "https", Path: "/", Authority: "origin.example"},
	}

	_, _ = w.Push("/style.css", []hpack.HeaderField{
		{Name: []byte(":authority"), Value: []byte("caller.example")},
	})

	got, n := pseudoValue(stream.headerSets[0], ":authority")
	if n != 1 {
		t.Fatalf(":authority appeared %d times, want exactly 1 (a repeated "+
			"pseudo-header name is malformed, rfc9113.txt:2624)", n)
	}
	if got != "caller.example" {
		t.Errorf(":authority = %q, want the caller-supplied value", got)
	}
}

// TestConformance_RFC9113_Sec84_PushRefusedWithoutAuthority pins the sender-side
// half of RFC 9110 §4.2: with no authority available from anywhere, the only
// promise the server could emit is one a conformant client MUST reject, so it
// must not be emitted at all.
func TestConformance_RFC9113_Sec84_PushRefusedWithoutAuthority(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &responseWriter{sw: &mockPusher{stream: stream}} // req == nil

	_, err := w.Push("/style.css", nil)
	if err == nil || errors.Is(err, errMockPushNotUsed) {
		t.Fatal("Push succeeded with no authority available; the promised request " +
			"would have an empty host (RFC 9110 §4.2) and a conformant client MUST " +
			"reset the promised stream (rfc9113.txt:2815)")
	}
	if len(stream.headerSets) != 0 {
		t.Errorf("emitted %d PUSH_PROMISE field sets despite refusing; want 0", len(stream.headerSets))
	}
}

// TestConformance_RFC9113_Sec84_PushWithPriorityCarriesAuthority covers the
// second, separately-written promise path.
func TestConformance_RFC9113_Sec84_PushWithPriorityCarriesAuthority(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &responseWriter{
		sw:  &mockPusher{stream: stream},
		req: &Request{Scheme: "https", Path: "/", Authority: "example.com"},
	}

	_, _ = w.PushWithPriority("/style.css", nil, nil)

	if len(stream.headerSets) != 1 {
		t.Fatalf("headerSets len = %d, want 1", len(stream.headerSets))
	}
	got, n := pseudoValue(stream.headerSets[0], ":authority")
	if n != 1 || got != "example.com" {
		t.Errorf(":authority = %q (count %d), want \"example.com\" once", got, n)
	}
}
