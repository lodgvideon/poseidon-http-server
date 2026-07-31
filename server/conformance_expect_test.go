package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the 100-continue expectation.
//
// RFC 9110 §10.1.1: "Upon receiving an HTTP/1.1 (or later) request that has a
// method, target URI, and complete header section that contains a 100-continue
// expectation and an indication that request content will follow, an origin
// server MUST send either:
//
//	*  an immediate response with a final status code, if that status can be
//	   determined by examining just the method, target URI, and header fields, or
//	*  an immediate 100 (Continue) response to encourage the client to send the
//	   request content."
//
// Only the second branch is available here: whether a final status can be
// determined from the header section alone is knowledge only the handler has.
//
// The expectation was never inspected, and the consequence is worse than a
// missing field. In buffered mode the server waits for the whole body before
// dispatching, while a client honouring its own expectation waits for the 100 —
// both sides waiting on each other until something times out.
//
// The same section allows the interim response to be skipped when "the framing
// indicates that there is no content", which in HTTP/2 is END_STREAM on the
// HEADERS frame.

// expectServer starts a server and returns a handshaked client framer.
func expectServer(t *testing.T) *frame.Framer {
	t.Helper()
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
		H2C: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	fr := frame.NewFramer(c, c)
	if err := performClientHandshake(c, fr); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return fr
}

func expectHeaders(withExpect bool) []hpack.HeaderField {
	h := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":path"), Value: []byte("/upload")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	if withExpect {
		h = append(h, hpack.HeaderField{Name: []byte("expect"), Value: []byte("100-continue")})
	}
	return h
}

// TestConformance_RFC9110_Sec1011_ImmediateContinue pins §10.1.1: the client
// deliberately sends no DATA until it has seen the interim response, which is
// exactly the behaviour the expectation exists to enable.
func TestConformance_RFC9110_Sec1011_ImmediateContinue(t *testing.T) {
	fr := expectServer(t)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, expectHeaders(true))
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: false,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	headers, err := readResponseHeaders(fr)
	if err != nil {
		t.Fatalf("no interim response before sending content: %v — RFC 9110 §10.1.1 "+
			"requires an immediate 100 (Continue) (or an immediate final status)", err)
	}
	if got := statusValue(headers); got != "100" {
		t.Fatalf(":status = %q on the first response, want 100 (Continue)", got)
	}

	// Having been encouraged, send the content and read the final status.
	if err := fr.WriteData(1, true, []byte("payload")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	final, err := readResponseHeaders(fr)
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	if got := statusValue(final); got != "200" {
		t.Errorf("final :status = %q, want 200", got)
	}
}

// TestConformance_RFC9110_Sec1011_NoExpectNoContinue is the control: an
// interim response must not be invented for a request that did not ask for one.
func TestConformance_RFC9110_Sec1011_NoExpectNoContinue(t *testing.T) {
	fr := expectServer(t)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, expectHeaders(false))
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: false,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := fr.WriteData(1, true, []byte("payload")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	headers, err := readResponseHeaders(fr)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := statusValue(headers); got != "200" {
		t.Errorf("first :status = %q, want 200 — no interim response was requested", got)
	}
}

// TestConformance_RFC9110_Sec1011_NoContentNoContinue covers the explicit
// exemption: "A server MAY omit sending a 100 (Continue) response ... if the
// framing indicates that there is no content." END_STREAM on HEADERS is that
// indication in HTTP/2.
func TestConformance_RFC9110_Sec1011_NoContentNoContinue(t *testing.T) {
	fr := expectServer(t)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, expectHeaders(true))
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	headers, err := readResponseHeaders(fr)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := statusValue(headers); got != "200" {
		t.Errorf("first :status = %q, want 200 — the framing says there is no content, "+
			"so no interim response is owed", got)
	}
}
