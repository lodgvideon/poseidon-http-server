package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the h2c Upgrade mechanism in server/h2c.go.
//
// Every assertion below is derived from the RFC text, NOT from what the
// implementation currently does. Quotes are copied verbatim from the sources
// fetched from rfc-editor.org; the line numbers are into those files.
//
// RFC 7540 defines the h2c Upgrade mechanism (RFC 9113 marks it obsolete but
// this server implements it, so 7540 is the governing text for this path).
// RFC 9110 §7.8 and RFC 9112 §2.2 add the generic Upgrade/Host obligations.

// upgradeConn dials the test server and returns the connection.
func upgradeConn(t *testing.T) net.Conn {
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
	return c
}

// validHTTP2Settings is an empty SETTINGS payload encoded per RFC 7540 §3.2.1:
// "encoded as a base64url string ... with any trailing '=' characters omitted".
var validHTTP2Settings = base64.RawURLEncoding.EncodeToString(nil)

// readStatusLine reads the first line of an HTTP/1.1 response.
func readStatusLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}
	return strings.TrimSpace(line)
}

// TestConformance_RFC7540_Sec32_ServerIgnoresH2UpgradeToken pins rfc7540.txt:464
//
//	"A server MUST ignore an "h2" token in an Upgrade header field."
//
// Ignoring the field means behaving as though it were absent. For this
// HTTP/2-only server that is the 400 path, and it is emphatically not 101.
func TestConformance_RFC7540_Sec32_ServerIgnoresH2UpgradeToken(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if strings.Contains(line, "101") {
		t.Errorf("switched protocols on an %q token; RFC 7540 §3.2 says the server "+
			"MUST ignore it (got %q)", "Upgrade: h2", line)
	}
}

// TestConformance_RFC7540_Sec321_NoUpgradeWithoutHTTP2Settings pins
// rfc7540.txt:511
//
//	"A server MUST NOT upgrade the connection to HTTP/2 if this header
//	 field is not present or if more than one is present."
func TestConformance_RFC7540_Sec321_NoUpgradeWithoutHTTP2Settings(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade\r\n\r\n")

	line := readStatusLine(t, bufio.NewReader(c))
	if strings.Contains(line, "101") {
		t.Errorf("upgraded without an HTTP2-Settings header field; RFC 7540 §3.2.1 "+
			"says the server MUST NOT (got %q)", line)
	}
}

// TestConformance_RFC7540_Sec321_NoUpgradeWithDuplicateHTTP2Settings pins the
// second half of rfc7540.txt:511 — "or if more than one is present".
func TestConformance_RFC7540_Sec321_NoUpgradeWithDuplicateHTTP2Settings(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings, validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if strings.Contains(line, "101") {
		t.Errorf("upgraded with two HTTP2-Settings header fields; RFC 7540 §3.2.1 "+
			"says the server MUST NOT (got %q)", line)
	}
}

// TestConformance_RFC9110_Sec78_IgnoreUpgradeInHTTP10Request pins
// rfc9110.txt:2880
//
//	"A server that receives an Upgrade header field in an HTTP/1.0
//	 request MUST ignore that Upgrade field."
//
// The same request also pins rfc9110.txt (§15.2): a server MUST NOT send a 1xx
// response to an HTTP/1.0 client.
func TestConformance_RFC9110_Sec78_IgnoreUpgradeInHTTP10Request(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.0\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if strings.Contains(line, "101") {
		t.Errorf("honoured Upgrade in an HTTP/1.0 request; RFC 9110 §7.8 says the "+
			"server MUST ignore it, and §15.2 forbids a 1xx to an HTTP/1.0 client "+
			"(got %q)", line)
	}
}

// TestConformance_RFC9112_Sec22_RejectRequestWithoutHost pins rfc9112.txt:445
//
//	"A server MUST respond with a 400 (Bad Request) status code to any
//	 HTTP/1.1 request message that lacks a Host header field and to any
//	 request message that contains more than one Host header field line or
//	 a Host header field with an invalid field value."
func TestConformance_RFC9112_Sec22_RejectRequestWithoutHost(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if !strings.Contains(line, "400") {
		t.Errorf("Host-less HTTP/1.1 request: got %q, want 400 (RFC 9112 §2.2)", line)
	}
}

// streamHeaderCapture records which stream a HEADERS frame arrived on.
type streamHeaderCapture struct {
	streamID uint32
	headers  []hpack.HeaderField
	dec      *hpack.Decoder
}

func (h *streamHeaderCapture) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	if h.dec == nil {
		h.dec = hpack.NewDecoder()
	}
	h.streamID = fh.StreamID
	return h.dec.DecodeBlock(hb, hpack.FieldVisitor(func(f hpack.HeaderField) error {
		cp := hpack.HeaderField{Name: make([]byte, len(f.Name)), Value: make([]byte, len(f.Value))}
		copy(cp.Name, f.Name)
		copy(cp.Value, f.Value)
		h.headers = append(h.headers, cp)
		return nil
	}))
}

func (h *streamHeaderCapture) OnData(frame.FrameHeader, []byte, uint8) error           { return nil }
func (h *streamHeaderCapture) OnPriority(frame.FrameHeader, frame.Priority) error      { return nil }
func (h *streamHeaderCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error      { return nil }
func (h *streamHeaderCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error {
	return nil
}
func (h *streamHeaderCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (h *streamHeaderCapture) OnPing(frame.FrameHeader, [8]byte) error                       { return nil }
func (h *streamHeaderCapture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}
func (h *streamHeaderCapture) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (h *streamHeaderCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (h *streamHeaderCapture) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (h *streamHeaderCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }

// TestConformance_RFC7540_Sec32_ResponseToUpgradingRequestOnStream1 pins
// rfc7540.txt:471 and :487-492
//
//	"These frames MUST include a response to the request that initiated the
//	 upgrade."
//
//	"The HTTP/1.1 request that is sent prior to upgrade is assigned a
//	 stream identifier of 1 ... Stream 1 is implicitly "half-closed" from
//	 the client toward the server ... After commencing the HTTP/2
//	 connection, stream 1 is used for the response."
//
// The client therefore MUST NOT open stream 1 itself. This test does what a
// conformant client does: send the preface and then simply wait for the
// response on stream 1.
func TestConformance_RFC7540_Sec32_ResponseToUpgradingRequestOnStream1(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET /upgraded HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	br := bufio.NewReader(c)
	if line := readStatusLine(t, br); !strings.Contains(line, "101") {
		t.Fatalf("expected 101 Switching Protocols for a conformant upgrade, got %q", line)
	}
	for {
		hdr, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("draining 101 headers: %v", err)
		}
		if strings.TrimSpace(hdr) == "" {
			break
		}
	}

	// "Upon receiving the 101 response, the client MUST send a connection
	// preface, which includes a SETTINGS frame." (rfc7540.txt:484)
	rwc := &bufioConn{Conn: c, Reader: br}
	fr := frame.NewFramer(rwc, rwc)
	if _, err := rwc.Write(clientPreface); err != nil {
		t.Fatal(err)
	}
	if err := performClientHandshakeAfterPreface(fr); err != nil {
		t.Fatal(err)
	}

	// Deliberately open NO stream. Read frames until HEADERS arrives; the
	// response to the upgrading request must appear on stream 1 unprompted.
	cap := &streamHeaderCapture{}
	deadline := time.Now().Add(4 * time.Second)
	for len(cap.headers) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no response to the upgrading request: the server never sent " +
				"HEADERS on stream 1 (RFC 7540 §3.2 — these frames MUST include a " +
				"response to the request that initiated the upgrade)")
		}
		if _, err := fr.ReadFrame(context.Background(), cap); err != nil {
			t.Fatalf("reading frames after upgrade: %v (expected a response on stream 1)", err)
		}
	}
	if cap.streamID != 1 {
		t.Errorf("response arrived on stream %d, want stream 1 (RFC 7540 §3.2)", cap.streamID)
	}
	if got := statusValue(cap.headers); got != "200" {
		t.Errorf(":status = %q, want 200", got)
	}
}
