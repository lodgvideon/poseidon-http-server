package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
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

func (h *streamHeaderCapture) OnData(frame.FrameHeader, []byte, uint8) error      { return nil }
func (h *streamHeaderCapture) OnPriority(frame.FrameHeader, frame.Priority) error { return nil }
func (h *streamHeaderCapture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error { return nil }
func (h *streamHeaderCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error {
	return nil
}
func (h *streamHeaderCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (h *streamHeaderCapture) OnPing(frame.FrameHeader, [8]byte) error { return nil }
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

// TestConformance_RFC9112_Sec51_WhitespaceBeforeColonRejected pins
// rfc9112.txt:716
//
//	"No whitespace is allowed between the field name and colon. In the past,
//	 differences in the handling of such whitespace have led to security
//	 vulnerabilities in request routing and response handling. A server MUST
//	 reject, with a response status code of 400 (Bad Request), any received
//	 request message that contains whitespace between a header field name and
//	 colon."
//
// Go's net/textproto deliberately accepts a SP there (go.dev/issue/34540) and
// hands back the field under a key with a trailing space, so this cannot be
// left to http.ReadRequest. A HTAB in the same position it does reject, which
// this repository's 400 path already covered; the SP is the one that leaked.
//
// The request below is otherwise a perfectly conformant upgrade, so nothing but
// the malformed field name can be responsible for the rejection.
func TestConformance_RFC9112_Sec51_WhitespaceBeforeColonRejected(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n"+
		"X-Foo : bar\r\n\r\n", validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if !strings.Contains(line, "400") {
		t.Errorf("whitespace before a field-name colon: got %q, want 400 (RFC 9112 §5.1)", line)
	}
}

// TestH2CProbe_HeadIsBounded covers the resource bounds on the h2c probe.
//
// Not a conformance rule but the reason one is reachable: http.ReadRequest
// accumulates the whole field section in memory with no limit of its own, and
// the probe's only previous deadline was derived from the context — which Serve
// is normally given without one, so it never fired. An unbounded probe is a
// memory-exhaustion vector and a trickled one is Slowloris.
func TestH2CProbe_HeadIsBounded(t *testing.T) {
	c := upgradeConn(t)

	// A well-formed request line and Host, then field lines forever. A probe
	// that reads to the cap and gives up closes; one that does not would grow
	// until the process does.
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: localhost\r\n")
	filler := "x-pad: " + strings.Repeat("A", 1024) + "\r\n"
	deadline := time.Now().Add(15 * time.Second)
	var written int
	for time.Now().Before(deadline) {
		n, err := c.Write([]byte(filler))
		written += n
		if err != nil {
			// The server bounded us: it stopped reading and closed.
			return
		}
		if written > 4<<20 {
			t.Fatalf("wrote %d bytes of header fields and the server was still reading; "+
				"the probe head is unbounded", written)
		}
	}
	t.Fatalf("wrote %d bytes without the server closing", written)
}

// TestH2CProbe_ReleasedAfterUpgrade guards the other direction: the bound must
// not leak into the HTTP/2 connection. A response body larger than the probe
// cap has to come back intact.
func TestH2CProbe_ReleasedAfterUpgrade(t *testing.T) {
	big := make([]byte, maxProbeHeadBytes*2)
	for i := range big {
		big[i] = byte('a' + i%26)
	}

	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			if err := w.WriteHeaders(200, nil); err != nil {
				return err
			}
			return w.WriteData(big)
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
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	_, _ = fmt.Fprintf(c, "GET /big HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	br := bufio.NewReader(c)
	if line := readStatusLine(t, br); !strings.Contains(line, "101") {
		t.Fatalf("expected 101, got %q", line)
	}
	for {
		hdr, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("draining 101 headers: %v", rerr)
		}
		if strings.TrimSpace(hdr) == "" {
			break
		}
	}

	rwc := &bufioConn{Conn: c, Reader: br}
	fr := frame.NewFramer(rwc, rwc)
	if _, werr := rwc.Write(clientPreface); werr != nil {
		t.Fatal(werr)
	}
	if herr := performClientHandshakeAfterPreface(fr); herr != nil {
		t.Fatal(herr)
	}

	cap := &streamHeaderCapture{}
	for len(cap.headers) == 0 {
		if _, rerr := fr.ReadFrame(context.Background(), cap); rerr != nil {
			t.Fatalf("reading the response after upgrade: %v — the probe bound leaked "+
				"into the HTTP/2 connection", rerr)
		}
	}
	if got := statusValue(cap.headers); got != "200" {
		t.Errorf(":status = %q, want 200", got)
	}
}

// TestConformance_RFC9112_Sec96_CloseOptionDeclinesUpgrade pins rfc9112.txt:1521
//
//	"A server that receives a "close" connection option MUST initiate closure of
//	 the connection (see below) after it sends the final response to the request
//	 that contained the "close" connection option. The server SHOULD send a
//	 "close" connection option in its final response on that connection. The
//	 server MUST NOT process any further requests received on that connection."
//
// Upgrading such a request is the one thing that cannot satisfy this: the
// server would then serve an unbounded number of HTTP/2 streams on a connection
// the client declared finished. Declining is expressly allowed — RFC 7540 §3.2
// lets a server "respond to the request as though the Upgrade header field were
// absent" — and the 400 path already sends "Connection: close" and closes.
//
// The token is looked for across every Connection field line, not via
// req.Close: net/http's shouldClose consults only the first one, so a second
// line carrying "close" would slip past.
func TestConformance_RFC9112_Sec96_CloseOptionDeclinesUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name       string
		connection string
	}{
		{"close_first", "close, Upgrade, HTTP2-Settings"},
		{"close_last", "Upgrade, HTTP2-Settings, close"},
		{"close_uppercase", "Upgrade, HTTP2-Settings, CLOSE"},
		{"close_htab_separated", "Upgrade,\tHTTP2-Settings,\tclose"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := upgradeConn(t)
			_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
				"Host: localhost\r\n"+
				"Upgrade: h2c\r\n"+
				"Connection: %s\r\n"+
				"HTTP2-Settings: %s\r\n\r\n", tc.connection, validHTTP2Settings)

			line := readStatusLine(t, bufio.NewReader(c))
			if !strings.Contains(line, "400") {
				t.Errorf("Connection: %q — got %q, want 400; upgrading would process further "+
					"requests on a connection the client declared finished", tc.connection, line)
			}
		})
	}
}

// TestConformance_RFC9112_Sec96_SecondCloseFieldLineCounts is the specific case
// req.Close misses.
func TestConformance_RFC9112_Sec96_SecondCloseFieldLineCounts(t *testing.T) {
	c := upgradeConn(t)
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"Connection: Upgrade, HTTP2-Settings\r\n"+
		"Connection: close\r\n"+
		"HTTP2-Settings: %s\r\n\r\n", validHTTP2Settings)

	line := readStatusLine(t, bufio.NewReader(c))
	if !strings.Contains(line, "400") {
		t.Errorf("got %q, want 400 — the \"close\" option arrived on a second Connection "+
			"field line, which net/http's shouldClose does not inspect", line)
	}
}

// stagedConn records the order of tear-down calls so the staging RFC 9112 §9.6
// prescribes can be asserted without depending on TCP timing.
type stagedConn struct {
	net.Conn
	pending []byte
	calls   []string
	read    int
}

func (c *stagedConn) CloseWrite() error {
	c.calls = append(c.calls, "CloseWrite")
	return nil
}

func (c *stagedConn) Close() error {
	c.calls = append(c.calls, "Close")
	return nil
}

func (c *stagedConn) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	c.read += n
	c.calls = append(c.calls, "Read")
	return n, nil
}

func (c *stagedConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *stagedConn) SetReadDeadline(time.Time) error { return nil }

// TestH2CProbe_TearDownIsStaged pins the tear-down RFC 9112 §9.6 prescribes
// (rfc9112.txt:1548): "servers typically close a connection in stages. First,
// the server performs a half-close by closing only the write side ... The
// server then continues to read from the connection until it receives a
// corresponding close by the client ... Finally, the server fully closes."
//
// The hazard is stated just above (:1539): unread client data on a fully closed
// connection makes the TCP stack send a reset, and "the reset packet might
// erase the client's unacknowledged input buffers before they can be read and
// interpreted by the client's HTTP parser" — losing the response just written.
//
// Asserted structurally rather than over a socket: an end-to-end version of
// this passed with a bare Close() too, because whether the reset actually
// erases the response depends on buffer sizes and scheduling. A test that
// cannot fail is worse than no test.
func TestH2CProbe_TearDownIsStaged(t *testing.T) {
	c := &stagedConn{pending: []byte("unread request body")}
	closeStaged(c)

	if len(c.calls) == 0 || c.calls[0] != "CloseWrite" {
		t.Fatalf("tear-down began with %v, want a half-close first", c.calls)
	}
	if c.calls[len(c.calls)-1] != "Close" {
		t.Errorf("tear-down ended with %v, want the full close last", c.calls)
	}
	if c.read != len("unread request body") {
		t.Errorf("drained %d of %d pending octets; unread data on a fully closed "+
			"connection is what provokes the reset", c.read, len("unread request body"))
	}
}

// TestH2CProbe_BadRequestTearsDownStaged closes the loop the test above leaves
// open: closeStaged can be correct while the 400 path bypasses it. Every
// rejection this file exercises goes out through writeBadRequest, so that is
// where the staging has to be observed.
func TestH2CProbe_BadRequestTearsDownStaged(t *testing.T) {
	c := &stagedConn{pending: []byte("unread request body")}
	writeBadRequest(c, "Only h2c supported")

	if len(c.calls) == 0 || c.calls[0] != "CloseWrite" {
		t.Fatalf("writeBadRequest tore down with %v; it must half-close first, or an "+
			"unread body provokes a reset that can erase the 400 (RFC 9112 §9.6)", c.calls)
	}
	if c.read != len("unread request body") {
		t.Errorf("drained %d of %d pending octets", c.read, len("unread request body"))
	}
}
