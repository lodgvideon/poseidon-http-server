package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for inbound HTTP field validation.
//
// Governing text, copied verbatim from the sources fetched from rfc-editor.org:
//
//	RFC 9110 §5.5 (rfc9110.txt:1606) — "Field values containing CR, LF, or NUL
//	characters are invalid and dangerous, due to the varying ways that
//	implementations might parse and interpret those characters; a recipient of
//	CR, LF, or NUL within a field value MUST either reject the message or
//	replace each of those characters with SP before further processing or
//	forwarding of that message."
//
//	RFC 9113 §8.2.1 (rfc9113.txt:2497) — "HTTP/2 implementations SHOULD validate
//	field names and values according to their definitions in Sections 5.1 and
//	5.5 of [HTTP], respectively, and treat messages that contain prohibited
//	characters as malformed (Section 8.1.1)."
//
//	RFC 9113 §8.1.1 (rfc9113.txt:2463) — "Malformed requests or responses that
//	are detected MUST be treated as a stream error (Section 5.4.2) of type
//	PROTOCOL_ERROR."
//
// The mandated reaction is therefore a STREAM error, not a connection error:
// the offending stream is reset and the connection survives.

// fieldRSTCapture records the first RST_STREAM and the first GOAWAY seen.
type fieldRSTCapture struct {
	rstStreamID uint32
	rstCode     frame.ErrCode
	sawRST      bool
	goAwayCode  frame.ErrCode
	sawGoAway   bool
}

func (c *fieldRSTCapture) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	if !c.sawRST {
		c.rstStreamID, c.rstCode, c.sawRST = fh.StreamID, code, true
	}
	return nil
}

func (c *fieldRSTCapture) OnGoAway(_ frame.FrameHeader, _ uint32, code frame.ErrCode, _ []byte) error {
	if !c.sawGoAway {
		c.goAwayCode, c.sawGoAway = code, true
	}
	return nil
}

func (c *fieldRSTCapture) OnData(frame.FrameHeader, []byte, uint8) error { return nil }
func (c *fieldRSTCapture) OnHeaders(frame.FrameHeader, frame.HeaderBlock, *frame.Priority, uint8) error {
	return nil
}
func (c *fieldRSTCapture) OnPriority(frame.FrameHeader, frame.Priority) error       { return nil }
func (c *fieldRSTCapture) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (c *fieldRSTCapture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (c *fieldRSTCapture) OnPing(frame.FrameHeader, [8]byte) error                   { return nil }
func (c *fieldRSTCapture) OnWindowUpdate(frame.FrameHeader, uint32) error            { return nil }
func (c *fieldRSTCapture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (c *fieldRSTCapture) OnOrigin(frame.FrameHeader, []string) error                { return nil }
func (c *fieldRSTCapture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error     { return nil }

// runRSTProbe drives the client side with `attack` and returns what the server
// sent back: the first RST_STREAM and whether the connection was also killed.
func runRSTProbe(t *testing.T, attack func(cliFr *frame.Framer)) fieldRSTCapture {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()

	result := make(chan fieldRSTCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			rc := &fieldRSTCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), rc); err != nil {
						return
					}
					if rc.sawRST || rc.sawGoAway {
						return
					}
				}
			}()
			attack(cliFr)
			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
			select {
			case result <- *rc:
			default:
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case rc := <-result:
		<-done
		return rc
	case <-time.After(4 * time.Second):
		<-done
		return fieldRSTCapture{}
	}
}

// TestConformance_RFC9110_Sec55_FieldValueCRLFNUL_StreamError pins
// rfc9110.txt:1606 together with the reaction mandated by rfc9113.txt:2463.
//
// A field value carrying CR, LF, or NUL must not reach the handler. Left
// unvalidated it is a header-injection primitive: the value is copied verbatim
// into the request and, for the stdlib-compat path, into http.Header.
func TestConformance_RFC9110_Sec55_FieldValueCRLFNUL_StreamError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"CR", []byte("a\rb")},
		{"LF", []byte("a\nb")},
		{"NUL", []byte("a\x00b")},
		{"CRLF_injection", []byte("x\r\nx-injected: 1")},
		{"leading_LF", []byte("\nvalue")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := []hpack.HeaderField{
				{Name: []byte(":method"), Value: []byte("GET")},
				{Name: []byte(":scheme"), Value: []byte("https")},
				{Name: []byte(":path"), Value: []byte("/")},
				{Name: []byte("x-test"), Value: tc.value},
			}
			rc := runRSTProbe(t, func(cliFr *frame.Framer) {
				sendReq(t, cliFr, 1, headers, true)
			})
			if !rc.sawRST {
				t.Fatalf("no RST_STREAM for a field value containing %s; RFC 9110 §5.5 "+
					"requires the message be rejected (goaway=%v code=%v)", tc.name, rc.sawGoAway, rc.goAwayCode)
			}
			if rc.rstCode != frame.ErrCodeProtocolError {
				t.Errorf("RST_STREAM code = %v, want PROTOCOL_ERROR (RFC 9113 §8.1.1)", rc.rstCode)
			}
			if rc.rstStreamID != 1 {
				t.Errorf("RST_STREAM on stream %d, want 1", rc.rstStreamID)
			}
			if rc.sawGoAway {
				t.Errorf("connection was torn down with GOAWAY(%v); a malformed request is a "+
					"STREAM error, not a connection error (RFC 9113 §8.1.1)", rc.goAwayCode)
			}
		})
	}
}

// TestConformance_RFC9110_Sec55_CleanFieldValueAccepted guards the other
// direction: ordinary values, including obs-text and other CTLs which the RFC
// explicitly permits a recipient to retain, must NOT be rejected.
//
//	rfc9110.txt:1611 — "Field values containing other CTL characters are also
//	invalid; however, recipients MAY retain such characters"
func TestConformance_RFC9110_Sec55_CleanFieldValueAccepted(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte("x-tab"), Value: []byte("a\tb")},
		{Name: []byte("x-obs-text"), Value: []byte{0xC3, 0xA9}},
	}
	rc := runRSTProbe(t, func(cliFr *frame.Framer) {
		sendReq(t, cliFr, 1, headers, true)
	})
	if rc.sawRST {
		t.Errorf("RST_STREAM(%v) for a legal field value; HTAB and obs-text are permitted", rc.rstCode)
	}
	if rc.sawGoAway {
		t.Errorf("GOAWAY(%v) for a legal field value", rc.goAwayCode)
	}
}
