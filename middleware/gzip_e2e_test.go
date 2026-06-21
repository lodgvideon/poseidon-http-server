package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// End-to-end Gzip tests: a real server (TCP + H2 handshake) with the Gzip
// middleware installed, driven by a raw HTTP/2 client. These prove the
// middleware actually compresses on the wire — something the prior unit tests
// (which only exercised the stdlib gzip package) never verified.
// ---------------------------------------------------------------------------

// gzipBigBody is comfortably above the default 512-byte MinSize and very
// compressible, so gzip is guaranteed to shrink it.
var gzipBigBody = bytes.Repeat([]byte("poseidon gzip end-to-end body — "), 64) // ~2KB

// TestGzip_E2E_NativePath_Compresses runs a request through the real server
// with Gzip middleware. The handler uses the native WriteHeaders/WriteData
// path. It asserts the response carries content-encoding: gzip and that the
// payload decompresses to the original body.
func TestGzip_E2E_NativePath_Compresses(t *testing.T) {
	headers, body := gzipRoundTrip(t, true, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			if err := w.WriteHeaders(200, []hpack.HeaderField{
				{Name: []byte("content-type"), Value: []byte("text/plain")},
			}); err != nil {
				return err
			}
			return w.WriteData(gzipBigBody)
		}))

	assertGzipEncoded(t, headers)
	assertDecompresses(t, body, gzipBigBody)
}

// TestGzip_E2E_HTTPPath_Compresses is the same end-to-end proof but the handler
// uses the stdlib http.ResponseWriter path (Header()/WriteHeader/Write), which
// flows through gzipResponseWriter's flushHTTP branch.
func TestGzip_E2E_HTTPPath_Compresses(t *testing.T) {
	headers, body := gzipRoundTrip(t, true, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(200)
			_, err := w.Write(gzipBigBody)
			return err
		}))

	assertGzipEncoded(t, headers)
	assertDecompresses(t, body, gzipBigBody)
}

// TestGzip_E2E_SmallBody_NotCompressed verifies a body below MinSize is sent
// uncompressed (no content-encoding), proving the threshold is honoured.
func TestGzip_E2E_SmallBody_NotCompressed(t *testing.T) {
	small := []byte("tiny")
	headers, body := gzipRoundTrip(t, true, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteData(small)
		}))

	if hasHeader(headers, "content-encoding", "gzip") {
		t.Fatal("small body should not be gzip-encoded")
	}
	if !bytes.Equal(body, small) {
		t.Fatalf("body = %q, want %q", body, small)
	}
}

// TestGzip_E2E_NoAcceptEncoding_PassThrough verifies a client that does not
// advertise gzip receives the identity response untouched.
func TestGzip_E2E_NoAcceptEncoding_PassThrough(t *testing.T) {
	headers, body := gzipRoundTrip(t, false, server.HandlerFunc(
		func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteData(gzipBigBody)
		}))

	if hasHeader(headers, "content-encoding", "gzip") {
		t.Fatal("response must not be gzip-encoded without Accept-Encoding: gzip")
	}
	if !bytes.Equal(body, gzipBigBody) {
		t.Fatalf("identity body mismatch: got %d bytes, want %d", len(body), len(gzipBigBody))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// gzipRoundTrip starts a server wrapping handler with the Gzip middleware,
// sends a single GET / (optionally advertising gzip), and returns the response
// headers and the raw (on-the-wire) body bytes.
func gzipRoundTrip(t *testing.T, acceptGzip bool, handler server.Handler) (headers []hpack.HeaderField, body []byte) {
	t.Helper()

	srv, err := server.NewServer(server.Options{
		Handler:    handler,
		Middleware: []server.Middleware{Gzip(DefaultGzipConfig())},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	fr := frame.NewFramer(c, c)
	if err := h2ClientHandshake(c, fr); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	reqHeaders := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	}
	if acceptGzip {
		reqHeaders = append(reqHeaders, hpack.HeaderField{
			Name: []byte("accept-encoding"), Value: []byte("gzip, deflate"),
		})
	}

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, reqHeaders)
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	return readResponse(t, fr)
}

// readResponse reads frames until END_STREAM, returning the first HEADERS block
// (decoded) and the concatenated DATA payload.
func readResponse(t *testing.T, fr *frame.Framer) (headers []hpack.HeaderField, body []byte) {
	t.Helper()

	capture := &h2Capture{}
	gotHeaders := false

	for range 64 { // bounded to avoid hangs on a misbehaving server
		fh, err := fr.ReadFrame(context.Background(), capture)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		// if/else (not switch) so the exhaustive linter doesn't demand every
		// frame type; we only care about HEADERS and DATA, ignoring the rest
		// (SETTINGS / WINDOW_UPDATE / ...) until END_STREAM.
		if fh.Type == frame.FrameHeaders {
			if !gotHeaders {
				headers = capture.headers
				gotHeaders = true
			}
			if fh.Flags&frame.FlagHeadersEndStream != 0 {
				return headers, capture.body
			}
		} else if fh.Type == frame.FrameData && fh.Flags&frame.FlagDataEndStream != 0 {
			return headers, capture.body
		}
	}
	t.Fatal("did not observe END_STREAM within frame budget")
	return nil, nil
}

// h2ClientHandshake performs the minimal HTTP/2 client handshake.
func h2ClientHandshake(c net.Conn, fr *frame.Framer) error {
	if _, err := c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return err
	}
	if err := fr.WriteSettings(frame.SettingsParams{}); err != nil {
		return err
	}
	if _, err := fr.ReadFrame(context.Background(), &h2Capture{}); err != nil {
		return err
	}
	if err := fr.WriteSettingsAck(); err != nil {
		return err
	}
	if _, err := fr.ReadFrame(context.Background(), &h2Capture{}); err != nil {
		return err
	}
	return nil
}

func assertGzipEncoded(t *testing.T, headers []hpack.HeaderField) {
	t.Helper()
	if got := headerValue(headers, ":status"); got != "200" {
		t.Fatalf(":status = %q, want 200", got)
	}
	if !hasHeader(headers, "content-encoding", "gzip") {
		t.Fatalf("missing content-encoding: gzip; headers=%v", stringifyHeaders(headers))
	}
}

func assertDecompresses(t *testing.T, wire, want []byte) {
	t.Helper()
	if len(wire) >= len(want) {
		t.Fatalf("compressed body (%d bytes) not smaller than original (%d bytes)", len(wire), len(want))
	}
	zr, err := gzip.NewReader(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decompressed body != original (got %d bytes, want %d)", len(got), len(want))
	}
}

func headerValue(headers []hpack.HeaderField, name string) string {
	for _, h := range headers {
		if string(h.Name) == name {
			return string(h.Value)
		}
	}
	return ""
}

func hasHeader(headers []hpack.HeaderField, name, value string) bool {
	for _, h := range headers {
		if string(h.Name) == name && string(h.Value) == value {
			return true
		}
	}
	return false
}

func stringifyHeaders(headers []hpack.HeaderField) string {
	var sb bytes.Buffer
	for _, h := range headers {
		sb.Write(h.Name)
		sb.WriteByte(':')
		sb.Write(h.Value)
		sb.WriteByte(' ')
	}
	return sb.String()
}

// h2Capture implements frame.Handler, capturing decoded response headers and
// concatenated DATA payloads.
type h2Capture struct {
	headers []hpack.HeaderField
	body    []byte
}

func (h *h2Capture) OnData(_ frame.FrameHeader, data []byte, _ uint8) error {
	h.body = append(h.body, data...)
	return nil
}

func (h *h2Capture) OnHeaders(_ frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	dec := hpack.NewDecoder()
	var result []hpack.HeaderField
	err := dec.DecodeBlock(hb, hpack.FieldVisitor(func(f hpack.HeaderField) error {
		cp := hpack.HeaderField{
			Name:  append([]byte(nil), f.Name...),
			Value: append([]byte(nil), f.Value...),
		}
		result = append(result, cp)
		return nil
	}))
	if err != nil {
		return err
	}
	h.headers = result
	return nil
}

func (h *h2Capture) OnPriority(frame.FrameHeader, frame.Priority) error                      { return nil }
func (h *h2Capture) OnRSTStream(frame.FrameHeader, frame.ErrCode) error                      { return nil }
func (h *h2Capture) OnSettings(frame.FrameHeader, frame.SettingsParams) error                { return nil }
func (h *h2Capture) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error { return nil }
func (h *h2Capture) OnPing(frame.FrameHeader, [8]byte) error                                 { return nil }
func (h *h2Capture) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error         { return nil }
func (h *h2Capture) OnWindowUpdate(frame.FrameHeader, uint32) error                          { return nil }
func (h *h2Capture) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error               { return nil }
func (h *h2Capture) OnOrigin(frame.FrameHeader, []string) error                              { return nil }
func (h *h2Capture) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error                   { return nil }
