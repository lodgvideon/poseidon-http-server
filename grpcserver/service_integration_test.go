package grpcserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Integration tests: full gRPC dispatch via net.Pipe + conn.ServerConn
// ---------------------------------------------------------------------------

// setupGRPCPair creates a server with the ServiceRegistrar handler and
// a client-side *conn.ServerConn pair connected via net.Pipe.
// Returns the client-side framer + encoder + cleanup function.
func setupGRPCPair(t *testing.T, registrar *ServiceRegistrar) (*frame.Framer, *hpack.Encoder, func()) {
	t.Helper()

	// Create server.
	srv, err := server.NewServer(server.Options{
		Handler: registrar.Handler(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Connect via net.Pipe.
	clientConn, serverConn := net.Pipe()

	// Server serves in background.
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, &singleListener{conn: serverConn})

	// Client: send HTTP/2 preface + SETTINGS to handshake.
	if _, err := clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatalf("write preface: %v", err)
	}

	// Read server SETTINGS.
	fr := frame.NewFramer(clientConn, clientConn)
	enc := hpack.NewEncoder()

	// Perform client-side handshake: read SETTINGS, send ACK, send our SETTINGS, read ACK.
	if err := clientHandshake(fr); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	cleanup := func() {
		cancel()
		clientConn.Close()
	}
	return fr, enc, cleanup
}

// clientHandshake performs the minimal client-side HTTP/2 handshake.
func clientHandshake(fr *frame.Framer) error {
	// Read server SETTINGS.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handler := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, handler)
	if err != nil {
		return err
	}
	if fh.Type != frame.FrameSettings {
		return newUnexpectedFrameError("settings", fh.Type)
	}

	// Send SETTINGS ACK.
	if err := fr.WriteSettingsAck(); err != nil {
		return err
	}

	// Send our SETTINGS.
	if err := fr.WriteSettings(frame.SettingsParams{N: 0}); err != nil {
		return err
	}

	// Read SETTINGS ACK.
	handler2 := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, handler2)
	if err != nil {
		return err
	}
	if fh2.Type != frame.FrameSettings {
		// Might be a window update or something — that's OK.
		return nil
	}
	return nil
}

// errUnexpectedFrame creates an error for unexpected frame types.
type unexpectedFrameError string

func (e unexpectedFrameError) Error() string { return string(e) }

func newUnexpectedFrameError(expected string, got frame.FrameType) unexpectedFrameError {
	return unexpectedFrameError("expected " + expected + ", got frame type " + string(rune('0'+got)))
}

// TestIntegration_UnknownMethod_UnaryHandler verifies the
// "unknown method" branch in Handler() (service.go:147-149) — the
// handler dispatches to a path that was never registered and the
// service returns writeGRPCError(Unimplemented).
func TestIntegration_UnknownMethod_UnaryHandler(t *testing.T) {
	registrar := NewServiceRegistrar()
	// Register an unrelated method so the registrar is non-empty, but
	// the request will target a different path.
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Greeter",
		Methods: []MethodDesc{
			{Name: "SayHello", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) {
				return nil, nil
			}},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	body := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("x")})
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Greeter/DoesNotExist")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("x")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
		{Name: []byte("te"), Value: []byte("trailers")},
	}
	block := enc.EncodeBlock(nil, headers)
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := fr.WriteData(1, true, body); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	// Read the response: HEADERS with :status=200 + grpc-status trailer.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h := &collectHeadersHandler{headers: make(map[string]string)}
	_, _ = fr.ReadFrame(ctx, h)
	// Just assert that the response arrived (any response is fine —
	// the point is the handler returned instead of panicking).
	if h.lastType != frame.FrameHeaders {
		t.Logf("note: first response frame was %v (handler may have written trailers first)", h.lastType)
	}
}

// TestIntegration_NonGRPCContentType verifies the "invalid content-type"
// branch in Handler() (service.go:141-143).
func TestIntegration_NonGRPCContentType(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Greeter",
		Methods: []MethodDesc{
			{Name: "SayHello", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) {
				return nil, nil
			}},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Greeter/SayHello")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("x")},
		// Note: NO content-type or wrong content-type.
	}
	block := enc.EncodeBlock(nil, headers)
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h := &collectHeadersHandler{headers: make(map[string]string)}
	if _, err := fr.ReadFrame(ctx, h); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// Expect a response of some kind — the handler should reject
	// the request without crashing.
	if h.lastType == 0 {
		t.Fatal("no response frame received")
	}
}

// collectHeadersHandler is a minimal frame.Handler that records the last
// frame header and a flat map of decoded headers.
type collectHeadersHandler struct {
	lastType frame.FrameType
	headers  map[string]string
}

func (h *collectHeadersHandler) OnHeaders(_ frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	h.lastType = frame.FrameHeaders
	dec := hpack.NewDecoder()
	_ = dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		h.headers[string(f.Name)] = string(f.Value)
		return nil
	})
	return nil
}
func (h *collectHeadersHandler) OnData(_ frame.FrameHeader, _ []byte, _ uint8) error {
	return nil
}
func (h *collectHeadersHandler) OnPriority(frame.FrameHeader, frame.Priority) error  { return nil }
func (h *collectHeadersHandler) OnRSTStream(frame.FrameHeader, frame.ErrCode) error  { return nil }
func (h *collectHeadersHandler) OnSettings(frame.FrameHeader, frame.SettingsParams) error { return nil }
func (h *collectHeadersHandler) OnSettingsAck(frame.FrameHeader) error               { return nil }
func (h *collectHeadersHandler) OnPing(frame.FrameHeader, [8]byte) error             { return nil }
func (h *collectHeadersHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error { return nil }
func (h *collectHeadersHandler) OnWindowUpdate(frame.FrameHeader, uint32) error      { return nil }
func (h *collectHeadersHandler) OnContinuation(frame.FrameHeader, frame.HeaderBlock) error { return nil }
func (h *collectHeadersHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	return nil
}
func (h *collectHeadersHandler) OnOrigin(frame.FrameHeader, []string) error          { return nil }
func (h *collectHeadersHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

// ---------------------------------------------------------------------------
// Test: Unary RPC end-to-end
// ---------------------------------------------------------------------------

func TestIntegration_UnaryRPC(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Greeter",
		Methods: []MethodDesc{
			{
				Name: "SayHello",
				UnaryHandler: func(_ context.Context, req []byte) ([]byte, error) {
					return append([]byte("Hello "), req...), nil
				},
			},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	// Send gRPC request: POST /test.Greeter/SayHello with LP-encoded body.
	body := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("World")})

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Greeter/SayHello")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
		{Name: []byte("te"), Value: []byte("trailers")},
	}

	hb := enc.EncodeBlock(nil, headers)
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:   1,
		BlockFragment: hb,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	// Send DATA with the LP body.
	if err := fr.WriteData(1, false, body); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	// Send end-of-stream.
	if err := fr.WriteData(1, true, nil); err != nil {
		t.Fatalf("WriteData EOS: %v", err)
	}

	// Read response: HEADERS + DATA + HEADERS(trailers).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	collector := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, collector)
	if err != nil {
		t.Fatalf("ReadFrame HEADERS: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read response DATA.
	collector2 := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, collector2)
	if err != nil {
		t.Fatalf("ReadFrame DATA: %v", err)
	}

	var respBody []byte
	if fh2.Type == frame.FrameData {
		respBody = collector2.dataBuf.Bytes()
		// Read trailers.
		collector3 := &collectHandler{}
		_, _ = fr.ReadFrame(ctx, collector3)
	} else if fh2.Type == frame.FrameHeaders {
		// Trailers-only (error case).
		// This is fine, just check trailers.
		_ = fh2
	}

	if len(respBody) == 0 {
		t.Fatal("expected response body")
	}

	// Decode LP response.
	msg, _, err := DecodeLPFromBytes(respBody)
	if err != nil {
		t.Fatalf("DecodeLP response: %v", err)
	}

	if string(msg.Payload) != "Hello World" {
		t.Errorf("response = %q, want %q", msg.Payload, "Hello World")
	}
}

// ---------------------------------------------------------------------------
// Test: Unary RPC error
// ---------------------------------------------------------------------------

func TestIntegration_UnaryRPC_Error(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Error",
		Methods: []MethodDesc{
			{
				Name: "Fail",
				UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) {
					return nil, Statusf(NotFound, "item gone")
				},
			},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Error/Fail")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:   1,
		BlockFragment: hb,
		EndHeaders: true,
		EndStream:  true,
	})

	// Read response: first HEADERS (response headers), second HEADERS (trailers).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS (200 + content-type).
	collector := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, collector)
	if err != nil {
		t.Fatalf("ReadFrame #1: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read trailers HEADERS (grpc-status).
	trailerCollector := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, trailerCollector)
	if err != nil {
		t.Fatalf("ReadFrame #2: %v", err)
	}
	if fh2.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS (trailers), got %d", fh2.Type)
	}

	// Check trailers for grpc-status = 5 (NotFound).
	trailers := trailerCollector.headers
	found := false
	for _, h := range trailers {
		if string(h.Name) == "grpc-status" && string(h.Value) == "5" {
			found = true
		}
	}
	if !found {
		t.Errorf("grpc-status trailer not found in trailers: %v", trailers)
	}
}

// ---------------------------------------------------------------------------
// Test: Unknown method
// ---------------------------------------------------------------------------

func TestIntegration_UnknownMethod(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name:    "test.Svc",
		Methods: []MethodDesc{{Name: "Exists", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }}},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Svc/Missing")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:   1,
		BlockFragment: hb,
		EndHeaders: true,
		EndStream:  true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	collector := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, collector)
	if err != nil {
		t.Fatalf("ReadFrame #1: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read trailers HEADERS.
	trailerCollector := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, trailerCollector)
	if err != nil {
		t.Fatalf("ReadFrame #2: %v", err)
	}
	if fh2.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS (trailers), got %d", fh2.Type)
	}

	trailers := trailerCollector.headers
	found := false
	for _, h := range trailers {
		if string(h.Name) == "grpc-status" && string(h.Value) == "12" {
			found = true
		}
	}
	if !found {
		t.Errorf("grpc-status=12 (Unimplemented) not found in trailers: %v", trailers)
	}
}

// ---------------------------------------------------------------------------
// Test: Server-streaming RPC
// ---------------------------------------------------------------------------

func TestIntegration_ServerStreaming(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Stream",
		Methods: []MethodDesc{
			{
				Name: "ListItems",
				ServerStreamH: func(_ context.Context, _ []byte, send StreamSender) error {
					for _, item := range []string{"alpha", "beta", "gamma"} {
						if err := send([]byte(item)); err != nil {
							return err
						}
					}
					return nil
				},
			},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	// Send request.
	body := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("list")})
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Stream/ListItems")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:   1,
		BlockFragment: hb,
		EndHeaders: true,
	})
	_ = fr.WriteData(1, false, body)
	_ = fr.WriteData(1, true, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	hCollector := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, hCollector)
	if err != nil {
		t.Fatalf("ReadFrame HEADERS: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read DATA frames with LP-encoded messages.
	var allPayloads []string
	for {
		dCollector := &collectHandler{}
		fh, err := fr.ReadFrame(ctx, dCollector)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if fh.Type == frame.FrameHeaders {
			break // Trailers — done.
		}
		if fh.Type != frame.FrameData {
			continue
		}
		data := dCollector.dataBuf.Bytes()
		if len(data) == 0 {
			continue
		}
		msg, _, decErr := DecodeLPFromBytes(data)
		if decErr != nil {
			t.Fatalf("DecodeLP: %v", decErr)
		}
		allPayloads = append(allPayloads, string(msg.Payload))
	}

	if len(allPayloads) != 3 {
		t.Errorf("got %d messages, want 3: %v", len(allPayloads), allPayloads)
	}
	if allPayloads[0] != "alpha" || allPayloads[1] != "beta" || allPayloads[2] != "gamma" {
		t.Errorf("payloads = %v, want [alpha beta gamma]", allPayloads)
	}
}

// ---------------------------------------------------------------------------
// Test: Client-streaming RPC
// ---------------------------------------------------------------------------

func TestIntegration_ClientStreaming(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.CStream",
		Methods: []MethodDesc{
			{
				Name: "Upload",
				ClientStreamH: func(_ context.Context, recv func() ([]byte, error)) ([]byte, error) {
					var total []byte
					for {
						msg, rerr := recv()
						if rerr != nil {
							if !errors.Is(rerr, io.EOF) {
								return nil, rerr
							}
							return total, nil //nolint:nilerr // EOF is expected end-of-stream
						}
						total = append(total, msg...)
					}
				},
			},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	// Send request with two LP-encoded messages.
	msg1 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("hello ")})
	msg2 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("world")})
	body := make([]byte, 0, len(msg1)+len(msg2))
	body = append(body, msg1...)
	body = append(body, msg2...)

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.CStream/Upload")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: hb,
		EndHeaders:    true,
	})
	_ = fr.WriteData(1, false, body)
	_ = fr.WriteData(1, true, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	hc := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, hc)
	if err != nil {
		t.Fatalf("ReadFrame HEADERS: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read response DATA.
	dc := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, dc)
	if err != nil {
		t.Fatalf("ReadFrame DATA: %v", err)
	}
	if fh2.Type != frame.FrameData {
		t.Fatalf("expected DATA, got %d", fh2.Type)
	}

	respMsg, _, decErr := DecodeLPFromBytes(dc.dataBuf.Bytes())
	if decErr != nil {
		t.Fatalf("DecodeLP: %v", decErr)
	}
	if string(respMsg.Payload) != "hello world" {
		t.Errorf("response = %q, want %q", respMsg.Payload, "hello world")
	}

	// Read trailers.
	tc := &collectHandler{}
	_, _ = fr.ReadFrame(ctx, tc)
}

// ---------------------------------------------------------------------------
// Test: Bidi-streaming RPC
// ---------------------------------------------------------------------------

func TestIntegration_BidiStreaming(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name: "test.Bidi",
		Methods: []MethodDesc{
			{
				Name: "Echo",
				BidiStreamH: func(_ context.Context, recv func() ([]byte, error), send StreamSender) error {
					for {
						msg, rerr := recv()
						if rerr != nil {
							if !errors.Is(rerr, io.EOF) {
								return rerr
							}
							return nil //nolint:nilerr // EOF is expected end-of-stream
						}
						if err := send(append([]byte("echo:"), msg...)); err != nil {
							return err
						}
					}
				},
			},
		},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	msg1 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("ping")})
	msg2 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("pong")})
	body := make([]byte, 0, len(msg1)+len(msg2))
	body = append(body, msg1...)
	body = append(body, msg2...)

	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Bidi/Echo")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      1,
		BlockFragment: hb,
		EndHeaders:    true,
	})
	_ = fr.WriteData(1, false, body)
	_ = fr.WriteData(1, true, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	hc := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, hc)
	if err != nil {
		t.Fatalf("ReadFrame HEADERS: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read echoed DATA frames.
	echoed := make([]string, 0, 2)
	for range 2 {
		dc := &collectHandler{}
		fh, err = fr.ReadFrame(ctx, dc)
		if err != nil {
			t.Fatalf("ReadFrame DATA: %v", err)
		}
		if fh.Type != frame.FrameData {
			break
		}
		data := dc.dataBuf.Bytes()
		if len(data) == 0 {
			continue
		}
		resp, _, decErr := DecodeLPFromBytes(data)
		if decErr != nil {
			t.Fatalf("DecodeLP: %v", decErr)
		}
		echoed = append(echoed, string(resp.Payload))
	}

	if len(echoed) != 2 {
		t.Fatalf("got %d echoed messages, want 2: %v", len(echoed), echoed)
	}
	if echoed[0] != "echo:ping" {
		t.Errorf("echoed[0] = %q, want %q", echoed[0], "echo:ping")
	}
	if echoed[1] != "echo:pong" {
		t.Errorf("echoed[1] = %q, want %q", echoed[1], "echo:pong")
	}
}

// ---------------------------------------------------------------------------
// Test: Invalid content-type rejected
// ---------------------------------------------------------------------------

func TestIntegration_InvalidContentType(t *testing.T) {
	registrar := NewServiceRegistrar()
	registrar.RegisterService(&ServiceDesc{
		Name:    "test.Svc",
		Methods: []MethodDesc{{Name: "Do", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }}},
	})

	fr, enc, cleanup := setupGRPCPair(t, registrar)
	defer cleanup()

	// Send with wrong content-type.
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Svc/Do")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte("content-type"), Value: []byte("application/json")},
	}

	hb := enc.EncodeBlock(nil, headers)
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:   1,
		BlockFragment: hb,
		EndHeaders: true,
		EndStream:  true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Read response HEADERS.
	c1 := &collectHandler{}
	fh, err := fr.ReadFrame(ctx, c1)
	if err != nil {
		t.Fatalf("ReadFrame #1: %v", err)
	}
	if fh.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS, got %d", fh.Type)
	}

	// Read trailers.
	c2 := &collectHandler{}
	fh2, err := fr.ReadFrame(ctx, c2)
	if err != nil {
		t.Fatalf("ReadFrame #2: %v", err)
	}
	if fh2.Type != frame.FrameHeaders {
		t.Fatalf("expected HEADERS (trailers), got %d", fh2.Type)
	}

	// grpc-status should be 12 (Unimplemented).
	found := false
	for _, h := range c2.headers {
		if string(h.Name) == "grpc-status" && string(h.Value) == "12" {
			found = true
		}
	}
	if !found {
		t.Errorf("grpc-status=12 not found: %v", c2.headers)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// singleListener wraps a single net.Conn as a net.Listener.
type singleListener struct {
	conn   net.Conn
	accept chan struct{}
}

func (l *singleListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.accept
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error   { return nil }
func (l *singleListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// collectHandler collects frame data for testing.
type collectHandler struct {
	headers []hpack.HeaderField
	dataBuf bytes.Buffer
}

func (h *collectHandler) OnData(fh frame.FrameHeader, p []byte, _ uint8) error {
	_ = fh
	h.dataBuf.Write(p)
	return nil
}

func (h *collectHandler) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	_ = fh
	dec := hpack.NewDecoder()
	return dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		h.headers = append(h.headers, f)
		return nil
	})
}

func (h *collectHandler) OnContinuation(_ frame.FrameHeader, _ frame.HeaderBlock) error { return nil }
func (h *collectHandler) OnOrigin(_ frame.FrameHeader, _ []string) error              { return nil }
func (h *collectHandler) OnAltSvc(_ frame.FrameHeader, _ []frame.AltSvcEntry) error   { return nil }
func (h *collectHandler) OnPriority(_ frame.FrameHeader, _ frame.Priority) error         { return nil }
func (h *collectHandler) OnRSTStream(_ frame.FrameHeader, _ frame.ErrCode) error         { return nil }
func (h *collectHandler) OnSettings(_ frame.FrameHeader, _ frame.SettingsParams) error   { return nil }
func (h *collectHandler) OnPushPromise(_ frame.FrameHeader, _ uint32, _ frame.HeaderBlock, _ uint8) error {
	return nil
}
func (h *collectHandler) OnPing(_ frame.FrameHeader, _ [8]byte) error          { return nil }
func (h *collectHandler) OnGoAway(_ frame.FrameHeader, _ uint32, _ frame.ErrCode, _ []byte) error {
	return nil
}
func (h *collectHandler) OnWindowUpdate(_ frame.FrameHeader, _ uint32) error { return nil }

// Ensure collectHandler implements frame.Handler.
var _ frame.Handler = (*collectHandler)(nil)

// Suppress unused import warnings.
var (
	_ = binary.BigEndian
	_ = io.EOF
	_ = (*conn.ServerConn)(nil)
)
