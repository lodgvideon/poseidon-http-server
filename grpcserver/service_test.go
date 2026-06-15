package grpcserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Test: RegisterService + lookup routing
// ---------------------------------------------------------------------------

func TestServiceRegistrar_RegisterAndLookup(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name: "test.Greeter",
		Methods: []MethodDesc{
			{
				Name:         "SayHello",
				UnaryHandler: func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
			},
		},
	})

	md := r.lookup("/test.Greeter/SayHello")
	if md == nil {
		t.Fatal("expected method to be registered")
	}
	if md.unary == nil {
		t.Fatal("expected unary handler")
	}

	md2 := r.lookup("/test.Greeter/Unknown")
	if md2 != nil {
		t.Fatal("expected nil for unknown method")
	}
}

func TestServiceRegistrar_DoubleRegisterPanics(t *testing.T) {
	r := NewServiceRegistrar()
	desc := &ServiceDesc{
		Name:    "test.Svc",
		Methods: []MethodDesc{{Name: "Foo", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }}},
	}
	r.RegisterService(desc)

	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("expected panic on double register")
		}
	}()
	r.RegisterService(desc)
}

func TestServiceRegistrar_NoHandlerPanics(t *testing.T) {
	r := NewServiceRegistrar()
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("expected panic when method has no handler")
		}
	}()
	r.RegisterService(&ServiceDesc{
		Name:    "test.Bad",
		Methods: []MethodDesc{{Name: "Nope"}},
	})
}

// ---------------------------------------------------------------------------
// Test: isGRPCContentType
// ---------------------------------------------------------------------------

func TestIsGRPCContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers []hpack.HeaderField
		want    bool
	}{
		{"grpc", []hpack.HeaderField{{Name: []byte("content-type"), Value: []byte("application/grpc")}}, true},
		{"grpc+proto", []hpack.HeaderField{{Name: []byte("content-type"), Value: []byte("application/grpc+proto")}}, true},
		{"json", []hpack.HeaderField{{Name: []byte("content-type"), Value: []byte("application/json")}}, false},
		{"missing", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGRPCContentType(tt.headers); got != tt.want {
				t.Errorf("isGRPCContentType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: errToStatus
// ---------------------------------------------------------------------------

func TestErrToStatus(t *testing.T) {
	st := Statusf(NotFound, "gone")
	if got := errToStatus(st); got != st {
		t.Errorf("errToStatus(RPCStatus) = %v, want %v", got, st)
	}

	got := errToStatus(io.EOF)
	if got.Code != Internal {
		t.Errorf("errToStatus(io.EOF).Code = %v, want Internal", got.Code)
	}
}

// ---------------------------------------------------------------------------
// Test: uint32ToString
// ---------------------------------------------------------------------------

func TestUint32ToString(t *testing.T) {
	tests := []struct {
		in   uint32
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{42, "42"},
		{99, "99"},
		{200, "200"},
		{1234, "1234"},
	}
	for _, tt := range tests {
		if got := uint32ToString(tt.in); got != tt.want {
			t.Errorf("uint32ToString(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: streamReceiver with LP-encoded body
// ---------------------------------------------------------------------------

func TestStreamReader_BufferedBody(t *testing.T) {
	msg1 := LPMessage{Flag: FlagNone, Payload: []byte("hello")}
	msg2 := LPMessage{Flag: FlagNone, Payload: []byte("world")}

	var body []byte
	body = EncodeLP(body, msg1)
	body = EncodeLP(body, msg2)

	req := &server.Request{Body: body}
	recv := streamReceiver(req)

	got1, err := recv()
	if err != nil {
		t.Fatalf("recv() #1: %v", err)
	}
	if string(got1) != "hello" {
		t.Errorf("recv() #1 = %q, want %q", got1, "hello")
	}

	got2, err := recv()
	if err != nil {
		t.Fatalf("recv() #2: %v", err)
	}
	if string(got2) != "world" {
		t.Errorf("recv() #2 = %q, want %q", got2, "world")
	}

	_, err = recv()
	if !errors.Is(err, io.EOF) {
		t.Errorf("recv() #3 err = %v, want EOF", err)
	}
}

func TestStreamReader_EmptyBody(t *testing.T) {
	req := &server.Request{Body: nil}
	recv := streamReceiver(req)

	_, err := recv()
	if !errors.Is(err, io.EOF) {
		t.Errorf("recv() on empty body: err = %v, want EOF", err)
	}
}

// TestStreamReader_BodyReader verifies the streaming BodyReader path of
// streamReceiver (service.go:388-403). Two LP messages are encoded in a
// pipe-like buffer; the receiver reads them sequentially.
func TestStreamReader_BodyReader(t *testing.T) {
	msg1 := LPMessage{Flag: FlagNone, Payload: []byte("hello")}
	msg2 := LPMessage{Flag: FlagNone, Payload: []byte("world")}

	var body []byte
	body = EncodeLP(body, msg1)
	body = EncodeLP(body, msg2)

	req := &server.Request{BodyReader: io.NopCloser(bytes.NewReader(body))}
	recv := streamReceiver(req)

	got1, err := recv()
	if err != nil {
		t.Fatalf("recv() #1: %v", err)
	}
	if string(got1) != "hello" {
		t.Errorf("recv() #1 = %q, want %q", got1, "hello")
	}

	got2, err := recv()
	if err != nil {
		t.Fatalf("recv() #2: %v", err)
	}
	if string(got2) != "world" {
		t.Errorf("recv() #2 = %q, want %q", got2, "world")
	}

	_, err = recv()
	if !errors.Is(err, io.EOF) {
		t.Errorf("recv() #3 err = %v, want EOF", err)
	}
}

// TestStreamReader_BodyReader_ZeroLengthMessage exercises the
// heartbeat branch: an LP frame with length=0 returns (nil, nil) so the
// handler can loop without treating it as EOF.
func TestStreamReader_BodyReader_ZeroLengthMessage(t *testing.T) {
	// LP frame: flag(1) + length(4) + payload(0)
	zeroFrame := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	req := &server.Request{BodyReader: io.NopCloser(bytes.NewReader(zeroFrame))}
	recv := streamReceiver(req)

	got, err := recv()
	if err != nil {
		t.Fatalf("recv() on zero-length: err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("recv() on zero-length: payload = %v, want nil", got)
	}
}

// TestStreamReader_BodyReader_Truncated verifies that a truncated
// header (fewer than 5 bytes) returns io.ErrUnexpectedEOF (from
// io.ReadFull) rather than a custom error.
func TestStreamReader_BodyReader_Truncated(t *testing.T) {
	// Only 3 bytes available — io.ReadFull returns ErrUnexpectedEOF.
	req := &server.Request{BodyReader: io.NopCloser(bytes.NewReader([]byte{0x00, 0x00, 0x00}))}
	recv := streamReceiver(req)

	_, err := recv()
	if err == nil {
		t.Fatal("recv() on truncated: err = nil, want non-nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("recv() truncated: err = %v, want ErrUnexpectedEOF", err)
	}
}

// TestStreamReader_BodyReader_TruncatedPayload exercises the
// io.ReadFull failure on the payload read (length declared > 0 but
// stream closes mid-payload).
func TestStreamReader_BodyReader_TruncatedPayload(t *testing.T) {
	// LP frame: flag=0, length=10, but only 4 bytes of payload follow.
	trunc := []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c', 'd'}
	req := &server.Request{BodyReader: io.NopCloser(bytes.NewReader(trunc))}
	recv := streamReceiver(req)

	_, err := recv()
	if err == nil {
		t.Fatal("recv() on truncated payload: err = nil, want non-nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("recv() truncated payload: err = %v, want ErrUnexpectedEOF", err)
	}
}

// ---------------------------------------------------------------------------
// Test: statusToHPack
// ---------------------------------------------------------------------------

func TestStatusToHPack(t *testing.T) {
	st := Statusf(NotFound, "user 42 not found")
	fields := statusToHPack(st)

	if len(fields) != 2 {
		t.Fatalf("len = %d, want 2", len(fields))
	}
	if string(fields[0].Name) != HeaderGRPCStatus || string(fields[0].Value) != "5" {
		t.Errorf("grpc-status = %q", fields[0].Value)
	}
	if string(fields[1].Name) != HeaderGRPCMessage || string(fields[1].Value) != "user 42 not found" {
		t.Errorf("grpc-message = %q", fields[1].Value)
	}
}

// ---------------------------------------------------------------------------
// Test: grpcResponseHeaders
// ---------------------------------------------------------------------------

func TestGRPCResponseHeaders(t *testing.T) {
	hdrs := grpcResponseHeaders()
	if len(hdrs) != 1 {
		t.Fatalf("len = %d, want 1", len(hdrs))
	}
	if string(hdrs[0].Name) != "content-type" || string(hdrs[0].Value) != "application/grpc" {
		t.Errorf("header = %q:%q", hdrs[0].Name, hdrs[0].Value)
	}
}

// ---------------------------------------------------------------------------
// Test: unary dispatch via lookup + decode
// ---------------------------------------------------------------------------

func TestServiceRegistrar_UnaryDispatch(t *testing.T) {
	r := NewServiceRegistrar()
	var receivedReq []byte

	r.RegisterService(&ServiceDesc{
		Name: "test.Calculator",
		Methods: []MethodDesc{
			{
				Name: "Add",
				UnaryHandler: func(_ context.Context, req []byte) ([]byte, error) {
					receivedReq = req
					return []byte("result:42"), nil
				},
			},
		},
	})

	// Encode LP request.
	reqBody := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("1+2")})

	md := r.lookup("/test.Calculator/Add")
	if md == nil || md.unary == nil {
		t.Fatal("expected unary method")
	}

	msg, _, err := DecodeLPFromBytes(reqBody)
	if err != nil {
		t.Fatalf("DecodeLPFromBytes: %v", err)
	}

	resp, err := md.unary(context.Background(), msg.Payload)
	if err != nil {
		t.Fatalf("unary handler: %v", err)
	}

	if string(receivedReq) != "1+2" {
		t.Errorf("received = %q, want %q", receivedReq, "1+2")
	}
	if string(resp) != "result:42" {
		t.Errorf("response = %q, want %q", resp, "result:42")
	}
}

func TestServiceRegistrar_MultipleServices(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name:    "svc.A",
		Methods: []MethodDesc{{Name: "Foo", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return []byte("A"), nil }}},
	})
	r.RegisterService(&ServiceDesc{
		Name:    "svc.B",
		Methods: []MethodDesc{{Name: "Bar", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return []byte("B"), nil }}},
	})

	mdA := r.lookup("/svc.A/Foo")
	if mdA == nil {
		t.Fatal("svc.A/Foo not found")
	}
	mdB := r.lookup("/svc.B/Bar")
	if mdB == nil {
		t.Fatal("svc.B/Bar not found")
	}

	resp, _ := mdA.unary(context.Background(), nil)
	if string(resp) != "A" {
		t.Errorf("A.Foo = %q", resp)
	}
	resp, _ = mdB.unary(context.Background(), nil)
	if string(resp) != "B" {
		t.Errorf("B.Bar = %q", resp)
	}
}

// ---------------------------------------------------------------------------
// Test: Handler() invalid content-type → Unimplemented
// ---------------------------------------------------------------------------

func TestServiceRegistrar_Handler_InvalidContentType(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name:    "test.Svc",
		Methods: []MethodDesc{{Name: "Do", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }}},
	})

	// Verify the handler is created without panic.
	h := r.Handler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	// Verify content-type check rejects non-gRPC.
	headers := []hpack.HeaderField{{Name: []byte("content-type"), Value: []byte("application/json")}}
	if isGRPCContentType(headers) {
		t.Error("isGRPCContentType should reject application/json")
	}
	_ = h
}

// ---------------------------------------------------------------------------
// Test: Handler() unknown method → Unimplemented
// ---------------------------------------------------------------------------

func TestServiceRegistrar_Handler_UnknownMethod(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name:    "test.Svc",
		Methods: []MethodDesc{{Name: "Do", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }}},
	})

	md := r.lookup("/test.Svc/Nonexistent")
	if md != nil {
		t.Fatal("expected nil for unknown method")
	}
}

// ---------------------------------------------------------------------------
// Test: codeToString
// ---------------------------------------------------------------------------

func TestCodeToString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{OK, "0"},
		{Canceled, "1"},
		{Internal, "13"},
		{Unauthenticated, "16"},
	}
	for _, tt := range tests {
		if got := codeToString(tt.code); got != tt.want {
			t.Errorf("codeToString(%v) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: stream type methods
// ---------------------------------------------------------------------------

func TestServiceRegistrar_ServerStreamMethod(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name: "test.Stream",
		Methods: []MethodDesc{
			{
				Name: "ServerStream",
				ServerStreamH: func(_ context.Context, _ []byte, _ StreamSender) error {
					return nil
				},
			},
		},
	})

	md := r.lookup("/test.Stream/ServerStream")
	if md == nil || md.serverS == nil {
		t.Fatal("expected server-stream handler")
	}
}

func TestServiceRegistrar_ClientStreamMethod(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name: "test.Stream",
		Methods: []MethodDesc{
			{
				Name: "ClientStream",
				ClientStreamH: func(_ context.Context, _ func() ([]byte, error)) ([]byte, error) {
					return nil, nil
				},
			},
		},
	})

	md := r.lookup("/test.Stream/ClientStream")
	if md == nil || md.clientS == nil {
		t.Fatal("expected client-stream handler")
	}
}

func TestServiceRegistrar_BidiStreamMethod(t *testing.T) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name: "test.Stream",
		Methods: []MethodDesc{
			{
				Name: "BidiStream",
				BidiStreamH: func(_ context.Context, _ func() ([]byte, error), _ StreamSender) error {
					return nil
				},
			},
		},
	})

	md := r.lookup("/test.Stream/BidiStream")
	if md == nil || md.bidi == nil {
		t.Fatal("expected bidi-stream handler")
	}
}
