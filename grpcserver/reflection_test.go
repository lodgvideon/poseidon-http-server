package grpcserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// ---------------------------------------------------------------------------
// Reflection proto wire encoding tests
// ---------------------------------------------------------------------------

func TestAppendVarint(t *testing.T) {
	tests := []struct {
		input  uint64
		expect []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
	}
	for _, tc := range tests {
		got := appendVarint(nil, tc.input)
		if !bytes.Equal(got, tc.expect) {
			t.Errorf("appendVarint(%d) = %v, want %v", tc.input, got, tc.expect)
		}
	}
}

func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		input  []byte
		value  uint64
		nbytes int
	}{
		{[]byte{0}, 0, 1},
		{[]byte{1}, 1, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xac, 0x02}, 300, 2},
	}
	for _, tc := range tests {
		val, n := decodeVarint(tc.input)
		if val != tc.value || n != tc.nbytes {
			t.Errorf("decodeVarint(%v) = (%d, %d), want (%d, %d)", tc.input, val, n, tc.value, tc.nbytes)
		}
	}
}

func TestEncodeDecodeVarint_RoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 42, 127, 128, 255, 256, 16384, 1 << 20, 1 << 32} {
		encoded := appendVarint(nil, v)
		decoded, n := decodeVarint(encoded)
		if decoded != v {
			t.Errorf("round-trip(%d): got %d", v, decoded)
		}
		if n != len(encoded) {
			t.Errorf("round-trip(%d): consumed %d, want %d", v, n, len(encoded))
		}
	}
}

func TestEncodeListServiceResponse(t *testing.T) {
	// Encode a list_services response with two service names.
	resp := encodeListServiceResponse([]string{"echo.Echo", "chat.Chat"})

	// Verify we can decode it back by checking for the service names in the bytes.
	// The response contains field 6 (list_service_response) → message with field 1 (service) entries.
	// Each ServiceResponse has field 1 (name) = string.
	// We check the raw bytes contain the encoded service names.
	if !containsSubstring(resp, []byte("echo.Echo")) {
		t.Error("response missing 'echo.Echo'")
	}
	if !containsSubstring(resp, []byte("chat.Chat")) {
		t.Error("response missing 'chat.Chat'")
	}
}

func TestEncodeErrorResponse(t *testing.T) {
	resp := encodeErrorResponse(NotFound, "symbol not found: foo")
	// ErrorResponse has field 1 (error_code) = varint and field 2 (error_message) = string.
	if !containsSubstring(resp, []byte("symbol not found: foo")) {
		t.Error("error response missing message")
	}
}

// ---------------------------------------------------------------------------
// Reflection request decoder tests
// ---------------------------------------------------------------------------

func TestDecodeReflectionRequest_ListServices(t *testing.T) {
	// ServerReflectionRequest { string list_services = 7; }
	// list_services = "" (empty string means "list all")
	reqBytes := encodeReflectionRequestListServices("")
	req, err := decodeReflectionRequest(reqBytes)
	if err != nil {
		t.Fatalf("decodeReflectionRequest: %v", err)
	}
	if !req.listAll {
		t.Error("listAll should be true for list_services request")
	}
}

func TestDecodeReflectionRequest_FileContainingSymbol(t *testing.T) {
	// ServerReflectionRequest { string file_containing_symbol = 4; }
	reqBytes := appendStringField(nil, 4, "echo.Echo")
	req, err := decodeReflectionRequest(reqBytes)
	if err != nil {
		t.Fatalf("decodeReflectionRequest: %v", err)
	}
	if req.fileContainingSymbol != "echo.Echo" {
		t.Errorf("fileContainingSymbol = %q, want 'echo.Echo'", req.fileContainingSymbol)
	}
}

// encodeReflectionRequestListServices encodes a list_services request.
func encodeReflectionRequestListServices(svcFilter string) []byte {
	var buf []byte
	buf = appendStringField(buf, 7, svcFilter)
	return buf
}

// ---------------------------------------------------------------------------
// Reflection integration: ServiceRegistrar
// ---------------------------------------------------------------------------

func TestReflection_ListServices(t *testing.T) {
	sr := NewServiceRegistrar()
	sr.RegisterService(&ServiceDesc{
		Name: "echo.Echo",
		Methods: []MethodDesc{
			{Name: "Get", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }},
		},
	})
	sr.RegisterService(&ServiceDesc{
		Name: "chat.Chat",
		Methods: []MethodDesc{
			{Name: "Send", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }},
		},
	})
	sr.RegisterReflection()

	// Simulate a list_services request via the bidi handler.
	listReq := encodeReflectionRequestListServices("")
	resp := processReflectionRequestForTest(sr, listReq)

	if !containsSubstring(resp, []byte("echo.Echo")) {
		t.Error("reflection list missing 'echo.Echo'")
	}
	if !containsSubstring(resp, []byte("chat.Chat")) {
		t.Error("reflection list missing 'chat.Chat'")
	}
	// Reflection service should NOT appear in list.
	if containsSubstring(resp, []byte("ServerReflection")) {
		t.Error("reflection service should not appear in list")
	}
}

func TestReflection_FileContainingSymbol_WithDescriptor(t *testing.T) {
	sr := NewServiceRegistrar()

	// Register a dummy FileDescriptorProto (just some bytes).
	dummyDescriptor := []byte{0x0a, 0x04, "test"[0], "test"[1], "test"[2], "test"[3]}
	sr.RegisterFileDescriptor([]string{"echo.Echo"}, dummyDescriptor)
	sr.RegisterService(&ServiceDesc{
		Name: "echo.Echo",
		Methods: []MethodDesc{
			{Name: "Get", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }},
		},
	})
	sr.RegisterReflection()

	// Query for the symbol.
	req := appendStringField(nil, 4, "echo.Echo")
	resp := processReflectionRequestForTest(sr, req)

	// Should contain the file descriptor bytes.
	if !containsSubstring(resp, dummyDescriptor) {
		t.Error("file_descriptor_response should contain the descriptor bytes")
	}
}

func TestReflection_FileContainingSymbol_NotFound(t *testing.T) {
	sr := NewServiceRegistrar()
	sr.RegisterService(&ServiceDesc{
		Name: "echo.Echo",
		Methods: []MethodDesc{
			{Name: "Get", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }},
		},
	})
	sr.RegisterReflection()

	req := appendStringField(nil, 4, "unknown.Service")
	resp := processReflectionRequestForTest(sr, req)

	// Should contain error response with NotFound code.
	if !containsSubstring(resp, []byte("symbol not found")) {
		t.Error("expected 'symbol not found' error response")
	}
}

func TestReflection_FileByFilename_NotFound(t *testing.T) {
	sr := NewServiceRegistrar()
	sr.RegisterReflection()

	req := appendStringField(nil, 3, "nonexistent.proto")
	resp := processReflectionRequestForTest(sr, req)

	if !containsSubstring(resp, []byte("file not found")) {
		t.Error("expected 'file not found' error response")
	}
}

func TestReflection_RegisterReflection_BothVersions(t *testing.T) {
	sr := NewServiceRegistrar()
	sr.RegisterReflection()

	// Both v1alpha and v1 should be registered.
	if sr.lookup("/"+reflectionServiceV1Alpha+"/"+reflectionMethod) == nil {
		t.Error("v1alpha reflection not registered")
	}
	if sr.lookup("/"+reflectionServiceV1+"/"+reflectionMethod) == nil {
		t.Error("v1 reflection not registered")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// processReflectionRequestForTest decodes the request and calls the registrar's
// internal processing method for testing.
func processReflectionRequestForTest(sr *ServiceRegistrar, reqBytes []byte) []byte {
	req, _ := decodeReflectionRequest(reqBytes)
	return sr.processReflectionRequest(req)
}

func containsSubstring(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}

// ---------------------------------------------------------------------------
// Pure helpers (Batch 2 of coverage push)
// ---------------------------------------------------------------------------

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"equal", []byte("abc"), []byte("abc"), true},
		{"different length", []byte("ab"), []byte("abc"), false},
		{"same length different content", []byte("abc"), []byte("abd"), false},
		{"empty", []byte{}, []byte{}, true},
		{"empty vs non-empty", []byte{}, []byte("x"), false},
		{"non-empty vs empty", []byte("x"), []byte{}, false},
	}
	for _, tc := range tests {
		if got := bytesEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: bytesEqual(%v,%v) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBytesContains(t *testing.T) {
	tests := []struct {
		name     string
		haystack []byte
		needle   []byte
		want     bool
	}{
		{"empty needle always matches", []byte("abc"), nil, true},
		{"empty needle matches empty haystack", nil, nil, true},
		{"needle longer than haystack", []byte("ab"), []byte("abc"), false},
		{"prefix match", []byte("abcdef"), []byte("abc"), true},
		{"middle match", []byte("xxABCyy"), []byte("ABC"), true},
		{"suffix match", []byte("abcdef"), []byte("def"), true},
		{"no match", []byte("abcdef"), []byte("xyz"), false},
		{"haystack shorter than needle", []byte("a"), []byte("ab"), false},
	}
	for _, tc := range tests {
		if got := bytesContains(tc.haystack, tc.needle); got != tc.want {
			t.Errorf("%s: bytesContains(%v,%v) = %v, want %v", tc.name, tc.haystack, tc.needle, got, tc.want)
		}
	}
}

func TestProtoContainsService(t *testing.T) {
	// Heuristic: looks for {byte(len(name)) + name} as a length-prefixed
	// string in protobuf wire format. Names of length >= 128 will not match
	// because the length field becomes 2 bytes; we only test short names.
	tests := []struct {
		name        string
		protoBytes  []byte
		serviceName string
		want        bool
	}{
		{
			name:        "match present",
			protoBytes:  []byte{0x0a, 4, 'E', 'c', 'h', 'o'},
			serviceName: "Echo",
			want:        true,
		},
		{
			name:        "match absent",
			protoBytes:  []byte{0x0a, 4, 'M', 'a', 'i', 'n'},
			serviceName: "Echo",
			want:        false,
		},
		{
			name:        "empty haystack",
			protoBytes:  nil,
			serviceName: "Echo",
			want:        false,
		},
		{
			name:        "wrong length prefix",
			protoBytes:  []byte{0x0a, 3, 'E', 'c', 'h', 'o'},
			serviceName: "Echo",
			want:        false,
		},
	}
	for _, tc := range tests {
		if got := protoContainsService(tc.protoBytes, tc.serviceName); got != tc.want {
			t.Errorf("%s: protoContainsService(%v,%q) = %v, want %v",
				tc.name, tc.protoBytes, tc.serviceName, got, tc.want)
		}
	}
}

func TestAppendIfUnique(t *testing.T) {
	// Fresh entries are appended.
	got := appendIfUnique(nil, []byte("a"))
	if len(got) != 1 || !bytesEqual(got[0], []byte("a")) {
		t.Fatalf("after first append: %v", got)
	}
	// Duplicate is NOT appended (the dedup branch).
	got = appendIfUnique(got, []byte("a"))
	if len(got) != 1 {
		t.Fatalf("after duplicate: len = %d, want 1", len(got))
	}
	// New entry appended alongside the existing one.
	got = appendIfUnique(got, []byte("b"))
	if len(got) != 2 {
		t.Fatalf("after second new: len = %d, want 2", len(got))
	}
}

func TestSkipField(t *testing.T) {
	// Wire type 0 (VARINT): 1-byte varint 0x05, 2-byte varint 0x80 0x01.
	if pos := skipField([]byte{0x05}, 0, 0); pos != 1 {
		t.Errorf("VARINT 1-byte: pos = %d, want 1", pos)
	}
	if pos := skipField([]byte{0x80, 0x01}, 0, 0); pos != 2 {
		t.Errorf("VARINT 2-byte: pos = %d, want 2", pos)
	}
	// VARINT with continuation bit set but no terminator → -1.
	if pos := skipField([]byte{0x80}, 0, 0); pos != -1 {
		t.Errorf("VARINT unterminated: pos = %d, want -1", pos)
	}
	// Wire type 1 (I64): skip 8 bytes.
	if pos := skipField(make([]byte, 8), 0, 1); pos != 8 {
		t.Errorf("I64: pos = %d, want 8", pos)
	}
	// Wire type 5 (I32): skip 4 bytes.
	if pos := skipField(make([]byte, 4), 0, 5); pos != 4 {
		t.Errorf("I32: pos = %d, want 4", pos)
	}
	// Wire type 2 (LEN): read varint length, advance past it.
	// Field = { tag-varint already consumed, [0x03, 'a','b','c'] }
	if pos := skipField([]byte{0x03, 'a', 'b', 'c'}, 0, 2); pos != 4 {
		t.Errorf("LEN 3 bytes: pos = %d, want 4", pos)
	}
	// Wire type 2 with truncated length varint → -1.
	if pos := skipField([]byte{0x80}, 0, 2); pos != -1 {
		t.Errorf("LEN truncated varint: pos = %d, want -1", pos)
	}
	// Wire type 2 with length that overflows buffer → -1.
	if pos := skipField([]byte{0x05, 'a'}, 0, 2); pos != -1 {
		t.Errorf("LEN overflow: pos = %d, want -1", pos)
	}
	// Invalid wire type (3, start group) returns -1.
	if pos := skipField([]byte{0x00}, 0, 3); pos != -1 {
		t.Errorf("wire type 3: pos = %d, want -1", pos)
	}
}

func TestEncodeExtensionNumberResponse(t *testing.T) {
	// Empty numbers.
	got := encodeExtensionNumberResponse("", nil)
	if len(got) == 0 {
		t.Fatal("got empty response for nil numbers")
	}
	// Non-empty type name and numbers.
	got = encodeExtensionNumberResponse("grpc.reflection.v1alpha.ServerReflectionRequest", []int32{100, 200, 300})
	if len(got) == 0 {
		t.Fatal("got empty response for non-empty numbers")
	}
}

func TestEncodeReflectionResponse(t *testing.T) {
	// All args present.
	got := encodeReflectionResponse("example.com", []byte{0x0a, 0x00}, []byte{0x0a, 0x00})
	if len(got) == 0 {
		t.Fatal("got empty response for full args")
	}
	// Empty host.
	got = encodeReflectionResponse("", []byte{0x0a, 0x00}, []byte{0x0a, 0x00})
	if len(got) == 0 {
		t.Fatal("got empty response for empty host")
	}
	// Empty original request.
	got = encodeReflectionResponse("example.com", nil, []byte{0x0a, 0x00})
	if len(got) == 0 {
		t.Fatal("got empty response for nil original")
	}
	// Empty message response.
	got = encodeReflectionResponse("example.com", []byte{0x0a, 0x00}, nil)
	if len(got) == 0 {
		t.Fatal("got empty response for nil message")
	}
}

// ---------------------------------------------------------------------------
// reflectionHandler integration (Batch 4 of coverage push)
// ---------------------------------------------------------------------------

// TestReflectionHandler_EOFReturnsNil verifies that a clean io.EOF from
// recv terminates the loop with nil (graceful end-of-stream).
func TestReflectionHandler_EOFReturnsNil(t *testing.T) {
	r := NewServiceRegistrar()
	var sent [][]byte
	send := func(b []byte) error {
		sent = append(sent, b)
		return nil
	}
	recv := func() ([]byte, error) { return nil, io.EOF }

	if err := r.reflectionHandler(context.Background(), recv, send); err != nil {
		t.Fatalf("reflectionHandler(EOF) = %v, want nil", err)
	}
	if len(sent) != 0 {
		t.Errorf("sent %d responses on EOF, want 0", len(sent))
	}
}

// TestReflectionHandler_MalformedThenGood drives the "send error response
// then continue" branch (reflection.go:302-310).
func TestReflectionHandler_MalformedThenGood(t *testing.T) {
	r := NewServiceRegistrar()
	// Register a service so the good request can produce a real response.
	r.RegisterFileDescriptorSet(buildEchoFDS())

	// recv returns: malformed bytes, then a valid list_services request,
	// then io.EOF.
	buildListReq := func() []byte {
		// ServerReflectionRequest{ list_services = "*" }
		// field 4 (string, LEN) tag = (4<<3)|2 = 0x22
		// "*" = 1 byte
		return []byte{0x22, 0x01, '*'}
	}
	calls := 0
	recv := func() ([]byte, error) {
		calls++
		switch calls {
		case 1:
			return []byte{0xff, 0xfe, 0xfd}, nil // malformed
		case 2:
			return buildListReq(), nil // valid
		default:
			return nil, io.EOF
		}
	}
	var sent [][]byte
	send := func(b []byte) error {
		sent = append(sent, b)
		return nil
	}

	if err := r.reflectionHandler(context.Background(), recv, send); err != nil {
		t.Fatalf("reflectionHandler = %v, want nil", err)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d responses, want 2 (error + list_services)", len(sent))
	}
}

// TestReflectionHandler_SendErrorPropagates verifies that a send error
// stops the loop and is returned to the caller.
func TestReflectionHandler_SendErrorPropagates(t *testing.T) {
	r := NewServiceRegistrar()
	recv := func() ([]byte, error) {
		return []byte{0xff, 0xfe}, nil // malformed → triggers error response
	}
	wantErr := errors.New("send failed")
	send := func(_ []byte) error { return wantErr }

	err := r.reflectionHandler(context.Background(), recv, send)
	if !errors.Is(err, wantErr) {
		t.Errorf("reflectionHandler = %v, want %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------------
// decodeReflectionRequest error cases (Batch 7 of coverage push)
// ---------------------------------------------------------------------------

func TestDecodeReflectionRequest_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		// Tag varint with continuation bit set but no terminator.
		{"tag varint unterminated", []byte{0x80}},
		// pos >= len(data) when reading the length varint: a single tag
		// byte with no body triggers the "truncated" branch (pos >= len
		// after consuming the tag).
		{"truncated length", []byte{0x0a}},
		// Tag byte followed by truncated length varint.
		{"length varint unterminated", []byte{0x0a, 0x80}},
		// Length varint that overflows the buffer.
		{"length overflow", []byte{0x0a, 0x05, 'a'}},
		// Wire-type-0 as the first field with an unterminated varint
		// payload.
		{"wire type 0 unterminated", []byte{0x08, 0x80}},
		// Wire type 1 (I64) is not allowed in this decoder.
		{"wire type 1 rejected", []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		// Wire type 3 (start group, deprecated) is not allowed.
		{"wire type 3 rejected", []byte{0x0b, 0x00}},
	}
	for _, tc := range tests {
		_, err := decodeReflectionRequest(tc.data)
		if err == nil {
			t.Errorf("%s: decodeReflectionRequest(%v) = nil, want error", tc.name, tc.data)
		}
	}
}

// buildEchoFDS constructs a minimal FileDescriptorSet containing a single
// FileDescriptorProto named "echo.proto" in package "echo.v1" with one
// service "Echo". All fields are encoded with literal bytes; do NOT use
// appendStringField etc. to test the helper (that would be a tautology).
func buildEchoFDS() []byte {
	// ServiceDescriptorProto: { field 1 (name) = "Echo" }
	// tag(1, LEN) = 0x0a
	// length-prefixed bytes: 0x04 'E' 'c' 'h' 'o'
	serviceProto := []byte{0x0a, 0x04, 'E', 'c', 'h', 'o'}

	// FileDescriptorProto:
	//   field 1 (name)   = "echo.proto"
	//   field 2 (package) = "echo.v1"
	//   field 6 (service) = serviceProto
	// tag(1, LEN) = 0x0a; tag(2, LEN) = 0x12; tag(6, LEN) = 0x32
	var fdp []byte
	fdp = append(fdp, 0x0a)                            // field 1 tag (LEN)
	fdp = append(fdp, byte(len("echo.proto")))         // length
	fdp = append(fdp, "echo.proto"...)                 // value
	fdp = append(fdp, 0x12)                            // field 2 tag (LEN)
	fdp = append(fdp, byte(len("echo.v1")))            // length (7)
	fdp = append(fdp, "echo.v1"...)                    // value
	fdp = append(fdp, 0x32)                            // field 6 tag (LEN)
	fdp = append(fdp, byte(len(serviceProto)))
	fdp = append(fdp, serviceProto...)

	// FileDescriptorSet: { field 1 (file) = FileDescriptorProto }
	// tag(1, LEN) = 0x0a
	fds := append([]byte{0x0a}, 0x00) // placeholder for length
	fds = append(fds, fdp...)
	fds[1] = byte(len(fdp))
	return fds
}

func TestRegisterFileDescriptorSet_HappyPath(t *testing.T) {
	r := NewServiceRegistrar()
	fds := buildEchoFDS()

	r.RegisterFileDescriptorSet(fds)

	// Lookup by filename.
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.reflection == nil {
		t.Fatal("reflection registry not initialised")
	}
	if got, ok := r.reflection.filesByName["echo.proto"]; !ok || len(got) == 0 {
		t.Errorf("filesByName[echo.proto] = (%v, %v), want (non-empty, true)", got, ok)
	}
	// Lookup by fully-qualified service name.
	if got, ok := r.reflection.descriptors["echo.v1.Echo"]; !ok || len(got) == 0 {
		t.Errorf("descriptors[echo.v1.Echo] = (%v, %v), want (non-empty, true)", got, ok)
	}
	// allFiles should have exactly one entry (no dedup yet).
	if len(r.reflection.allFiles) != 1 {
		t.Errorf("allFiles len = %d, want 1", len(r.reflection.allFiles))
	}
}

func TestRegisterFileDescriptorSet_Idempotent(t *testing.T) {
	r := NewServiceRegistrar()
	fds := buildEchoFDS()

	r.RegisterFileDescriptorSet(fds)
	r.RegisterFileDescriptorSet(fds) // second call

	r.mu.RLock()
	defer r.mu.RUnlock()
	// Same FileDescriptorSet registered twice — allFiles should still be 1.
	if len(r.reflection.allFiles) != 1 {
		t.Errorf("allFiles len after double register = %d, want 1", len(r.reflection.allFiles))
	}
}

func TestExtractFileProtos(t *testing.T) {
	fds := buildEchoFDS()
	files := extractFileProtos(fds)
	if len(files) != 1 {
		t.Fatalf("extractFileProtos returned %d files, want 1", len(files))
	}
	// The extracted file should be the inner FileDescriptorProto.
	// Verify by checking that "echo.proto" can be extracted from it.
	if name := extractStringField(files[0], 1); name != "echo.proto" {
		t.Errorf("extractStringField(name) = %q, want echo.proto", name)
	}
	// Empty input.
	if got := extractFileProtos(nil); len(got) != 0 {
		t.Errorf("extractFileProtos(nil) = %d, want 0", len(got))
	}
	// Truncated varint (no continuation terminator).
	truncated := []byte{0x80}
	if got := extractFileProtos(truncated); len(got) != 0 {
		t.Errorf("extractFileProtos(truncated varint) = %d, want 0", len(got))
	}
}

func TestExtractServiceNames(t *testing.T) {
	// Build a FileDescriptorProto directly (no FDS wrapper).
	serviceProto := []byte{0x0a, 0x04, 'E', 'c', 'h', 'o'}
	var fdp []byte
	fdp = append(fdp, 0x12, byte(len("echo.v1")))
	fdp = append(fdp, "echo.v1"...)
	fdp = append(fdp, 0x32, byte(len(serviceProto)))
	fdp = append(fdp, serviceProto...)

	names := extractServiceNames(fdp)
	if len(names) != 1 || names[0] != "echo.v1.Echo" {
		t.Errorf("extractServiceNames = %v, want [echo.v1.Echo]", names)
	}

	// FileDescriptorProto with one service and no package — should be
	// just the service name.
	var fdpNoPkg []byte
	fdpNoPkg = append(fdpNoPkg, 0x32, byte(len(serviceProto)))
	fdpNoPkg = append(fdpNoPkg, serviceProto...)
	names = extractServiceNames(fdpNoPkg)
	if len(names) != 1 || names[0] != "Echo" {
		t.Errorf("extractServiceNames(no pkg) = %v, want [Echo]", names)
	}
}
