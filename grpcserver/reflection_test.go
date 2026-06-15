package grpcserver

import (
	"bytes"
	"context"
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
