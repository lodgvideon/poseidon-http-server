package grpcserver

import (
	"context"
	"errors"
	"io"
)

// ---------------------------------------------------------------------------
// gRPC Server Reflection (grpc.reflection.v1alpha)
//
// Implements the ServerReflectionInfo bidi-streaming RPC so that tools like
// grpcurl can discover services, describe methods, and invoke them without
// .proto files at the client side.
//
// Zero external dependencies: protobuf wire format is hand-encoded.
// ---------------------------------------------------------------------------

// Reflection service path (v1alpha — what grpcurl uses by default).
const (
	reflectionServiceV1Alpha = "grpc.reflection.v1alpha.ServerReflection"
	reflectionServiceV1      = "grpc.reflection.v1.ServerReflection"
	reflectionMethod         = "ServerReflectionInfo"
)

// FileDescriptor holds raw FileDescriptorProto bytes for a service.
// Users obtain these from `protoc --descriptor_set_out` or from
// generated Go code's file descriptor variable.
type FileDescriptor struct {
	// Name is the full service name this descriptor belongs to, e.g. "echo.Echo".
	Name string

	// Data is the serialised FileDescriptorProto (wire bytes).
	Data []byte
}

// reflectionRegistry holds file descriptors for reflection queries.
type reflectionRegistry struct {
	// descriptors maps service name → FileDescriptorProto bytes.
	// Multiple services can share one FileDescriptorProto.
	descriptors map[string][]byte

	// filesByName maps filename → FileDescriptorProto bytes (for file_by_filename).
	filesByName map[string][]byte

	// ordered list of all unique FileDescriptorProto bytes (for symbol resolution).
	allFiles [][]byte
}

func newReflectionRegistry() *reflectionRegistry {
	return &reflectionRegistry{
		descriptors: make(map[string][]byte),
		filesByName: make(map[string][]byte),
	}
}

// RegisterFileDescriptor associates a FileDescriptorProto with one or more
// service names. This enables grpcurl describe and grpcurl invoke.
//
// To get the bytes from generated Go code:
//
//	import echo_pb "path/to/echo"
//	// echo_pb.File_echo_proto.RawDescriptor is []byte
func (r *ServiceRegistrar) RegisterFileDescriptor(services []string, fileDescriptorBytes []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reflection == nil {
		r.reflection = newReflectionRegistry()
	}

	for _, svc := range services {
		r.reflection.descriptors[svc] = fileDescriptorBytes
	}

	// Deduplicate by pointer identity of the byte slice.
	r.reflection.allFiles = appendIfUnique(r.reflection.allFiles, fileDescriptorBytes)
}


// RegisterFileDescriptorSet extracts individual FileDescriptorProto entries
// from a FileDescriptorSet (produced by `protoc --descriptor_set_out`) and
// registers them. Each file is indexed by filename and by any services it
// defines.
func (r *ServiceRegistrar) RegisterFileDescriptorSet(fileDescriptorSetBytes []byte) {
	files := extractFileProtos(fileDescriptorSetBytes)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reflection == nil {
		r.reflection = newReflectionRegistry()
	}

	for _, fdb := range files {
		// Index by filename.
		if name := extractStringField(fdb, 1); name != "" {
			r.reflection.filesByName[name] = fdb
		}
		// Index by services defined in this file.
		for _, svc := range extractServiceNames(fdb) {
			r.reflection.descriptors[svc] = fdb
		}
		r.reflection.allFiles = appendIfUnique(r.reflection.allFiles, fdb)
	}
}

// extractFileProtos extracts individual FileDescriptorProto byte slices from
// a FileDescriptorSet protobuf. FileDescriptorSet has:
//
//	repeated FileDescriptorProto file = 1;
//nolint:gosec // protobuf wire format: int conversions are safe for field tags and lengths
func extractFileProtos(fdsBytes []byte) [][]byte {
	var files [][]byte
	pos := 0
	for pos < len(fdsBytes) {
		tag, n := decodeVarint(fdsBytes[pos:])
		if n == 0 {
			break
		}
		pos += n
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)
		if fieldNum == 1 && wireType == 2 {
			length, n := decodeVarint(fdsBytes[pos:])
			if n == 0 {
				break
			}
			pos += n
			if pos+int(length) > len(fdsBytes) {
				break
			}
			files = append(files, fdsBytes[pos:pos+int(length)])
			pos += int(length)
		} else {
			pos = skipField(fdsBytes, pos, wireType)
			if pos < 0 {
				break
			}
		}
	}
	return files
}

// extractStringField returns the first string field with the given number.
//nolint:gosec // protobuf wire format: int conversions are safe for field tags and lengths
func extractStringField(data []byte, fieldNum int) string {
	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		fn := int(tag >> 3)
		wt := int(tag & 0x7)
		if wt == 2 {
			length, n := decodeVarint(data[pos:])
			if n == 0 {
				break
			}
			pos += n
			if fn == fieldNum {
				return string(data[pos : pos+int(length)])
			}
			pos += int(length)
		} else {
			pos = skipField(data, pos, wt)
			if pos < 0 {
				break
			}
		}
	}
	return ""
}

// extractServiceNames returns fully-qualified service names from a
// FileDescriptorProto. Services are field 6, each containing a
// ServiceDescriptorProto with name at field 1.
//nolint:gosec // protobuf wire format: int conversions are safe for field tags and lengths
func extractServiceNames(fdp []byte) []string {
	pkg := extractStringField(fdp, 2) // package = field 2
	pos := 0
	var names []string
	for pos < len(fdp) {
		tag, n := decodeVarint(fdp[pos:])
		if n == 0 {
			break
		}
		pos += n
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)
		if wireType != 2 {
			pos = skipField(fdp, pos, wireType)
			if pos < 0 {
				break
			}
			continue
		}
		length, n := decodeVarint(fdp[pos:])
		if n == 0 {
			break
		}
		pos += n
		if fieldNum == 6 && pos+int(length) <= len(fdp) {
			// ServiceDescriptorProto: field 1 = name
			svcBytes := fdp[pos : pos+int(length)]
			svcName := extractStringField(svcBytes, 1)
			if svcName != "" {
				if pkg != "" {
					names = append(names, pkg+"."+svcName)
				} else {
					names = append(names, svcName)
				}
			}
		}
		pos += int(length)
	}
	return names
}

// skipField advances past a protobuf field of the given wire type.
// Returns the new position, or -1 on error.
//
//nolint:gosec // protobuf wire format: int conversions are safe for field tags and lengths
func skipField(data []byte, pos, wireType int) int {
	switch wireType {
	case 0: // VARINT
		for pos < len(data) {
			if data[pos]&0x80 == 0 {
				return pos + 1
			}
			pos++
		}
		return -1
	case 2: // LEN
		length, n := decodeVarint(data[pos:])
		if n == 0 {
			return -1
		}
		pos += n + int(length)
		if pos > len(data) {
			return -1
		}
		return pos
	case 1: // I64
		return pos + 8
	case 5: // I32
		return pos + 4
	default:
		return -1
	}
}

// RegisterReflection registers the gRPC server reflection service.
// After calling this, grpcurl list / describe / invoke work out of the box.
//
// Services without registered FileDescriptorProto bytes will appear in
// grpcurl list but cannot be described in detail.
func (r *ServiceRegistrar) RegisterReflection() {
	desc := &ServiceDesc{
		Name: reflectionServiceV1Alpha,
		Methods: []MethodDesc{
			{
				Name:       reflectionMethod,
				BidiStreamH: r.reflectionHandler,
			},
		},
	}
	r.RegisterService(desc)

	// Also register v1 path for newer clients.
	descV1 := &ServiceDesc{
		Name: reflectionServiceV1,
		Methods: []MethodDesc{
			{
				Name:       reflectionMethod,
				BidiStreamH: r.reflectionHandler,
			},
		},
	}
	r.RegisterService(descV1)
}

// reflectionHandler is the bidi handler for ServerReflectionInfo.
func (r *ServiceRegistrar) reflectionHandler(
	_ context.Context,
	recv func() ([]byte, error),
	send StreamSender,
) error {
	for {
		reqBytes, err := recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// Decode the ServerReflectionRequest protobuf.
		req, perr := decodeReflectionRequest(reqBytes)
		if perr != nil {
			// Send error response. req is nil on the error path; use an
			// empty host rather than dereferencing nil.
			errResp := encodeErrorResponse(InvalidArgument, perr.Error())
			fullResp := encodeReflectionResponse("", reqBytes, errResp)
			if serr := send(fullResp); serr != nil {
				return serr
			}
			continue
		}

		// Process the request.
		resp := r.processReflectionRequest(req)
		fullResp := encodeReflectionResponse(req.host, reqBytes, resp)
		if serr := send(fullResp); serr != nil {
			return serr
		}
	}
}

// processReflectionRequest handles a single reflection request and returns
// the encoded message_response body (without the wrapper fields).
func (r *ServiceRegistrar) processReflectionRequest(req *reflectionRequest) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	switch {
	case req.listServices != "" || req.listAll:
		// list_services: return all registered service names.
		var names []string
		for svc := range r.services {
			// Skip the reflection service itself.
			if svc == reflectionServiceV1Alpha || svc == reflectionServiceV1 {
				continue
			}
			names = append(names, svc)
		}
		return encodeListServiceResponse(names)

	case req.fileContainingSymbol != "":
		// file_containing_symbol: return the FileDescriptorProto containing
		// the requested symbol (service name).
		data, ok := r.lookupSymbol(req.fileContainingSymbol)
		if !ok {
			return encodeErrorResponse(NotFound, "symbol not found: "+req.fileContainingSymbol)
		}
		return encodeFileDescriptorResponse([][]byte{data})

	case req.fileByFilename != "":
		// file_by_filename: return the FileDescriptorProto by filename.
		data, ok := r.lookupFile(req.fileByFilename)
		if !ok {
			return encodeErrorResponse(NotFound, "file not found: "+req.fileByFilename)
		}
		return encodeFileDescriptorResponse([][]byte{data})

	case req.allExtensionNumbers != "":
		// Extension support is not implemented — return empty.
		return encodeExtensionNumberResponse(req.allExtensionNumbers, nil)

	default:
		return encodeErrorResponse(InvalidArgument, "empty request")
	}
}

// lookupSymbol finds FileDescriptorProto bytes for a service name.
// It also resolves method paths (e.g. "echo.Echo/Get" → "echo.Echo").
func (r *ServiceRegistrar) lookupSymbol(symbol string) ([]byte, bool) {
	if r.reflection == nil {
		return nil, false
	}

	// Direct service name lookup.
	if data, ok := r.reflection.descriptors[symbol]; ok {
		return data, true
	}

	// Try stripping "/Method" suffix to get the service name.
	for i := range symbol {
		if symbol[i] == '/' {
			svcName := symbol[:i]
			if data, ok := r.reflection.descriptors[svcName]; ok {
				return data, true
			}
		}
	}

	// Search all registered descriptors (they may contain the symbol).
	for _, data := range r.reflection.allFiles {
		if protoContainsService(data, symbol) {
			return data, true
		}
	}

	return nil, false
}

// lookupFile finds FileDescriptorProto bytes by filename.
func (r *ServiceRegistrar) lookupFile(filename string) ([]byte, bool) {
	if r.reflection == nil {
		return nil, false
	}
	data, ok := r.reflection.filesByName[filename]
	return data, ok
}

// ---------------------------------------------------------------------------
// ServerReflectionRequest decoder
// ---------------------------------------------------------------------------

// reflectionRequest is the decoded ServerReflectionRequest.
type reflectionRequest struct {
	host string

	// Exactly one of the following is set (or listAll for empty string).
	listAll               bool
	listServices          string // field 7
	fileByFilename        string // field 3
	fileContainingSymbol  string // field 4
	allExtensionNumbers   string // field 6 (message)
	_ string // field 5 (message) — file_containing_extension, not supported
}

//nolint:funlen,gosec // protobuf wire decoder — one switch body; int conversions are safe for proto field tags
// decodeReflectionRequest parses a ServerReflectionRequest protobuf message.
func decodeReflectionRequest(data []byte) (*reflectionRequest, error) {
	req := &reflectionRequest{}
	pos := 0

	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			return nil, errInvalidVarint
		}
		pos += n

		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)

		switch wireType {
		case 2: // Length-delimited (string, bytes, message).
			if pos >= len(data) {
				return nil, errTruncated
			}
			length, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, errInvalidVarint
			}
			pos += n

			end := pos + int(length)
			if end > len(data) || end < pos {
				return nil, errTruncated
			}
			val := data[pos:end]
			pos = end

			switch fieldNum {
			case 1: // host (string)
				req.host = string(val)
			case 3: // file_by_filename (string)
				req.fileByFilename = string(val)
			case 4: // file_containing_symbol (string)
				req.fileContainingSymbol = string(val)
			case 7: // list_services (string)
				req.listServices = string(val)
				req.listAll = true
			}

		case 0: // Varint
			v, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, errInvalidVarint
			}
			pos += n
			_ = v // No varint fields in ServerReflectionRequest

		default:
			// Skip unknown wire types.
			return nil, errUnknownWireType
		}
	}

	return req, nil
}

// ---------------------------------------------------------------------------
// Protobuf response encoders
// ---------------------------------------------------------------------------

// encodeListServiceResponse encodes a ListServiceResponse.
func encodeListServiceResponse(serviceNames []string) []byte {
	var services []byte
	for _, name := range serviceNames {
		// ServiceResponse { string name = 1; }
		var svc []byte
		svc = appendStringField(svc, 1, name)
		services = appendMessageField(services, 1, svc)
	}

	// ListServiceResponse { repeated ServiceResponse service = 1; }
	var resp []byte
	resp = appendMessageField(resp, 6, services) // field 6 = list_service_response
	return resp
}

// encodeFileDescriptorResponse encodes a FileDescriptorResponse.
func encodeFileDescriptorResponse(files [][]byte) []byte {
	// FileDescriptorResponse { repeated bytes file_descriptor_proto = 1; }
	var fdr []byte
	for _, f := range files {
		fdr = appendBytesField(fdr, 1, f)
	}

	var resp []byte
	resp = appendMessageField(resp, 4, fdr) // field 4 = file_descriptor_response
	return resp
}

// encodeErrorResponse encodes an ErrorResponse.
func encodeErrorResponse(code Code, message string) []byte {
	// ErrorResponse { int32 error_code = 1; string error_message = 2; }
	var errResp []byte
	errResp = appendVarintField(errResp, 1, uint64(code))
	errResp = appendStringField(errResp, 2, message)

	var resp []byte
	resp = appendMessageField(resp, 7, errResp) // field 7 = error_response
	return resp
}

// encodeExtensionNumberResponse encodes an ExtensionNumberResponse.
func encodeExtensionNumberResponse(typeName string, numbers []int32) []byte {
	// ExtensionNumberResponse { string base_type_name = 1; repeated int32 extension_number = 2; }
	var enr []byte
	enr = appendStringField(enr, 1, typeName)
	for _, n := range numbers {
		enr = appendVarintField(enr, 2, uint64(n)) //nolint:gosec // extension numbers are small
	}

	var resp []byte
	resp = appendMessageField(resp, 5, enr) // field 5 = all_extension_numbers_response
	return resp
}

// encodeReflectionResponse wraps the response body with host + original_request.
//
// full_response = ServerReflectionResponse {
//   string valid_host = 1;
//   ServerReflectionRequest original_request = 2;
//   oneof message_response { ... }
// }
func encodeReflectionResponse(host string, originalRequest []byte, messageResponse []byte) []byte {
	var buf []byte
	if host != "" {
		buf = appendStringField(buf, 1, host)
	}
	if len(originalRequest) > 0 {
		buf = appendMessageField(buf, 2, originalRequest)
	}
	// message_response fields are already field-tagged in messageResponse.
	buf = append(buf, messageResponse...)
	return buf
}

// ---------------------------------------------------------------------------
// Minimal protobuf wire encoding
// ---------------------------------------------------------------------------

// appendVarint encodes a uint64 as a base-128 varint.
func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// decodeVarint decodes a base-128 varint. Returns (value, bytesConsumed).
func decodeVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		if i >= 10 {
			return 0, 0 // overflow
		}
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, 0 // incomplete
}

// appendTag encodes a protobuf field tag.
//
//nolint:gosec // field numbers are small constants, no overflow risk
func appendTag(buf []byte, fieldNum int, wireType int) []byte {
	return appendVarint(buf, uint64(fieldNum)<<3|uint64(wireType))
}

// appendStringField encodes a string field (wire type 2).
func appendStringField(buf []byte, fieldNum int, s string) []byte {
	buf = appendTag(buf, fieldNum, 2)
	buf = appendVarint(buf, uint64(len(s)))
	return append(buf, s...)
}

// appendBytesField encodes a bytes field (wire type 2).
func appendBytesField(buf []byte, fieldNum int, b []byte) []byte {
	buf = appendTag(buf, fieldNum, 2)
	buf = appendVarint(buf, uint64(len(b)))
	return append(buf, b...)
}

// appendMessageField encodes a nested message field (wire type 2).
func appendMessageField(buf []byte, fieldNum int, msg []byte) []byte {
	buf = appendTag(buf, fieldNum, 2)
	buf = appendVarint(buf, uint64(len(msg)))
	return append(buf, msg...)
}

// appendVarintField encodes a varint field (wire type 0).
func appendVarintField(buf []byte, fieldNum int, v uint64) []byte {
	buf = appendTag(buf, fieldNum, 0)
	return appendVarint(buf, v)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// appendIfUnique appends b to slice only if it's not already present by content.
func appendIfUnique(slice [][]byte, b []byte) [][]byte {
	for _, existing := range slice {
		if bytesEqual(existing, b) {
			return slice
		}
	}
	return append(slice, b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// protoContainsService does a naive byte search for the service name in the
// FileDescriptorProto bytes. This is a heuristic — it searches for the UTF-8
// service name as a length-prefixed string in the proto wire format.
func protoContainsService(fileDescriptorBytes []byte, serviceName string) bool {
	// In protobuf, a string field is: tag + length + bytes.
	// We search for serviceName preceded by its length byte.
	nameLen := byte(len(serviceName))
	needle := make([]byte, 0, len(serviceName)+1)
	needle = append(needle, nameLen)
	needle = append(needle, serviceName...)

	return bytesContains(fileDescriptorBytes, needle)
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Sentinel errors for protobuf decoding.
var (
	errInvalidVarint    = newProtoError("invalid varint encoding")
	errTruncated        = newProtoError("truncated message")
	errUnknownWireType  = newProtoError("unknown wire type")
)

type protoError struct{ msg string }

func (e *protoError) Error() string { return e.msg }

func newProtoError(msg string) *protoError { return &protoError{msg: msg} }
