package grpcserver

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Unary RPC handler
// ---------------------------------------------------------------------------

// UnaryHandler is the signature for a unary gRPC method.
// req is the decoded request payload; the handler should populate resp
// with the serialised response and return nil on success.
type UnaryHandler func(ctx context.Context, req []byte) (resp []byte, err error)

// StreamSender sends a single message on a streaming RPC.
type StreamSender func(msg []byte) error

// ServerStreamHandler handles server-streaming RPCs.
type ServerStreamHandler func(ctx context.Context, req []byte, send StreamSender) error

// ClientStreamHandler handles client-streaming RPCs.
// recv returns (nil, io.EOF) when the client is done.
type ClientStreamHandler func(ctx context.Context, recv func() ([]byte, error)) (resp []byte, err error)

// BidiStreamHandler handles bidirectional-streaming RPCs.
type BidiStreamHandler func(ctx context.Context, recv func() ([]byte, error), send StreamSender) error

// ---------------------------------------------------------------------------
// Method descriptor
// ---------------------------------------------------------------------------

// methodDesc describes one gRPC method.
type methodDesc struct {
	fullPath string // "/package.Service/Method"

	// Exactly one handler is set.
	unary   UnaryHandler
	serverS ServerStreamHandler
	clientS ClientStreamHandler
	bidi    BidiStreamHandler
}

// ---------------------------------------------------------------------------
// Service descriptor
// ---------------------------------------------------------------------------

// ServiceDesc describes a gRPC service (a collection of methods under
// the same "/package.Service/" prefix).
type ServiceDesc struct {
	// Name is the full service name, e.g. "mypackage.MyService".
	Name string

	// Methods lists the methods for this service.
	Methods []MethodDesc
}

// MethodDesc describes a single method inside a ServiceDesc.
type MethodDesc struct {
	// Name is the method name (without service prefix), e.g. "GetUser".
	Name string

	// One of the following must be set.
	UnaryHandler    UnaryHandler
	ServerStreamH   ServerStreamHandler
	ClientStreamH   ClientStreamHandler
	BidiStreamH     BidiStreamHandler
}

// ---------------------------------------------------------------------------
// ServiceRegistrar
// ---------------------------------------------------------------------------

// ServiceRegistrar collects service registrations and produces a
// server.Handler that routes gRPC requests to the correct method.
//
// Design (SOLID):
//   - O: new services registered without modifying core
//   - D: depends on server.Handler, not on server.Server
type ServiceRegistrar struct {
	mu       sync.RWMutex
	methods  map[string]*methodDesc // "/pkg.Svc/Method" → desc
	services map[string]bool         // "pkg.Svc" → registered
}

// NewServiceRegistrar creates an empty registrar.
func NewServiceRegistrar() *ServiceRegistrar {
	return &ServiceRegistrar{
		methods:  make(map[string]*methodDesc),
		services: make(map[string]bool),
	}
}

// RegisterService registers all methods from a ServiceDesc.
// Panics if the service is already registered.
func (r *ServiceRegistrar) RegisterService(desc *ServiceDesc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.services[desc.Name] {
		panic("grpcserver: service already registered: " + desc.Name)
	}
	r.services[desc.Name] = true

	for i := range desc.Methods {
		md := &desc.Methods[i]
		fullPath := "/" + desc.Name + "/" + md.Name
		internal := &methodDesc{fullPath: fullPath}

		switch {
		case md.UnaryHandler != nil:
			internal.unary = md.UnaryHandler
		case md.ServerStreamH != nil:
			internal.serverS = md.ServerStreamH
		case md.ClientStreamH != nil:
			internal.clientS = md.ClientStreamH
		case md.BidiStreamH != nil:
			internal.bidi = md.BidiStreamH
		default:
			panic("grpcserver: method " + fullPath + " has no handler")
		}

		r.methods[fullPath] = internal
	}
}

// Handler returns a server.Handler that dispatches gRPC requests.
// The handler validates content-type, decodes LP framing, routes to
// the registered method, and encodes the response.
func (r *ServiceRegistrar) Handler() server.Handler {
	return server.HandlerFunc(func(ctx context.Context, req *server.Request, w *server.ResponseWriter) error {
		// Validate content-type.
		if !isGRPCContentType(req.Headers) {
			return writeGRPCError(w, Statusf(Unimplemented, "invalid content-type"))
		}

		// Route by :path.
		md := r.lookup(req.Path)
		if md == nil {
			return writeGRPCError(w, Statusf(Unimplemented, "unknown method %s", req.Path))
		}

		// Decode request body (LP message).
		var reqPayload []byte
		if req.BodyReader != nil {
			data, err := io.ReadAll(req.BodyReader)
			if err != nil {
				return writeGRPCError(w, Statusf(Internal, "read body: %s", err.Error()))
			}
			_ = req.BodyReader.Close()
			reqPayload = data
		} else if len(req.Body) > 0 {
			msg, _, err := DecodeLPFromBytes(req.Body)
			if err != nil {
				return writeGRPCError(w, Statusf(Internal, "decode lp: %s", err.Error()))
			}
			reqPayload = msg.Payload
		}

		// Dispatch.
		switch {
		case md.unary != nil:
			return r.handleUnary(ctx, w, md, reqPayload)
		case md.serverS != nil:
			return r.handleServerStream(ctx, w, md, reqPayload)
		case md.clientS != nil:
			return r.handleClientStream(ctx, w, md, req)
		case md.bidi != nil:
			return r.handleBidiStream(ctx, w, md, req)
		default:
			return writeGRPCError(w, Statusf(Unimplemented, "no handler for %s", md.fullPath))
		}
	})
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

func (r *ServiceRegistrar) handleUnary(
	ctx context.Context,
	w *server.ResponseWriter,
	md *methodDesc,
	reqPayload []byte,
) error {
	respPayload, err := md.unary(ctx, reqPayload)
	if err != nil {
		st := errToStatus(err)
		return writeGRPCError(w, st)
	}

	// Send response headers.
	if err := w.WriteHeaders(200, grpcResponseHeaders()); err != nil {
		return err
	}

	// Send LP-encoded response body.
	if respPayload != nil {
		encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: respPayload})
		if err := w.WriteData(encoded); err != nil {
			return err
		}
	}

	// Send trailers with OK status.
	return w.WriteTrailers(statusToHPack(StatusOK()))
}

func (r *ServiceRegistrar) handleServerStream(
	ctx context.Context,
	w *server.ResponseWriter,
	md *methodDesc,
	reqPayload []byte,
) error {
	send := func(msg []byte) error {
		encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: msg})
		return w.WriteData(encoded)
	}

	// Send response headers.
	if err := w.WriteHeaders(200, grpcResponseHeaders()); err != nil {
		return err
	}

	if err := md.serverS(ctx, reqPayload, send); err != nil {
		st := errToStatus(err)
		return writeGRPCError(w, st)
	}

	return w.WriteTrailers(statusToHPack(StatusOK()))
}

func (r *ServiceRegistrar) handleClientStream(
	ctx context.Context,
	w *server.ResponseWriter,
	md *methodDesc,
	req *server.Request,
) error {
	// Send response headers first.
	if err := w.WriteHeaders(200, grpcResponseHeaders()); err != nil {
		return err
	}

	recv := streamReceiver(req)

	respPayload, err := md.clientS(ctx, recv)
	if err != nil {
		st := errToStatus(err)
		return writeGRPCError(w, st)
	}

	if respPayload != nil {
		encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: respPayload})
		if err := w.WriteData(encoded); err != nil {
			return err
		}
	}

	return w.WriteTrailers(statusToHPack(StatusOK()))
}

func (r *ServiceRegistrar) handleBidiStream(
	ctx context.Context,
	w *server.ResponseWriter,
	md *methodDesc,
	req *server.Request,
) error {
	// Send response headers first.
	if err := w.WriteHeaders(200, grpcResponseHeaders()); err != nil {
		return err
	}

	recv := streamReceiver(req)
	send := func(msg []byte) error {
		encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: msg})
		return w.WriteData(encoded)
	}

	if err := md.bidi(ctx, recv, send); err != nil {
		st := errToStatus(err)
		return writeGRPCError(w, st)
	}

	return w.WriteTrailers(statusToHPack(StatusOK()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *ServiceRegistrar) lookup(path string) *methodDesc {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.methods[path]
}

// isGRPCContentType checks for "application/grpc" or "application/grpc+proto".
func isGRPCContentType(headers []hpack.HeaderField) bool {
	for _, h := range headers {
		if string(h.Name) == HeaderContentType {
			ct := string(h.Value)
			return ct == ContentTypeGRPC || ct == ContentTypeGRPC+"+proto"
		}
	}
	return false
}

// grpcResponseHeaders returns the required response headers for gRPC.
var grpcResponseHeadersSlice = []hpack.HeaderField{
	{Name: sContentType, Value: sContentGRPC},
}

func grpcResponseHeaders() []hpack.HeaderField {
	return grpcResponseHeadersSlice
}

// writeGRPCError sends a gRPC error as headers + trailers (no body).
func writeGRPCError(w *server.ResponseWriter, st RPCStatus) error {
	// gRPC errors are sent via trailers-only response.
	// Headers with :status 200 + content-type, then trailers with grpc-status.
	hdrs := grpcResponseHeaders()
	if err := w.WriteHeaders(200, hdrs); err != nil {
		return err
	}
	return w.WriteTrailers(statusToHPack(st))
}

// statusToHPack converts an RPCStatus to HPACK trailer fields.
func statusToHPack(st RPCStatus) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: sGRPCStatus, Value: []byte(uint32ToString(uint32(st.Code)))},
		{Name: sGRPCMessage, Value: []byte(st.Message)},
	}
}

// Pre-allocated header name byte slices (avoid per-call []byte conversion).
var (
	sGRPCStatus  = []byte(HeaderGRPCStatus)
	sGRPCMessage = []byte(HeaderGRPCMessage)
	sContentType = []byte(HeaderContentType)
	sContentGRPC = []byte(ContentTypeGRPC)
)

// errToStatus converts an error to RPCStatus. If the error already is
// an RPCStatus, it is returned directly; otherwise Internal is used.
func errToStatus(err error) RPCStatus {
	var st RPCStatus
	if errors.As(err, &st) {
		return st
	}
	return RPCStatus{Code: Internal, Message: err.Error()}
}

// streamReceiver creates a recv function for client/bidi streaming.
func streamReceiver(req *server.Request) func() ([]byte, error) {
	// For buffered body, decode LP messages from the body.
	if len(req.Body) > 0 {
		remaining := req.Body
		return func() ([]byte, error) {
			if len(remaining) == 0 {
				return nil, io.EOF
			}
			msg, n, err := DecodeLPFromBytes(remaining)
			if err != nil {
				return nil, err
			}
			remaining = remaining[n:]
			return msg.Payload, nil
		}
	}
	// No body → immediate EOF.
	return func() ([]byte, error) {
		return nil, io.EOF
	}
}

// codeToString converts a Code to its decimal string representation.
func codeToString(c Code) string {
	return uint32ToString(uint32(c))
}

// uint32ToString is a zero-allocation uint32 → string for small values.
func uint32ToString(v uint32) string {
	// Fast path: single digit (gRPC codes 0-9).
	if v < 10 {
		return digits[v : v+1]
	}
	// Two digits — use pre-computed table for values 10-99.
	if v < uint32(len(twoDigitStrings)) {
		return twoDigitStrings[v]
	}
	// General case (rare for gRPC).
	buf := make([]byte, 0, 10)
	for v > 0 {
		buf = append(buf, byte('0'+v%10))
		v /= 10
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// digits lookup table for zero-allocation single-digit uint32 → string.
var digits = "0123456789"

// twoDigitStrings pre-computed string representations for 0-99.
var twoDigitStrings [100]string

func init() {
	for i := range twoDigitStrings {
		if i < 10 {
			twoDigitStrings[i] = digits[i : i+1]
		} else {
			twoDigitStrings[i] = string([]byte{byte('0' + i/10), byte('0' + i%10)})
		}
	}
}
