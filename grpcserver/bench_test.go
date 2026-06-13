package grpcserver

import (
	"bytes"
	"context"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Benchmarks: LP framing (supplement existing benchmarks in framing_test.go)
// ---------------------------------------------------------------------------

func BenchmarkEncodeLP_ReuseBuf(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := LPMessage{Flag: FlagNone, Payload: payload}
	buf := make([]byte, 0, len(payload)+5)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		buf = EncodeLP(buf[:0], msg)
	}
}

func BenchmarkDecodeLPFromBytes(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: payload})

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_, _, _ = DecodeLPFromBytes(encoded)
	}
}

func BenchmarkDecodeLPWithLimit(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	encoded := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: payload})
	reader := bytes.NewReader(encoded)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		reader.Reset(encoded)
		_, _ = DecodeLPWithLimit(reader, 64*1024)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: Status / headers
// ---------------------------------------------------------------------------

func BenchmarkStatusToHPack(b *testing.B) {
	st := Statusf(NotFound, "resource not found")

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = statusToHPack(st)
	}
}

func BenchmarkGRPCResponseHeaders(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = grpcResponseHeaders()
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: Dispatch helpers
// ---------------------------------------------------------------------------

func BenchmarkUint32ToString(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = uint32ToString(200)
	}
}

func BenchmarkIsGRPCContentType(b *testing.B) {
	headers := []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/test.Svc/Do")},
		{Name: []byte("content-type"), Value: []byte("application/grpc")},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = isGRPCContentType(headers)
	}
}

func BenchmarkErrToStatus_GRPCStatus(b *testing.B) {
	st := Statusf(NotFound, "not found")
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = errToStatus(st)
	}
}

func BenchmarkErrToStatus_GenericError(b *testing.B) {
	err := context.DeadlineExceeded
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = errToStatus(err)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: Stream receiver
// ---------------------------------------------------------------------------

func BenchmarkStreamReceiver_Buffered(b *testing.B) {
	msg1 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("hello")})
	msg2 := EncodeLP(nil, LPMessage{Flag: FlagNone, Payload: []byte("world")})
	body := make([]byte, 0, len(msg1)+len(msg2))
	body = append(body, msg1...)
	body = append(body, msg2...)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		recv := streamReceiver(&server.Request{Body: body})
		for {
			_, err := recv()
			if err != nil {
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: Service lookup
// ---------------------------------------------------------------------------

func BenchmarkServiceRegistrar_Lookup(b *testing.B) {
	r := NewServiceRegistrar()
	r.RegisterService(&ServiceDesc{
		Name: "test.Greeter",
		Methods: []MethodDesc{
			{Name: "SayHello", UnaryHandler: func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = r.lookup("/test.Greeter/SayHello")
	}
}
