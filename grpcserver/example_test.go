package grpcserver_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lodgvideon/poseidon-http-server/grpcserver"
)

// ExampleEncodeLP shows the gRPC Length-Prefixed (LP) wire framing: a 1-byte
// compression flag, a big-endian uint32 length, then the payload.
func ExampleEncodeLP() {
	frame := grpcserver.EncodeLP(nil, grpcserver.LPMessage{
		Flag:    grpcserver.FlagNone,
		Payload: []byte("hi"),
	})

	fmt.Printf("flag=%d len=%d total=%d\n", frame[0], uint32(frame[4]), len(frame))
	// Output: flag=0 len=2 total=7
}

// ExampleDecodeLP reads one LP-framed message back from an io.Reader,
// round-tripping the bytes produced by EncodeLP.
func ExampleDecodeLP() {
	wire := grpcserver.EncodeLP(nil, grpcserver.LPMessage{
		Flag:    grpcserver.FlagNone,
		Payload: []byte("pong"),
	})

	msg, err := grpcserver.DecodeLP(bytes.NewReader(wire))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	fmt.Printf("flag=%d payload=%q\n", msg.Flag, msg.Payload)
	// Output: flag=0 payload="pong"
}

// ExampleDecodeLPFromBytes decodes one LP message directly from a byte slice,
// also reporting how many bytes were consumed (useful when several messages are
// concatenated in a single buffer).
func ExampleDecodeLPFromBytes() {
	wire := grpcserver.EncodeLP(nil, grpcserver.LPMessage{
		Flag:    grpcserver.FlagNone,
		Payload: []byte("abc"),
	})

	msg, n, err := grpcserver.DecodeLPFromBytes(wire)
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	fmt.Printf("payload=%q consumed=%d\n", msg.Payload, n)
	// Output: payload="abc" consumed=8
}

// ExampleCode_String shows that gRPC status codes render to their canonical
// names.
func ExampleCode_String() {
	fmt.Println(grpcserver.OK)
	fmt.Println(grpcserver.NotFound)
	fmt.Println(grpcserver.Unimplemented)
	// Output:
	// OK
	// NotFound
	// Unimplemented
}

// ExampleStatusToTrailers maps an RPCStatus onto the grpc-status / grpc-message
// HTTP/2 trailer pairs that terminate every gRPC response.
func ExampleStatusToTrailers() {
	st := grpcserver.Statusf(grpcserver.NotFound, "user 42 not found")

	for _, kv := range grpcserver.StatusToTrailers(st) {
		fmt.Printf("%s: %s\n", kv[0], kv[1])
	}
	// Output:
	// grpc-status: 5
	// grpc-message: user 42 not found
}

// ExampleServiceRegistrar demonstrates registering a unary gRPC method and
// obtaining a server.Handler that routes "/echo.Echo/Say" to it. The handler
// can then be mounted on a Poseidon server via server.Options.Handler.
func ExampleServiceRegistrar() {
	reg := grpcserver.NewServiceRegistrar()

	reg.RegisterService(&grpcserver.ServiceDesc{
		Name: "echo.Echo",
		Methods: []grpcserver.MethodDesc{
			{
				Name: "Say",
				UnaryHandler: func(_ context.Context, req []byte) ([]byte, error) {
					// Echo the request payload straight back.
					return req, nil
				},
			},
		},
	})

	// reg.Handler() is a server.Handler ready to pass to server.NewServer.
	var h = reg.Handler()
	fmt.Println(h != nil)
	// Output: true
}
