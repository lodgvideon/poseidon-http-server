// Package grpcserver implements gRPC-over-HTTP/2 using the server package.
//
// It provides Length-Prefixed Message encoding/decoding, gRPC status code
// trailers, and support for unary and streaming RPCs.
//
// Design (SOLID):
//   - S: owns only gRPC framing (LP messages, status trailers)
//   - O: ServiceRegistrar allows adding services without modifying core
//   - D: depends on server.Handler, not on server.Server
package grpcserver
