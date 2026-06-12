// Package server provides a high-level HTTP/2 server built on the conn package.
//
// It handles TLS + h2c listening, accepts connections, dispatches inbound
// streams to registered handlers, and manages graceful shutdown.
//
// Design (SOLID):
//   - S: owns only the accept loop + routing
//   - O: extensible via Handler interface and Middleware chain
//   - L: any Handler implementation is interchangeable
//   - I: small interfaces — Handler, Middleware, Listener
//   - D: depends on Listener and Handler interfaces, not concrete types
package server
