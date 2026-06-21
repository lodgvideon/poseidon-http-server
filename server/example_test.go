package server_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// ExampleNewServer builds a Poseidon HTTP/2 server from a native Handler and
// serves it over an h2c (cleartext HTTP/2) listener. The handler uses the
// stdlib-compatible http.ResponseWriter path exposed by server.ResponseWriter.
//
// No Output line: the example binds a port and runs the accept loop, so it is
// compiled and shown in godoc but not asserted against output.
func ExampleNewServer() {
	srv, err := server.NewServer(server.Options{
		Handler: server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello from poseidon"))
			return nil
		}),
		H2C:         true,
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		fmt.Println("new server:", err)
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen:", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// ... handle requests ...

	_ = srv.Close()
}

// ExampleFromHTTPHandler shows mounting an ordinary http.Handler
// (net/http.ServeMux here, but chi/echo/gin routers work the same way) onto a
// Poseidon server via server.FromHTTPHandler.
func ExampleFromHTTPHandler() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv, err := server.NewServer(server.Options{
		Handler: server.FromHTTPHandler(mux),
		H2C:     true,
	})
	if err != nil {
		fmt.Println("new server:", err)
		return
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	_ = srv.Close()
}

// ExampleServer_Shutdown demonstrates a graceful drain: Shutdown stops the
// listener, sends GOAWAY, and waits for in-flight streams to finish (or for the
// supplied context to expire, after which remaining connections are forced).
func ExampleServer_Shutdown() {
	srv, err := server.NewServer(server.Options{
		Handler: server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
			return w.WriteHeaders(http.StatusOK, nil)
		}),
		H2C: true,
		// Flip readiness to NOT-ready at the start of drain so orchestrators
		// (e.g. Kubernetes) stop routing new traffic before streams drain.
		OnDrainStart: func() { /* health.SetNotReady() */ },
	})
	if err != nil {
		fmt.Println("new server:", err)
		return
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	serveCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(serveCtx, ln) }()

	// Drain with a bounded deadline.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		fmt.Println("shutdown:", err)
	}
}
