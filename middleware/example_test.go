package middleware_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ExampleChain composes several middlewares around a final Handler using the
// onion model: Chain(m1, m2)(h) runs m1 → m2 → h → m2 → m1. The composed value
// is itself a server.Middleware, ready to pass via server.Options.Middleware.
func ExampleChain() {
	stack := server.Chain(
		middleware.Recovery(nil),
		middleware.RequestID(),
		middleware.SecurityHeaders(middleware.DefaultSecurityHeadersConfig()),
	)

	final := server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteHeaders(http.StatusOK, nil)
	})

	// stack(final) is a fully wrapped server.Handler.
	wrapped := stack(final)
	fmt.Println(wrapped != nil)
	// Output: true
}

// ExampleRecovery wires the panic-recovery middleware (which converts a handler
// panic into a 500 response) into a server's middleware stack.
func ExampleRecovery() {
	_, err := server.NewServer(server.Options{
		Handler: server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
			panic("boom") // recovered → 500, never crashes the server
		}),
		Middleware: []server.Middleware{
			middleware.Recovery(nil),
		},
	})
	fmt.Println(err == nil)
	// Output: true
}

// ExampleSecurityHeaders shows the secure-by-default header configuration that
// the SecurityHeaders middleware injects (HSTS, nosniff, frame options, ...).
func ExampleSecurityHeaders() {
	cfg := middleware.DefaultSecurityHeadersConfig()

	fmt.Println("frame-options:", cfg.FrameOptions)
	fmt.Println("referrer-policy:", cfg.ReferrerPolicy)
	fmt.Println("nosniff:", cfg.ContentTypeNosniff)

	mw := middleware.SecurityHeaders(cfg)
	fmt.Println("middleware ready:", mw != nil)
	// Output:
	// frame-options: DENY
	// referrer-policy: no-referrer
	// nosniff: true
	// middleware ready: true
}
