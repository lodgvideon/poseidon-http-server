package server

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"
)

// Bug 1: with `go Serve(context.Background(), ln)` and no client ever
// connecting, Close() must make Serve return. Two sub-problems:
//
//	(a) the ctx watcher does `<-ctx.Done()`; for context.Background() that is a
//	    nil channel, so the watcher goroutine blocks forever (leak) unless guarded.
//	(b) Close()/Shutdown() must close the listener passed to Serve so ln.Accept()
//	    unblocks and Serve returns ErrServerClosed regardless of ctx.
//
// Before the fix this test times out (Serve stays blocked in Accept) and/or the
// watcher goroutine leaks.
func TestServe_CloseUnblocksAcceptWithBackgroundCtx(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()

	time.Sleep(50 * time.Millisecond) // let Serve enter Accept
	_ = srv.Close()

	select {
	case err := <-done:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s after Close() with a background ctx (Bug 1)")
	}
}

// The ctx watcher must terminate when the server is closed, even with a
// background ctx (ctx.Done() == nil). Before the fix, each Serve spawned a
// `go func(){ <-ctx.Done(); ... }` that blocked forever on a nil channel, so N
// Serve+Close cycles leaked N goroutines.
func TestServe_BackgroundCtxNoWatcherLeak(t *testing.T) {
	const cycles = 20
	base := runtime.NumGoroutine()
	for range cycles {
		srv, err := NewServer(Options{
			Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
				return w.WriteHeaders(200, nil)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = srv.Serve(context.Background(), ln); close(done) }()
		time.Sleep(3 * time.Millisecond)
		_ = srv.Close()
		<-done
	}
	// Let any exiting goroutines settle.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if got := runtime.NumGoroutine(); got > base+5 {
		t.Errorf("goroutine leak: base=%d, after %d Serve+Close cycles=%d (the background-ctx watcher leaked on a nil channel)", base, cycles, got)
	}
}

// Shutdown (not just Close) must also unblock Serve with a background ctx.
func TestShutdown_UnblocksAcceptWithBackgroundCtx(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	time.Sleep(50 * time.Millisecond)

	sdCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(sdCtx)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s after Shutdown() with a background ctx (Bug 1)")
	}
}
