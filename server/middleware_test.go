package server

import (
	"context"
	"errors"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// ---------------------------------------------------------------------------
// Middleware tests
// ---------------------------------------------------------------------------

func TestMiddleware_Chain_ExecutionOrder(t *testing.T) {
	var order []string

	mw1 := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			order = append(order, "mw1-before")
			err := next.ServeHTTP(ctx, req, w)
			order = append(order, "mw1-after")
			return err
		})
	}

	mw2 := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			order = append(order, "mw2-before")
			err := next.ServeHTTP(ctx, req, w)
			order = append(order, "mw2-after")
			return err
		})
	}

	mw3 := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			order = append(order, "mw3-before")
			err := next.ServeHTTP(ctx, req, w)
			order = append(order, "mw3-after")
			return err
		})
	}

	final := HandlerFunc(func(_ context.Context, _ *Request, _ ResponseWriter) error {
		order = append(order, "handler")
		return nil
	})

	chain := Chain(mw1, mw2, mw3)
	wrapped := chain(final)

	w, _ := newTestWriter()
	if err := wrapped.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	expected := []string{
		"mw1-before", "mw2-before", "mw3-before",
		"handler",
		"mw3-after", "mw2-after", "mw1-after",
	}
	if len(order) != len(expected) {
		t.Fatalf("execution order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("order[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestMiddleware_Chain_Empty(t *testing.T) {
	called := false
	final := HandlerFunc(func(_ context.Context, _ *Request, _ ResponseWriter) error {
		called = true
		return nil
	})

	chain := Chain()
	wrapped := chain(final)

	w, _ := newTestWriter()
	if err := wrapped.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Error("handler was not called with empty chain")
	}
}

func TestMiddleware_Chain_Single(t *testing.T) {
	mark := ""
	mw := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			mark = "before-"
			err := next.ServeHTTP(ctx, req, w)
			mark += "-after"
			return err
		})
	}

	final := HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		mark += "handler"
		_ = w.WriteHeaders(200, nil)
		return nil
	})

	chain := Chain(mw)
	wrapped := chain(final)

	w, _ := newTestWriter()
	if err := wrapped.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if mark != "before-handler-after" {
		t.Errorf("mark = %q, want before-handler-after", mark)
	}
}

func TestMiddleware_Chain_ShortCircuit(t *testing.T) {
	handlerCalled := false

	mw := func(_ Handler) Handler {
		return HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			// Short-circuit: don't call next.
			_ = w.WriteHeaders(403, []hpack.HeaderField{
				{Name: []byte("x-blocked"), Value: []byte("true")},
			})
			return nil
		})
	}

	final := HandlerFunc(func(_ context.Context, _ *Request, _ ResponseWriter) error {
		handlerCalled = true
		return nil
	})

	chain := Chain(mw)
	wrapped := chain(final)

	w, _ := newTestWriter()
	if err := wrapped.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if handlerCalled {
		t.Error("final handler should NOT have been called (short-circuit)")
	}
	if w.StatusCode() != 403 {
		t.Errorf("StatusCode = %d, want 403", w.StatusCode())
	}
}

func TestMiddleware_Chain_ErrorPropagation(t *testing.T) {
	testErr := context.DeadlineExceeded

	mw := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			err := next.ServeHTTP(ctx, req, w)
			return err // propagate
		})
	}

	final := HandlerFunc(func(_ context.Context, _ *Request, _ ResponseWriter) error {
		return testErr
	})

	chain := Chain(mw)
	wrapped := chain(final)

	w, _ := newTestWriter()
	err := wrapped.ServeHTTP(context.Background(), &Request{Method: "GET", Path: "/"}, w)
	if !errors.Is(err, testErr) {
		t.Errorf("error = %v, want %v", err, testErr)
	}
}

func TestMiddleware_Chain_ModifiesRequest(t *testing.T) {
	mw := func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request, w ResponseWriter) error {
			req.Headers = append(req.Headers, hpack.HeaderField{
				Name:  []byte("x-injected"),
				Value: []byte("by-middleware"),
			})
			return next.ServeHTTP(ctx, req, w)
		})
	}

	var capturedHeaders []hpack.HeaderField
	final := HandlerFunc(func(_ context.Context, req *Request, _ ResponseWriter) error {
		capturedHeaders = req.Headers
		return nil
	})

	chain := Chain(mw)
	wrapped := chain(final)

	w, _ := newTestWriter()
	req := &Request{
		Method:  "GET",
		Path:    "/",
		Headers: []hpack.HeaderField{{Name: []byte("accept"), Value: []byte("text/html")}},
	}
	if err := wrapped.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if len(capturedHeaders) != 2 {
		t.Fatalf("len(Headers) = %d, want 2", len(capturedHeaders))
	}
	last := capturedHeaders[1]
	if string(last.Name) != "x-injected" || string(last.Value) != "by-middleware" {
		t.Errorf("injected header = %q:%q, want x-injected:by-middleware", last.Name, last.Value)
	}
}
