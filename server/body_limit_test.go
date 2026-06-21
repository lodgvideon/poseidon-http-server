package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// dialLnHandshake is a small helper that connects to ln, performs the
// minimal HTTP/2 client handshake, and returns the conn + framer.
func dialLnHandshake(t *testing.T, ln net.Listener) (net.Conn, *frame.Framer) {
	t.Helper()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fr := frame.NewFramer(c, c)
	if err := performClientHandshake(c, fr); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return c, fr
}

// writeReqHeaders writes request HEADERS (POST, body to follow) on stream 1.
func writeReqHeaders(t *testing.T, fr *frame.Framer, path string) {
	t.Helper()
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte(path)},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: false,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
}

// TestResolveMaxBodyBytes verifies sentinel semantics for the limit knob.
func TestResolveMaxBodyBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int64
		want int64 // -1 == unlimited
	}{
		{0, defaultMaxRequestBodyBytes}, // secure default
		{-1, -1},                        // disabled / unlimited
		{-100, -1},                      // any negative == unlimited
		{1024, 1024},                    // explicit
	}
	for _, c := range cases {
		o := Options{MaxRequestBodyBytes: c.in}
		if got := o.resolveMaxBodyBytes(); got != c.want {
			t.Errorf("resolveMaxBodyBytes(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestBodyLimit_BufferedRejected verifies a buffered body over the limit is
// rejected with 413 and not buffered beyond the cap.
func TestBodyLimit_BufferedRejected(t *testing.T) {
	handlerCalled := make(chan int64, 1)
	srv, err := NewServer(Options{
		MaxRequestBodyBytes: 8, // tiny cap
		Handler: HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
			handlerCalled <- int64(len(req.Body))
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	writeReqHeaders(t, fr, "/big")
	// Send 32 bytes — far over the 8-byte cap.
	_ = fr.WriteData(1, true, make([]byte, 32))

	respHeaders, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatalf("read response: %v", herr)
	}
	if status := statusValue(respHeaders); status != "413" {
		t.Errorf("status = %q, want 413", status)
	}

	// Handler must NOT have been invoked with an over-cap body.
	select {
	case n := <-handlerCalled:
		t.Errorf("handler invoked with body len %d; want rejection before dispatch", n)
	case <-time.After(300 * time.Millisecond):
		// good — handler not called
	}
}

// TestBodyLimit_BufferedUnderLimit verifies a body under the cap works.
func TestBodyLimit_BufferedUnderLimit(t *testing.T) {
	bodyCh := make(chan string, 1)
	srv, err := NewServer(Options{
		MaxRequestBodyBytes: 1024,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
			bodyCh <- string(req.Body)
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	writeReqHeaders(t, fr, "/ok")
	_ = fr.WriteData(1, true, []byte("small"))

	select {
	case b := <-bodyCh:
		if b != "small" {
			t.Errorf("body = %q, want %q", b, "small")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
}

// TestBodyLimit_NegativeUnlimited verifies a negative limit allows a large body.
func TestBodyLimit_NegativeUnlimited(t *testing.T) {
	bodyLen := make(chan int, 1)
	srv, err := NewServer(Options{
		MaxRequestBodyBytes: -1, // unlimited
		Handler: HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
			bodyLen <- len(req.Body)
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	writeReqHeaders(t, fr, "/unlimited")
	// 64 KiB across chunks; default cap is 10 MiB but we disabled it.
	big := make([]byte, 16384)
	_ = fr.WriteData(1, false, big)
	_ = fr.WriteData(1, false, big)
	_ = fr.WriteData(1, true, big)

	select {
	case n := <-bodyLen:
		if n != 3*16384 {
			t.Errorf("body len = %d, want %d", n, 3*16384)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
}

// TestBodyLimit_StreamingRejected verifies the streaming BodyReader caps total
// bytes and returns an error past the limit.
func TestBodyLimit_StreamingRejected(t *testing.T) {
	readErrCh := make(chan error, 1)
	srv, err := NewServer(Options{
		StreamingBody:       true,
		MaxRequestBodyBytes: 8,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
			_, rerr := io.ReadAll(req.BodyReader)
			_ = req.BodyReader.Close()
			readErrCh <- rerr
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	writeReqHeaders(t, fr, "/stream-big")
	_ = fr.WriteData(1, false, make([]byte, 32))
	_ = fr.WriteData(1, true, make([]byte, 32))

	select {
	case rerr := <-readErrCh:
		if rerr == nil {
			t.Fatal("expected ReadAll to fail once body exceeds the cap")
		}
		if !errors.Is(rerr, ErrBodyTooLarge) {
			t.Errorf("read error = %v, want ErrBodyTooLarge", rerr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
}

// TestBodyLimit_StreamingUnderLimit verifies a streaming body under the cap works.
func TestBodyLimit_StreamingUnderLimit(t *testing.T) {
	bodyCh := make(chan string, 1)
	srv, err := NewServer(Options{
		StreamingBody:       true,
		MaxRequestBodyBytes: 1024,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
			b, rerr := io.ReadAll(req.BodyReader)
			_ = req.BodyReader.Close()
			if rerr != nil {
				bodyCh <- "ERR:" + rerr.Error()
				return w.WriteHeaders(500, nil)
			}
			bodyCh <- string(b)
			return w.WriteHeaders(200, nil)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, fr := dialLnHandshake(t, ln)
	defer c.Close()

	writeReqHeaders(t, fr, "/stream-ok")
	_ = fr.WriteData(1, true, []byte("streamed"))

	select {
	case b := <-bodyCh:
		if b != "streamed" {
			t.Errorf("body = %q, want %q", b, "streamed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
}
