package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestStreamBody_ReadAll reads body via io.ReadAll from streaming body.
func TestStreamBody_ReadAll(t *testing.T) {
	srv, err := NewServer(Options{
		StreamingBody: true,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w *ResponseWriter) error {
			if req.BodyReader == nil {
				t.Error("BodyReader is nil, expected io.ReadCloser")
				_ = w.WriteHeaders(500, nil)
				return nil
			}
			body, readErr := io.ReadAll(req.BodyReader)
			if readErr != nil {
				t.Errorf("ReadAll: %v", readErr)
			}
			_ = req.BodyReader.Close()

			// Echo body back.
			_ = w.WriteHeaders(200, nil)
			_ = w.WriteData(body)
			return nil
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

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/stream")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})
	_ = fr.WriteData(1, false, []byte("chunk1"))
	_ = fr.WriteData(1, true, []byte("chunk2"))

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Errorf("status = %q, want 200", statusValue(headers))
	}
}

// TestStreamBody_BufferedMode verifies default buffered mode still works.
func TestStreamBody_BufferedMode(t *testing.T) {
	srv, err := NewServer(Options{
		StreamingBody: false,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w *ResponseWriter) error {
			if req.BodyReader != nil {
				t.Error("BodyReader should be nil in buffered mode")
			}
			if string(req.Body) != "buffered" {
				t.Errorf("Body = %q, want %q", string(req.Body), "buffered")
			}
			_ = w.WriteHeaders(200, nil)
			return nil
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

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/buf")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})
	_ = fr.WriteData(1, true, []byte("buffered"))

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Errorf("status = %q, want 200", statusValue(headers))
	}
}

// TestStreamBody_LargeChunk tests reading a body larger than one Read buffer.
func TestStreamBody_LargeChunk(t *testing.T) {
	srv, err := NewServer(Options{
		StreamingBody: true,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w *ResponseWriter) error {
			body, _ := io.ReadAll(req.BodyReader)
			_ = req.BodyReader.Close()
			_ = w.WriteHeaders(200, nil)
			_ = w.WriteData(body)
			return nil
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

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/large")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})
	// Send 3 data chunks.
	_ = fr.WriteData(1, false, []byte("aaa"))
	_ = fr.WriteData(1, false, []byte("bbb"))
	_ = fr.WriteData(1, true, []byte("ccc"))

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Fatalf("status = %q, want 200", statusValue(headers))
	}
}

// TestServeStreamBuffered_Trailers covers the Trailer path in serveStreamBuffered.
func TestServeStreamBuffered_Trailers(t *testing.T) {
	trailerReceived := make(chan string, 1)
	srv, err := NewServer(Options{
		StreamingBody: false,
		Handler: HandlerFunc(func(_ context.Context, req *Request, w *ResponseWriter) error {
			body := string(req.Body)
			trailer := ""
			for _, h := range req.Trailers {
				if string(h.Name) == "x-trailer" {
					trailer = string(h.Value)
				}
			}
			trailerReceived <- body + "|" + trailer
			_ = w.WriteHeaders(200, nil)
			return nil
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

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	defer c.Close()
	fr := frame.NewFramer(c, c)
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("POST")},
		{Name: []byte(":path"), Value: []byte("/trailers")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
		{Name: []byte("te"), Value: []byte("trailers")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})
	_ = fr.WriteData(1, false, []byte("body-data"))

	// Send trailers with EndStream.
	trailerBlock := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte("x-trailer"), Value: []byte("trailer-value")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: trailerBlock, EndHeaders: true, EndStream: true,
	})

	select {
	case result := <-trailerReceived:
		if result != "body-data|trailer-value" {
			t.Errorf("got %q, want %q", result, "body-data|trailer-value")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for trailer")
	}
}
