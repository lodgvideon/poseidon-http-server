package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestH2C_PriorKnowledge verifies direct HTTP/2 preface (prior knowledge).
func TestH2C_PriorKnowledge(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		H2C: true,
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

	// Send H2 preface directly (prior knowledge).
	_ = performClientHandshake(c, fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Errorf("status = %q, want 200", statusValue(headers))
	}
}

// TestH2C_Upgrade verifies HTTP/1.1 Upgrade: h2c → 101 Switching.
func TestH2C_Upgrade(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		H2C: true,
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

	// Send HTTP/1.1 Upgrade request.
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: h2c\r\n"+
		"HTTP2-Settings: \r\n"+
		"Connection: Upgrade\r\n\r\n")

	// Read 101 Switching Protocols response.
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %q", line)
	}
	// Skip remaining headers until empty line.
	for {
		hdr, _ := br.ReadString('\n')
		if strings.TrimSpace(hdr) == "" {
			break
		}
	}

	// Now send HTTP/2 preface + settings.
	_, _ = c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	rwc := &bufioConn{Conn: c, Reader: br}
	fr := frame.NewFramer(rwc, rwc)
	_ = performClientHandshakeAfterPreface(fr)

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/upgraded")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Errorf("status = %q, want 200", statusValue(headers))
	}
}

// TestH2C_RejectHTTP1 verifies plain HTTP/1.1 without Upgrade gets 400.
func TestH2C_RejectHTTP1(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		H2C: true,
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

	// Send plain HTTP/1.1 without Upgrade.
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Errorf("expected 400 Bad Request, got: %q", line)
	}
}

// TestH2C_Disabled verifies that H2C=false still works for direct H2.
func TestH2C_Disabled(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w *ResponseWriter) error {
			_ = w.WriteHeaders(200, nil)
			return nil
		}),
		H2C: false,
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
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	_ = fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	headers, herr := readResponseHeaders(fr)
	if herr != nil {
		t.Fatal(herr)
	}
	if statusValue(headers) != "200" {
		t.Errorf("status = %q, want 200", statusValue(headers))
	}
}

// performClientHandshakeAfterPreface sends settings after the preface
// was already written to the wire (e.g. after 101 upgrade).
// performClientHandshakeAfterPreface does full H2 handshake after
// the preface magic was already written to the wire.
func performClientHandshakeAfterPreface(fr *frame.Framer) error {
	_ = fr.WriteSettings(frame.SettingsParams{})
	// Read server SETTINGS.
	if _, err := fr.ReadFrame(context.Background(), &noopHandler{}); err != nil {
		return err
	}
	_ = fr.WriteSettingsAck()
	// Read server SETTINGS ACK.
	if _, err := fr.ReadFrame(context.Background(), &noopHandler{}); err != nil {
		return err
	}
	return nil
}
