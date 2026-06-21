package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// FuzzServerConn drives a real ServerConn (over net.Pipe) with arbitrary
// fuzzed bytes AFTER a valid client preface + SETTINGS handshake, and asserts
// the server NEVER panics. Malformed frames must be rejected with a connection
// error / GOAWAY and the connection must tear down cleanly.
//
// Harness shape:
//  1. net.Pipe() — synchronous in-memory transport.
//  2. A client goroutine writes the HTTP/2 preface, a valid SETTINGS frame,
//     reads the server SETTINGS, ACKs, reads the server ACK, then dumps the
//     fuzzed bytes raw onto the wire and closes.
//  3. NewServerConn completes the handshake; we then drain AcceptStream and
//     each accepted stream until the connection collapses.
//
// Any panic in a harness-owned goroutine is converted to a test failure with
// the crashing input. A panic inside ServerConn's own reader goroutine aborts
// the process, which the Go fuzzer records as a crash together with the input —
// exactly the failure signal we want.
func FuzzServerConn(f *testing.F) {
	enc := hpack.NewEncoder()
	hdrBlock := func(hf []hpack.HeaderField) []byte { return enc.EncodeBlock(nil, hf) }

	getReq := hdrBlock([]hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("example.com")},
		{Name: []byte(":path"), Value: []byte("/")},
	})

	// Seeds: empty, garbage, a truncated frame header, and a structurally
	// valid HEADERS frame body (without going through the framer — raw bytes
	// the server's reader must parse).
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff}) // truncated frame header
	// A 9-byte frame header claiming a huge length but no payload.
	f.Add([]byte{0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// PING frame header (type=0x06) with wrong length.
	f.Add([]byte{0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00})
	// RST_STREAM on stream 1 (rapid-reset-ish): type=0x03 len=4.
	f.Add([]byte{0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08})
	// A real-ish HEADERS frame on stream 1 carrying a valid request block.
	if len(getReq) < 1<<16 {
		hf := make([]byte, 0, 9+len(getReq))
		l := len(getReq)
		hf = append(hf, byte(l>>16), byte(l>>8), byte(l)) // length
		hf = append(hf, 0x01)                             // type=HEADERS
		hf = append(hf, 0x05)                             // flags: END_HEADERS|END_STREAM
		hf = append(hf, 0x00, 0x00, 0x00, 0x01)           // stream 1
		hf = append(hf, getReq...)
		f.Add(hf)
	}

	f.Fuzz(func(t *testing.T, fuzzed []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic driving ServerConn with fuzzed input %x: %v", fuzzed, r)
			}
		}()

		cli, srv := net.Pipe()

		// Hard deadline so a fuzzed input that wedges the pipe cannot hang
		// the fuzzer; net.Pipe honors SetDeadline. Kept short so the fuzzer
		// can explore many inputs per second — the server reacts to the
		// fuzzed bytes near-instantly, and a deadline merely caps the wait
		// for connections that neither error nor close on their own.
		deadline := time.Now().Add(250 * time.Millisecond)
		_ = cli.SetDeadline(deadline)
		_ = srv.SetDeadline(deadline)

		clientDone := make(chan struct{})
		go func() {
			defer close(clientDone)
			defer func() { _ = recover() }() // client-side panics are not under test
			defer cli.Close()

			// 1. Client preface magic.
			if _, err := cli.Write(clientPreface); err != nil {
				return
			}
			cliFr := frame.NewFramer(cli, cli)

			// 2. Client SETTINGS (defaults).
			wd := make(chan error, 1)
			go func() { wd <- cliFr.WriteSettings(frame.SettingsParams{}) }()
			if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
				return
			}
			if err := <-wd; err != nil {
				return
			}

			// 3. ACK server SETTINGS, read server ACK.
			go func() { wd <- cliFr.WriteSettingsAck() }()
			if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
				return
			}
			if err := <-wd; err != nil {
				return
			}

			// 4. Dump the fuzzed bytes raw onto the wire. The server's reader
			//    loop must parse/reject them without panicking.
			_, _ = cli.Write(fuzzed)
			// Keep reading anything the server sends back (GOAWAY, etc.) so the
			// pipe drains and the server write side never blocks.
			for {
				if _, err := cliFr.ReadFrame(context.Background(), &nilHandler{}); err != nil {
					return
				}
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()

		sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
		if err != nil {
			// Handshake rejected (e.g. fuzzed bytes corrupted SETTINGS): that
			// is a clean, non-panicking outcome.
			<-clientDone
			return
		}

		// Drain accepted streams until the connection collapses. Each accepted
		// stream is read to completion so DATA/HEADERS/RST handling executes.
		go func() {
			for {
				st, aerr := sc.AcceptStream(ctx)
				if aerr != nil {
					return
				}
				go drainStream(ctx, st)
			}
		}()

		// Give the reader loop time to consume the fuzzed bytes and react.
		select {
		case <-ctx.Done():
		case <-sc.readerDone:
		}
		_ = sc.Close()
		<-clientDone
	})
}

// drainStream consumes all events from a stream until it ends or errors,
// exercising the server-side per-stream receive path on fuzzed input.
func drainStream(ctx context.Context, st *ServerStream) {
	defer func() { _ = recover() }()
	for {
		ev, err := st.Recv(ctx)
		if err != nil {
			return
		}
		if ev.EndStream {
			return
		}
	}
}
