package server

import (
	"context"
	"io"
	"sync"

	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// streamBody — io.ReadCloser backed by ServerStream events
// ---------------------------------------------------------------------------

// streamBody implements io.ReadCloser by reading DATA frames from a
// ServerStream on demand. This avoids buffering the entire request body
// in memory.
type streamBody struct {
	stream *conn.ServerStream
	ctx    context.Context

	mu          sync.Mutex
	buf         []byte   // leftover data from last event
	done        bool     // true after EndStream or Reset
}

// newStreamBody creates a streaming body reader. The first call to Read
// will consume the HEADERS event (if not already consumed) and then
// read DATA frames lazily.
func newStreamBody(ctx context.Context, stream *conn.ServerStream) *streamBody {
	return &streamBody{
		stream: stream,
		ctx:    ctx,
	}
}

// Read reads request body bytes. Blocks until data is available, EOF,
// or the context is cancelled.
func (sb *streamBody) Read(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Drain buffered data first.
	if len(sb.buf) > 0 {
		n := copy(p, sb.buf)
		sb.buf = sb.buf[n:]
		return n, nil
	}

	if sb.done {
		return 0, io.EOF
	}

	// Read next event from stream.
	for {
		ev, err := sb.stream.Recv(sb.ctx)
		if err != nil {
			sb.done = true
			return 0, err
		}

		switch ev.Type {
		case conn.EventHeaders:
			// Skip — headers already consumed by serveStream.
			if ev.EndStream {
				sb.done = true
				return 0, io.EOF
			}

		case conn.EventData:
			if len(ev.Data) == 0 {
				if ev.EndStream {
					sb.done = true
					return 0, io.EOF
				}
				continue
			}

			n := copy(p, ev.Data)
			if n < len(ev.Data) {
				sb.buf = append(sb.buf, ev.Data[n:]...)
			}

			if ev.EndStream {
				sb.done = true
				if n == 0 {
					return 0, io.EOF
				}
			}
			return n, nil

		case conn.EventTrailers:
			sb.done = true
			return 0, io.EOF

		case conn.EventReset:
			sb.done = true
			return 0, io.ErrUnexpectedEOF
		}
	}
}

// Close marks the body as done. Subsequent reads return EOF.
func (sb *streamBody) Close() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.done = true
	return nil
}
