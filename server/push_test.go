package server

import (
	"context"
	"errors"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// errMockPushNotUsed is returned by mockPushableStream; tests do not consume the stream.
var errMockPushNotUsed = errors.New("mock push: stream not used")

// mockPushableStream is a pushableStream for tests.
type mockPushableStream struct {
	id         uint32
	pushedTo   []string
	headerSets [][]hpack.HeaderField
}

func (m *mockPushableStream) ID() uint32 { return m.id }

func (m *mockPushableStream) Push(_ context.Context, fields []hpack.HeaderField) (*conn.ServerStream, error) {
	// Capture path.
	for _, f := range fields {
		if string(f.Name) == ":path" {
			m.pushedTo = append(m.pushedTo, string(f.Value))
		}
	}
	m.headerSets = append(m.headerSets, fields)
	// Return sentinel error; tests do not consume the stream.
	return nil, errMockPushNotUsed
}

// mockPusher is a streamWriter that also implements the pusher interface.
type mockPusher struct {
	stream *mockPushableStream
}

func (m *mockPusher) canPush() (pushableStream, bool) {
	return m.stream, true
}

func (m *mockPusher) sendHeaders(_ context.Context, _ []hpack.HeaderField, _ bool) error {
	return nil
}

func (m *mockPusher) sendData(_ context.Context, _ []byte, _ bool) error {
	return nil
}

func (m *mockPusher) streamID() uint32 { return m.stream.id }

func TestResponseWriter_Push_BeforeHeaders(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &ResponseWriter{sw: &mockPusher{stream: stream}}

	pushed, err := w.Push("/style.css", nil)
	if err != nil {
		// Test is only interested in headers, not real frame writing.
		// Mock returns sentinel; ensure the call reached the stream.
		if !errors.Is(err, errMockPushNotUsed) {
			t.Fatalf("Push: unexpected err = %v", err)
		}
	}
	// Either real push stream (nil ok for these tests) or nil on mock error.
	_ = pushed

	// Verify path was promised.
	if len(stream.pushedTo) != 1 || stream.pushedTo[0] != "/style.css" {
		t.Fatalf("pushedTo = %v, want [/style.css]", stream.pushedTo)
	}
}

func TestResponseWriter_Push_AfterHeaders_Fails(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &ResponseWriter{sw: &mockPusher{stream: stream}}

	// Mark as already written.
	w.written = true

	_, err := w.Push("/style.css", nil)
	if !errors.Is(err, ErrPushAlreadySent) {
		t.Fatalf("err = %v, want ErrPushAlreadySent", err)
	}
}

func TestResponseWriter_Push_NotSupported(t *testing.T) {
	t.Parallel()

	// Use a streamWriter that does NOT implement pusher.
	plain := &mockStreamWriter{id: 1}
	w := &ResponseWriter{sw: plain}

	_, err := w.Push("/style.css", nil)
	if !errors.Is(err, ErrPushNotSupported) {
		t.Fatalf("err = %v, want ErrPushNotSupported", err)
	}
}

func TestResponseWriter_Push_MultiplePromises(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &ResponseWriter{sw: &mockPusher{stream: stream}}

	paths := []string{"/style.css", "/app.js", "/favicon.ico"}
	for _, p := range paths {
		_, _ = w.Push(p, nil) // mock returns sentinel; ignore err
	}

	if len(stream.pushedTo) != 3 {
		t.Fatalf("pushedTo len = %d, want 3", len(stream.pushedTo))
	}
	for i, p := range paths {
		if stream.pushedTo[i] != p {
			t.Fatalf("pushedTo[%d] = %q, want %q", i, stream.pushedTo[i], p)
		}
	}
}

func TestResponseWriter_Push_WithCustomHeaders(t *testing.T) {
	t.Parallel()

	stream := &mockPushableStream{id: 1}
	w := &ResponseWriter{sw: &mockPusher{stream: stream}}

	customHeaders := []hpack.HeaderField{
		{Name: []byte("if-none-match"), Value: []byte(`"abc"`)},
		{Name: []byte("accept"), Value: []byte("text/css")},
	}

	_, _ = w.Push("/style.css", customHeaders) // mock returns sentinel; ignore err

	if len(stream.headerSets) != 1 {
		t.Fatalf("headerSets len = %d, want 1", len(stream.headerSets))
	}

	// Verify :method, :path, :scheme are present + custom headers.
	got := stream.headerSets[0]
	wantHeaders := map[string]string{
		":method":        "GET",
		":path":          "/style.css",
		":scheme":        "https",
		"if-none-match":  `"abc"`,
		"accept":         "text/css",
	}
	for _, h := range got {
		if want, ok := wantHeaders[string(h.Name)]; ok {
			if string(h.Value) != want {
				t.Errorf("header %q = %q, want %q", h.Name, h.Value, want)
			}
			delete(wantHeaders, string(h.Name))
		}
	}
	if len(wantHeaders) > 0 {
		t.Errorf("missing headers: %v", wantHeaders)
	}
}

func TestErrPushNotSupported(t *testing.T) {
	t.Parallel()
	if ErrPushNotSupported == nil {
		t.Fatal("ErrPushNotSupported is nil")
	}
	if ErrPushNotSupported.Error() == "" {
		t.Fatal("ErrPushNotSupported has empty message")
	}
}

func TestErrPushAlreadySent(t *testing.T) {
	t.Parallel()
	if ErrPushAlreadySent == nil {
		t.Fatal("ErrPushAlreadySent is nil")
	}
	if ErrPushAlreadySent.Error() == "" {
		t.Fatal("ErrPushAlreadySent has empty message")
	}
}
