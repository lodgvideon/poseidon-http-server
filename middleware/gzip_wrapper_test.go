package middleware

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// fakeRW is a minimal server.ResponseWriter that records what the gzip wrapper
// forwards to it. It deliberately does NOT implement server.Pusher.
type fakeRW struct {
	header        http.Header
	nativeStatus  int
	nativeHeaders []hpack.HeaderField
	httpStatus    int
	data          [][]byte
	trailers      int
	written       bool
}

func newFakeRW() *fakeRW { return &fakeRW{header: make(http.Header)} }

func (f *fakeRW) Header() http.Header { return f.header }

func (f *fakeRW) Write(p []byte) (int, error) {
	f.written = true
	f.data = append(f.data, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeRW) WriteHeader(status int) {
	f.httpStatus = status
	f.written = true
}

func (f *fakeRW) WriteHeaders(status int, headers []hpack.HeaderField) error {
	f.nativeStatus = status
	f.nativeHeaders = headers
	f.written = true
	return nil
}

func (f *fakeRW) WriteData(p []byte) error {
	f.written = true
	f.data = append(f.data, append([]byte(nil), p...))
	return nil
}

func (f *fakeRW) WriteTrailers([]hpack.HeaderField) error {
	f.trailers++
	return nil
}

func (f *fakeRW) Status() int     { return f.nativeStatus }
func (f *fakeRW) StatusCode() int { return f.nativeStatus }
func (f *fakeRW) Written() bool   { return f.written }

// fakePusherRW additionally implements server.Pusher.
type fakePusherRW struct {
	*fakeRW
	pushed []string
}

func (f *fakePusherRW) Push(path string, _ []hpack.HeaderField) (server.ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock: tests only assert the recorded push path
}

func (f *fakePusherRW) PushWithScheme(path, _ string, _ []hpack.HeaderField) (server.ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock: tests only assert the recorded push path
}

func (f *fakePusherRW) PushWithPriority(path string, _ []hpack.HeaderField, _ *frame.Priority) (server.ResponseWriter, error) {
	f.pushed = append(f.pushed, path)
	return nil, nil //nolint:nilnil // mock: tests only assert the recorded push path
}

func hasField(headers []hpack.HeaderField, name, value string) bool {
	for _, h := range headers {
		if string(h.Name) == name && string(h.Value) == value {
			return true
		}
	}
	return false
}

// TestGzipWrapper_NativeFlushCompresses checks the native path: a large body
// flushes with content-encoding: gzip and compressed bytes.
func TestGzipWrapper_NativeFlushCompresses(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	_ = gw.WriteHeaders(200, []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("text/plain")},
		{Name: []byte("content-length"), Value: []byte("9999")},
	})
	_ = gw.WriteData(gzipBigBody)
	if err := gw.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if under.nativeStatus != 200 {
		t.Fatalf("status = %d, want 200", under.nativeStatus)
	}
	if !hasField(under.nativeHeaders, "content-encoding", "gzip") {
		t.Fatal("missing content-encoding: gzip")
	}
	if hasField(under.nativeHeaders, "content-length", "9999") {
		t.Fatal("stale content-length must be dropped when compressing")
	}
	if len(under.data) != 1 || len(under.data[0]) >= len(gzipBigBody) {
		t.Fatal("body was not compressed")
	}
}

// TestGzipWrapper_FlushIdempotent verifies a second flush is a no-op.
func TestGzipWrapper_FlushIdempotent(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}
	_ = gw.WriteData(gzipBigBody)
	_ = gw.flush()
	_ = gw.flush()
	if len(under.data) != 1 {
		t.Fatalf("data writes = %d, want 1 (idempotent flush)", len(under.data))
	}
}

// TestGzipWrapper_NothingWritten verifies that if the handler writes nothing,
// flush forwards nothing (the server finalizes on the original writer).
func TestGzipWrapper_NothingWritten(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}
	if err := gw.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if under.written {
		t.Fatal("nothing should be forwarded when the handler wrote nothing")
	}
}

// TestGzipWrapper_WriteTrailersFlushesFirst verifies a handler that ends its own
// stream still gets the buffered body flushed before the trailers.
func TestGzipWrapper_WriteTrailersFlushesFirst(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	_ = gw.WriteData(gzipBigBody)
	if err := gw.WriteTrailers(nil); err != nil {
		t.Fatalf("WriteTrailers: %v", err)
	}
	if len(under.data) != 1 {
		t.Fatal("body should have been flushed before trailers")
	}
	if under.trailers != 1 {
		t.Fatalf("trailers forwarded = %d, want 1", under.trailers)
	}
}

// TestGzipWrapper_HTTPPathAuto200 verifies the stdlib Write path defaults the
// status to 200 and compresses via the Header() map.
func TestGzipWrapper_HTTPPathAuto200(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	if _, err := gw.Write(gzipBigBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !gw.Written() || gw.Status() != http.StatusOK {
		t.Fatalf("Written=%v Status=%d, want true/200", gw.Written(), gw.Status())
	}
	if err := gw.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if under.httpStatus != 200 {
		t.Fatalf("http status = %d, want 200", under.httpStatus)
	}
	if under.header.Get("Content-Encoding") != "gzip" {
		t.Fatal("http path should set Content-Encoding: gzip")
	}
	if len(under.data) != 1 || len(under.data[0]) >= len(gzipBigBody) {
		t.Fatal("http-path body was not compressed")
	}
}

// TestGzipWrapper_SmallBodyIdentity verifies sub-MinSize bodies pass through
// uncompressed with no content-encoding (native path).
func TestGzipWrapper_SmallBodyIdentity(t *testing.T) {
	t.Parallel()
	under := newFakeRW()
	gw := &gzipResponseWriter{ResponseWriter: under, cfg: DefaultGzipConfig()}

	small := []byte("hi there")
	_ = gw.WriteHeaders(200, nil)
	_ = gw.WriteData(small)
	_ = gw.flush()

	if hasField(under.nativeHeaders, "content-encoding", "gzip") {
		t.Fatal("small body must not be gzip-encoded")
	}
	if len(under.data) != 1 || !bytes.Equal(under.data[0], small) {
		t.Fatalf("small body altered: %v", under.data)
	}
}

// TestGzipWrapper_PushDelegation verifies Push forwards to a Pusher-capable
// underlying writer, and reports ErrPushNotSupported otherwise.
func TestGzipWrapper_PushDelegation(t *testing.T) {
	t.Parallel()

	// Underlying writer supports push.
	pusher := &fakePusherRW{fakeRW: newFakeRW()}
	gw := &gzipResponseWriter{ResponseWriter: pusher, cfg: DefaultGzipConfig()}
	if _, err := gw.Push("/style.css", nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := gw.PushWithScheme("/a.js", "https", nil); err != nil {
		t.Fatalf("PushWithScheme: %v", err)
	}
	if _, err := gw.PushWithPriority("/b.css", nil, nil); err != nil {
		t.Fatalf("PushWithPriority: %v", err)
	}
	if len(pusher.pushed) != 3 {
		t.Fatalf("pushed = %v, want 3 paths", pusher.pushed)
	}

	// Underlying writer does NOT support push.
	noPush := &gzipResponseWriter{ResponseWriter: newFakeRW(), cfg: DefaultGzipConfig()}
	if _, err := noPush.Push("/x", nil); !errors.Is(err, server.ErrPushNotSupported) {
		t.Fatalf("Push err = %v, want ErrPushNotSupported", err)
	}
	if _, err := noPush.PushWithScheme("/x", "http", nil); !errors.Is(err, server.ErrPushNotSupported) {
		t.Fatalf("PushWithScheme err = %v, want ErrPushNotSupported", err)
	}
	if _, err := noPush.PushWithPriority("/x", nil, nil); !errors.Is(err, server.ErrPushNotSupported) {
		t.Fatalf("PushWithPriority err = %v, want ErrPushNotSupported", err)
	}
}

// TestGzipWrapper_ImplementsInterfaces is a compile-time-ish guard that the
// wrapper satisfies both ResponseWriter and Pusher.
func TestGzipWrapper_ImplementsInterfaces(t *testing.T) {
	t.Parallel()
	var _ server.ResponseWriter = (*gzipResponseWriter)(nil)
	var _ server.Pusher = (*gzipResponseWriter)(nil)
}
