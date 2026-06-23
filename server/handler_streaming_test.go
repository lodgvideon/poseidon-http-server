package server

import (
	"bytes"
	"io"
	"testing"
)

// NewHTTPRequest must wire a streaming Request.BodyReader (set when the server
// runs with Options.StreamingBody) into http.Request.Body. Before the fix it
// consulted only Request.Body ([]byte) and left BodyReader unread, so the
// http.Request got http.NoBody and a FromHTTPHandler handler saw an EMPTY body
// — the streamed request body was silently discarded.
func TestNewHTTPRequest_StreamingBodyReader(t *testing.T) {
	data := []byte("streamed request body bytes")
	req := &Request{
		Method:     "POST",
		Path:       "/upload",
		BodyReader: io.NopCloser(bytes.NewReader(data)), // Body is nil in streaming mode
	}

	httpReq, err := NewHTTPRequest(req)
	if err != nil {
		t.Fatalf("NewHTTPRequest: %v", err)
	}
	if httpReq.Body == nil {
		t.Fatal("http.Request.Body is nil")
	}
	got, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("streamed body = %q, want %q (BodyReader was ignored → empty body)", got, data)
	}
	if httpReq.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1 (unknown length for a stream)", httpReq.ContentLength)
	}
}

// The buffered ([]byte) and empty paths must keep working: Body is never nil,
// buffered bodies report their length, and an absent body reads as zero bytes.
func TestNewHTTPRequest_BufferedAndEmptyBody(t *testing.T) {
	buffered := &Request{Method: "POST", Path: "/", Body: []byte("buffered")}
	r, err := NewHTTPRequest(buffered)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	if string(b) != "buffered" {
		t.Fatalf("buffered body = %q, want %q", b, "buffered")
	}
	if r.ContentLength != int64(len("buffered")) {
		t.Errorf("buffered ContentLength = %d, want %d", r.ContentLength, len("buffered"))
	}

	empty := &Request{Method: "GET", Path: "/"}
	r2, err := NewHTTPRequest(empty)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Body == nil {
		t.Fatal("empty request: Body is nil, want http.NoBody")
	}
	b2, err := io.ReadAll(r2.Body)
	if err != nil || len(b2) != 0 {
		t.Fatalf("empty body: read %q err=%v, want 0 bytes / nil", b2, err)
	}
}
