package server

import (
	"net/http"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for HEAD responses.
//
// RFC 9110 §9.3.2 (rfc9110.txt:3987):
//
//	"The HEAD method is identical to GET except that the server MUST NOT send
//	 content in the response."
//
// and (:3993):
//
//	"The server SHOULD send the same header fields in response to a HEAD
//	 request as it would have sent if the request method had been GET."
//
// So the DATA frames are suppressed while the header section is left alone.
// RFC 9113 §8.1.1 blesses the resulting mismatch
// explicitly: "A response that is defined to have no content ... MAY have a
// non-zero content-length header field, even though no content is included in
// DATA frames."
//
// Nothing in conn/, server/ or middleware/ was aware of HEAD at all —
// MethodHead did not appear anywhere in the repository — so a handler's body
// went out in full. It bites hardest through FromHTTPHandler, where a stdlib
// handler is written on the assumption that net/http suppresses the body for it.

func headWriter(method string) (*responseWriter, *mockStreamWriter) {
	sw := &mockStreamWriter{id: 1}
	w := newResponseWriterWithSW(sw)
	w.req = &Request{Method: method, Path: "/", Scheme: "https", Authority: "example.com"}
	return w, sw
}

// TestConformance_RFC9110_Sec932_HeadSendsNoContent pins rfc9110.txt:3987 for
// both write paths: the native WriteData and the stdlib-compatible Write.
func TestConformance_RFC9110_Sec932_HeadSendsNoContent(t *testing.T) {
	t.Run("WriteData", func(t *testing.T) {
		w, sw := headWriter(http.MethodHead)
		if err := w.WriteData([]byte("body bytes")); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
		if len(sw.dataSent) != 0 {
			t.Errorf("sent %d DATA frame(s) on a HEAD response: %q — RFC 9110 §9.3.2 "+
				"says the server MUST NOT send content", len(sw.dataSent), sw.dataSent)
		}
		if !w.Written() {
			t.Error("headers were not sent; only the content is suppressed")
		}
	})

	t.Run("Write", func(t *testing.T) {
		w, sw := headWriter(http.MethodHead)
		n, err := w.Write([]byte("body bytes"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		// io.Writer contract: a short write must be an error, so a suppressed
		// body has to report the full length or io.Copy in a stdlib handler
		// fails or spins.
		if n != len("body bytes") {
			t.Errorf("Write returned n = %d, want %d; a suppressed HEAD body must still "+
				"report a complete write", n, len("body bytes"))
		}
		if len(sw.dataSent) != 0 {
			t.Errorf("sent %d DATA frame(s) on a HEAD response: %q", len(sw.dataSent), sw.dataSent)
		}
	})
}

// TestConformance_RFC9110_Sec932_GetStillSendsContent is the control: the
// suppression must key on the method and nothing else.
func TestConformance_RFC9110_Sec932_GetStillSendsContent(t *testing.T) {
	w, sw := headWriter(http.MethodGet)
	if err := w.WriteData([]byte("body bytes")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	if len(sw.dataSent) != 1 || string(sw.dataSent[0]) != "body bytes" {
		t.Errorf("GET dataSent = %q, want one frame of \"body bytes\"", sw.dataSent)
	}
}

// TestConformance_RFC9110_Sec932_HeadKeepsHeaderFields pins rfc9110.txt:3993
// together with RFC 9113 §8.1.1 — the header section, content-length included,
// survives untouched even though no DATA follows.
func TestConformance_RFC9110_Sec932_HeadKeepsHeaderFields(t *testing.T) {
	w, sw := headWriter(http.MethodHead)
	if err := w.WriteHeaders(200, []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte("text/plain")},
		{Name: []byte("content-length"), Value: []byte("10")},
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := w.WriteData([]byte("body bytes")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	if len(sw.headersSent) == 0 {
		t.Fatal("no header block was sent")
	}
	got, _ := pseudoValue(sw.headersSent[0], "content-length")
	if got != "10" {
		t.Errorf("content-length = %q, want it preserved on a HEAD response", got)
	}
	if len(sw.dataSent) != 0 {
		t.Errorf("sent %d DATA frame(s) on a HEAD response", len(sw.dataSent))
	}
}
