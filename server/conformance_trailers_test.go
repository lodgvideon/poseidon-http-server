package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for trailer handling in ToHTTPHandler.
//
// RFC 9110 §6.5.1 (rfc9110.txt:2245):
//
//	"A recipient MUST NOT merge a trailer field into a header section unless
//	 the recipient understands the corresponding header field definition and
//	 that definition explicitly permits and defines how trailer field values
//	 can be safely merged."
//
// bufferStreamWriter received the endStream flag that distinguishes the two and
// discarded it, appending everything into one field list; its comment asserted
// that "appending them is harmless". It is not: a Poseidon handler's trailers —
// grpc-status and grpc-message above all — surfaced in the response header
// section of the http.ResponseWriter this adapter replays onto.
//
// They are forwarded as real trailers rather than dropped. The RFC notes that
// "in most cases, the trailers are simply discarded" (:2244), which would also
// satisfy the MUST, but dropping grpc-status loses the outcome of the call.

// TestConformance_RFC9110_Sec651_TrailersNotMergedIntoHeaders pins :2245.
func TestConformance_RFC9110_Sec651_TrailersNotMergedIntoHeaders(t *testing.T) {
	h := ToHTTPHandler(HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		if err := w.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("content-type"), Value: []byte("application/grpc")},
		}); err != nil {
			return err
		}
		if err := w.WriteData([]byte("payload")); err != nil {
			return err
		}
		return w.WriteTrailers([]hpack.HeaderField{
			{Name: []byte("grpc-status"), Value: []byte("5")},
			{Name: []byte("grpc-message"), Value: []byte("not found")},
		})
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://example.com/svc/Method", nil))
	res := rec.Result()
	defer res.Body.Close()

	if got := res.Header.Get("grpc-status"); got != "" {
		t.Errorf("grpc-status = %q in the HEADER section; RFC 9110 §6.5.1 forbids merging "+
			"a trailer field into the header section", got)
	}
	if got := res.Header.Get("grpc-message"); got != "" {
		t.Errorf("grpc-message = %q in the header section", got)
	}
	// The response's own header fields must still come through.
	if got := res.Header.Get("Content-Type"); got != "application/grpc" {
		t.Errorf("Content-Type = %q, want application/grpc — response headers must survive", got)
	}
	if got := res.StatusCode; got != 200 {
		t.Errorf("status = %d, want 200", got)
	}
}

// TestConformance_RFC9110_Sec651_TrailersForwardedAsTrailers checks the
// information is preserved rather than dropped: dropping would satisfy the MUST
// but would lose the outcome of a gRPC call.
func TestConformance_RFC9110_Sec651_TrailersForwardedAsTrailers(t *testing.T) {
	h := ToHTTPHandler(HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		if err := w.WriteHeaders(200, nil); err != nil {
			return err
		}
		return w.WriteTrailers([]hpack.HeaderField{
			{Name: []byte("grpc-status"), Value: []byte("5")},
		})
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://example.com/svc/Method", nil))
	res := rec.Result()
	defer res.Body.Close()

	if got := res.Trailer.Get("grpc-status"); got != "5" {
		t.Errorf("trailer grpc-status = %q, want %q; the field must be forwarded as a "+
			"trailer, not merged and not dropped", got, "5")
	}
}

// TestConformance_RFC9110_Sec651_HeaderOnlyResponseUnaffected is the boundary
// case: a response with no trailers at all must be untouched by the split.
func TestConformance_RFC9110_Sec651_HeaderOnlyResponseUnaffected(t *testing.T) {
	h := ToHTTPHandler(HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
		return w.WriteHeaders(204, []hpack.HeaderField{
			{Name: []byte("x-marker"), Value: []byte("present")},
		})
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
	res := rec.Result()
	defer res.Body.Close()

	if got := res.Header.Get("x-marker"); got != "present" {
		t.Errorf("x-marker = %q, want present", got)
	}
	if res.StatusCode != 204 {
		t.Errorf("status = %d, want 204", res.StatusCode)
	}
}
