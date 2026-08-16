package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Conformance tests for the Date response field.
//
// RFC 9110 §6.6.1:
//
//	"An origin server with a clock (as defined in Section 5.6.7) MUST generate
//	 a Date header field in all 2xx (Successful), 3xx (Redirection), and 4xx
//	 (Client Error) responses, and MAY generate a Date header field in 1xx
//	 (Informational) and 5xx (Server Error) responses."
//
// Neither write path emitted one, so every framework-generated response — and
// every handler response — went out without a Date.
//
// 1xx and 5xx are a MAY and are deliberately left alone; the tests below assert
// only the MUST range, so adding them later would not be a regression.

func dateWriter() (*responseWriter, *mockStreamWriter) {
	sw := &mockStreamWriter{id: 1}
	w := newResponseWriterWithSW(sw)
	w.req = &Request{Method: http.MethodGet, Path: "/", Scheme: "https", Authority: "example.com"}
	return w, sw
}

func dateField(t *testing.T, fields []hpack.HeaderField) string {
	t.Helper()
	value, count := pseudoValue(fields, "date")
	if count > 1 {
		t.Fatalf("date field appeared %d times, want at most 1", count)
	}
	return value
}

// TestConformance_RFC9110_Sec661_DateOnMustStatuses pins RFC 9110 §6.6.1 for
// the whole MUST range, on the native write path.
func TestConformance_RFC9110_Sec661_DateOnMustStatuses(t *testing.T) {
	for _, status := range []int{200, 204, 301, 304, 400, 404, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			w, sw := dateWriter()
			if err := w.WriteHeaders(status, nil); err != nil {
				t.Fatalf("WriteHeaders: %v", err)
			}
			if len(sw.headersSent) != 1 {
				t.Fatalf("headersSent len = %d, want 1", len(sw.headersSent))
			}
			got := dateField(t, sw.headersSent[0])
			if got == "" {
				t.Fatalf("no date field on a %d response; RFC 9110 §6.6.1 makes it a MUST "+
					"for 2xx, 3xx and 4xx", status)
			}
			// §6.6.1: "The field value is an HTTP-date, as defined in Section 5.6.7."
			parsed, err := http.ParseTime(got)
			if err != nil {
				t.Fatalf("date = %q is not an HTTP-date: %v", got, err)
			}
			if delta := time.Since(parsed); delta < -2*time.Second || delta > time.Minute {
				t.Errorf("date = %q is %v away from now; it must approximate the time of "+
					"message generation", got, delta)
			}
		})
	}
}

// TestConformance_RFC9110_Sec661_DateOnStdlibPath covers the other write path:
// a handler using Header()/WriteHeader must get the same treatment.
func TestConformance_RFC9110_Sec661_DateOnStdlibPath(t *testing.T) {
	w, sw := dateWriter()
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	if len(sw.headersSent) != 1 {
		t.Fatalf("headersSent len = %d, want 1", len(sw.headersSent))
	}
	if got := dateField(t, sw.headersSent[0]); got == "" {
		t.Error("no date field on the stdlib write path")
	}
}

// TestConformance_RFC9110_Sec661_HandlerDateWins guards against overwriting or
// duplicating a Date the handler set deliberately. A repeated field would also
// be a grammar violation in its own right.
func TestConformance_RFC9110_Sec661_HandlerDateWins(t *testing.T) {
	const handlerDate = "Tue, 15 Nov 1994 08:12:31 GMT"

	t.Run("native", func(t *testing.T) {
		w, sw := dateWriter()
		if err := w.WriteHeaders(200, []hpack.HeaderField{
			{Name: []byte("date"), Value: []byte(handlerDate)},
		}); err != nil {
			t.Fatalf("WriteHeaders: %v", err)
		}
		if got := dateField(t, sw.headersSent[0]); got != handlerDate {
			t.Errorf("date = %q, want the handler's %q", got, handlerDate)
		}
	})

	t.Run("stdlib", func(t *testing.T) {
		w, sw := dateWriter()
		w.Header().Set("Date", handlerDate)
		w.WriteHeader(200)
		if got := dateField(t, sw.headersSent[0]); got != handlerDate {
			t.Errorf("date = %q, want the handler's %q", got, handlerDate)
		}
	})
}
