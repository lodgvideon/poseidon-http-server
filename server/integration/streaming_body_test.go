package integration

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// With Options.StreamingBody=true the server sets Request.BodyReader (not the
// buffered Request.Body). A FromHTTPHandler-wrapped http.Handler must still
// receive the full request body. Before the fix, NewHTTPRequest ignored
// BodyReader, so the handler read an empty body (http.NoBody) and the streamed
// request body was silently discarded. Body is kept small (16 KiB, within the
// default window) to avoid any flow-control timing sensitivity.
func TestStreamingBody_FromHTTPHandlerReceivesFullBody(t *testing.T) {
	h := server.FromHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Body-Len", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
	}))
	ts := startTestServer(t, h, func(o *server.Options) {
		o.StreamingBody = true
	})

	const size = 16 << 10
	body := bytes.Repeat([]byte("z"), size)
	resp, err := ts.client.Post(ts.URL()+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Body-Len"); got != strconv.Itoa(size) {
		t.Fatalf("X-Body-Len = %q, want %d (streaming request body was dropped)", got, size)
	}
}
