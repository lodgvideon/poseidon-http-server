package integration

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-server/conn"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// readLenHandler reads the entire request body and reports its length in the
// X-Body-Len response header (a small response, to isolate REQUEST-body flow
// control from response-body flow control). It mirrors the dogfood handler that
// does io.ReadAll(r.Body).
func readLenHandler() server.Handler {
	return server.FromHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Body-Len", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
	}))
}

// Bug 2: net/http guarantees Request.Body is non-nil on the server side. A
// handler doing io.ReadAll(r.Body) on a request with no body must NOT panic.
// Before the fix the compat layer left r.Body == nil for empty-body requests,
// so io.ReadAll(nil) panicked (nil-pointer deref) -> the request failed.
func TestDogfood_EmptyBodyReadAllDoesNotPanic(t *testing.T) {
	ts := startTestServer(t, readLenHandler())

	// GET with no body, and a POST with an explicit zero-length body.
	cases := []struct {
		name string
		do   func() (*http.Response, error)
	}{
		{"GET-no-body", func() (*http.Response, error) { return ts.client.Get(ts.URL() + "/") }},
		{"POST-empty-body", func() (*http.Response, error) {
			return ts.client.Post(ts.URL()+"/", "application/octet-stream", bytes.NewReader(nil))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.do()
			if err != nil {
				t.Fatalf("request failed (handler likely panicked on nil r.Body): %v", err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Body-Len"); got != "0" {
				t.Fatalf("X-Body-Len = %q, want \"0\"", got)
			}
		})
	}
}

// Bug 3 (consistency): setting only MaxConcurrentStreams must NOT leave the
// advertised InitialWindowSize at 0. Before the fix, ServerConnOptions.defaulted()
// only defaulted the advertised settings when MaxConcurrentStreams==0, so a caller
// that set only MaxConcurrentStreams advertised InitialWindowSize=0 — a zero send
// window for the peer — and every request body deadlocked.
func TestDogfood_MaxStreamsSetStillAdvertisesWindow(t *testing.T) {
	ts := startTestServer(t, readLenHandler(), func(o *server.Options) {
		o.ConnOpts.AdvertisedSettings = conn.AdvertisedSettings{MaxConcurrentStreams: 50}
	})

	const size = 256 << 10 // larger than the defaulted 64 KiB window, exercises refund too
	body := bytes.Repeat([]byte("y"), size)
	req, err := http.NewRequest(http.MethodPost, ts.URL()+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(size)

	cli := &http.Client{Transport: ts.client.Transport, Timeout: 5 * time.Second}
	done := make(chan *http.Response, 1)
	errc := make(chan error, 1)
	go func() {
		resp, err := cli.Do(req) //nolint:bodyclose // closed by the receiver in the select below
		if err != nil {
			errc <- err
			return
		}
		done <- resp
	}()
	select {
	case resp := <-done:
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		if got := resp.Header.Get("X-Body-Len"); got != strconv.Itoa(size) {
			t.Fatalf("X-Body-Len = %q, want %d", got, size)
		}
	case err := <-errc:
		t.Fatalf("request error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("body deadlocked: advertised InitialWindowSize was 0 (Bug 3 consistency)")
	}
}

// Bug 3: the server advertises InitialWindowSize = W, so the client's per-stream
// SEND window is W. The server must refund the per-stream recv window (emit
// stream-level WINDOW_UPDATE) as it consumes DATA; otherwise a body at/over W
// deadlocks once the client exhausts its send window. Before the fix, the W and
// 2W cases hang until the client deadline; sub-W works.
func TestDogfood_LargeBodyFlowControl(t *testing.T) {
	const w = 1 << 20 // advertised InitialWindowSize
	ts := startTestServer(t, readLenHandler(), func(o *server.Options) {
		o.ConnOpts.AdvertisedSettings = conn.AdvertisedSettings{InitialWindowSize: w}
	})

	for _, size := range []int{64 << 10, w, 2 * w} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			body := bytes.Repeat([]byte("x"), size)
			req, err := http.NewRequest(http.MethodPost, ts.URL()+"/", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(size)

			cli := &http.Client{Transport: ts.client.Transport, Timeout: 5 * time.Second}
			done := make(chan *http.Response, 1)
			errc := make(chan error, 1)
			go func() {
				resp, err := cli.Do(req) //nolint:bodyclose // closed by the receiver in the select below
				if err != nil {
					errc <- err
					return
				}
				done <- resp
			}()

			select {
			case resp := <-done:
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d, want 200", resp.StatusCode)
				}
				if got := resp.Header.Get("X-Body-Len"); got != strconv.Itoa(size) {
					t.Fatalf("X-Body-Len = %q, want %d (body did not fully transfer)", got, size)
				}
			case err := <-errc:
				t.Fatalf("request error: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatalf("body of %d bytes deadlocked (no per-stream WINDOW_UPDATE refund; Bug 3)", size)
			}
		})
	}
}
