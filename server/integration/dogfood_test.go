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

// postBodyWithRetry POSTs a `size`-byte body and asserts the handler read it in
// full (X-Body-Len == size). It is resilient to transient shared-CI-runner
// stalls: each attempt uses a FRESH HTTP/2 connection with a bounded timeout,
// retried a few times. A genuine server-side flow-control deadlock reproduces on
// every fresh connection (all attempts fail → the test fails); a one-off runner
// freeze clears on the next attempt. The refund behaviour this exercises
// end-to-end is also covered deterministically by the conn-level flow-control
// tests (conn/server_coverage_test.go, conn/server_flowcontrol_test.go), so the
// retry cannot mask a reproducible bug.
func postBodyWithRetry(t *testing.T, ts *testServer, size int) {
	t.Helper()
	body := bytes.Repeat([]byte("x"), size)
	const attempts = 4
	var lastErr error
	for a := 1; a <= attempts; a++ {
		tr := &http.Transport{
			TLSClientConfig:    ts.tls,
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL()+"/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = int64(size)
		cli := &http.Client{Transport: tr, Timeout: 15 * time.Second}
		resp, err := cli.Do(req)
		if err != nil {
			lastErr = err
			tr.CloseIdleConnections()
			t.Logf("attempt %d/%d for %d-byte body failed: %v (retrying on a fresh connection)", a, attempts, size, err)
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%d-byte body)", resp.StatusCode, size)
		}
		if got := resp.Header.Get("X-Body-Len"); got != strconv.Itoa(size) {
			t.Fatalf("X-Body-Len = %q, want %d (body did not fully transfer)", got, size)
		}
		return
	}
	t.Fatalf("body of %d bytes never completed across %d fresh-connection attempts — "+
		"likely a real flow-control deadlock (no per-stream WINDOW_UPDATE refund; Bug 3): %v",
		size, attempts, lastErr)
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

	// 256 KiB is larger than the defaulted 64 KiB window, so it exercises the
	// refund path; pre-fix it deadlocked because a MaxConcurrentStreams-only
	// config advertised InitialWindowSize=0 (a zero peer send window).
	postBodyWithRetry(t, ts, 256<<10)
}

// Bug 3: the server advertises InitialWindowSize = W, so the client's per-stream
// SEND window is W. The server must refund the per-stream recv window (emit
// stream-level WINDOW_UPDATE) as it consumes DATA; otherwise a body at/over W
// deadlocks once the client exhausts its send window. Before the fix, the W and
// 2W cases hang until the client deadline; sub-W works.
func TestDogfood_LargeBodyFlowControl(t *testing.T) {
	// W is kept modest so the transfer stays fast: it must exceed the advertised
	// window (forcing stream + connection WINDOW_UPDATE refund cycles — the path
	// the dogfood deadlock hit), but a multi-MiB body would amplify shared-runner
	// stalls. 256 KiB still exceeds the 64 KiB connection window several times
	// over. postBodyWithRetry supplies the CI-stall resilience (fresh connection
	// per attempt) so a transient freeze does not flake the run.
	const w = 256 << 10 // advertised InitialWindowSize
	ts := startTestServer(t, readLenHandler(), func(o *server.Options) {
		o.ConnOpts.AdvertisedSettings = conn.AdvertisedSettings{InitialWindowSize: w}
	})

	for _, size := range []int{64 << 10, w, 2 * w} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			postBodyWithRetry(t, ts, size)
		})
	}
}
