package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hclient "github.com/lodgvideon/poseidon-http-client/client"
)

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

type config struct {
	duration   time.Duration
	vus        int
	dataSize   int64
	jsonItems  int64
	rateLimit  float64
	maxBody    int64
	spikeAfter time.Duration
	spikeDur   time.Duration
	spikeVUs   int
	cpuProfile string
	memProfile string
	seed       int64
}

func parseFlags() config {
	var c config
	var dataSize, maxBody string
	flag.DurationVar(&c.duration, "duration", 15*time.Second, "sustained soak duration")
	flag.IntVar(&c.vus, "vus", 32, "sustained virtual users (concurrent goroutines)")
	flag.StringVar(&dataSize, "data-size", "16MiB", "upload/download body size (e.g. 64MiB, 10GiB) — streamed, so memory stays flat")
	flag.Int64Var(&c.jsonItems, "json-items", 40000, "items in the big-JSON response for the large-response parse scenario (~3.3MiB at the default; each item ≈83B)")
	flag.Float64Var(&c.rateLimit, "rate-limit", 100000, "global token-bucket rate (req/s); kept high so soak+spike stay under it (RateLimit is traversed but does not reject) — lower it below achievable throughput to exercise 429s, which the helpers treat as expected")
	flag.StringVar(&maxBody, "max-body", "-1", "server request-body limit (e.g. 12GiB); -1 disables")
	flag.DurationVar(&c.spikeAfter, "spike-after", 6*time.Second, "delay before the spike unblocks (0 disables the spike)")
	flag.DurationVar(&c.spikeDur, "spike-dur", 5*time.Second, "spike duration (set 2m for the full-scale burst)")
	flag.IntVar(&c.spikeVUs, "spike-vus", 0, "spike virtual users (0 => 4×vus)")
	flag.StringVar(&c.cpuProfile, "cpuprofile", "", "write a CPU profile to this file")
	flag.StringVar(&c.memProfile, "memprofile", "", "write a heap profile to this file")
	flag.Int64Var(&c.seed, "seed", 1, "PRNG seed for reproducible scenario selection")
	flag.Parse()

	c.dataSize = mustSize(dataSize)
	c.maxBody = mustSize(maxBody)
	if c.spikeVUs == 0 {
		c.spikeVUs = 4 * c.vus
	}
	return c
}

func mustSize(s string) int64 {
	n, err := parseSize(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return n
}

// parseSize parses "10GiB", "64MiB", "3MB", "-1", "1048576".
//
// Suffixes are matched from an ORDERED slice, not a map: every unit suffix ends
// in the byte suffix "B", so a map's randomized iteration order would let "B"
// win for "16MiB" (→ TrimSuffix → "16Mi" → 16 bytes) on a random fraction of
// calls. The bare "B" fallback must therefore be checked last.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3},
		{"B", 1}, // must be last: every other suffix also ends in "B"
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSuffix(s, u.suffix)
			break
		}
	}
	var n float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%g", &n); err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n) * mult, nil
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

type metrics struct {
	attempts atomic.Int64 // requests attempted (incl. transport failures) — the error% denominator
	reqs     atomic.Int64 // requests that got a response
	errs     atomic.Int64
	bytes    atomic.Int64
	perSc    map[string]*atomic.Int64
	status   map[int]*atomic.Int64

	mu         sync.Mutex
	errSamples map[string]int // capped distinct error strings → count
}

// sampleErr records a genuine error's message for the report (capped so a flood
// of unique-stream-id errors can't grow it without bound).
func (m *metrics) sampleErr(err error) {
	m.mu.Lock()
	if _, ok := m.errSamples[err.Error()]; ok || len(m.errSamples) < 24 {
		m.errSamples[err.Error()]++
	}
	m.mu.Unlock()
}

func newMetrics(scenarios []scenario) *metrics {
	m := &metrics{perSc: map[string]*atomic.Int64{}, status: map[int]*atomic.Int64{}, errSamples: map[string]int{}}
	for _, s := range scenarios {
		m.perSc[s.name] = &atomic.Int64{}
	}
	m.perSc["spike-heavy"] = &atomic.Int64{} // spike scenario is not in the weighted mix
	for _, code := range []int{200, 404, 429, 500, 503} {
		m.status[code] = &atomic.Int64{}
	}
	return m
}

// reservoir is a lock-free-per-goroutine latency sample store (one per worker),
// capped so a multi-minute run keeps memory flat. Merged for percentiles.
type reservoir struct {
	cap  int
	seen int64
	xs   []time.Duration
	rng  *rand.Rand
}

func newReservoir(capN int, rng *rand.Rand) *reservoir {
	return &reservoir{cap: capN, xs: make([]time.Duration, 0, capN), rng: rng}
}

func (r *reservoir) add(d time.Duration) {
	r.seen++
	if len(r.xs) < r.cap {
		r.xs = append(r.xs, d)
		return
	}
	if j := int(r.rng.Int63n(r.seen)); j < r.cap {
		r.xs[j] = d
	}
}

// ---------------------------------------------------------------------------
// Scenarios — weighted + conditional + nested, with per-VU variable state.
// ---------------------------------------------------------------------------

type vus struct {
	session  string
	uploaded int
	rng      *rand.Rand
}

type scenario struct {
	name   string
	weight int
	cond   func(*vus) bool // nil => always eligible
	run    func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error
}

func buildScenarios(cfg config, grpcURL string, h2cCli *hclient.Client) []scenario {
	small := int64(1 << 20) // 1 MiB round-trip inside the upload scenario
	return []scenario{
		{name: "ping", weight: 40, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return get(ctx, cli, base+"/", 200, m)
		}},
		{name: "login", weight: 8, cond: func(v *vus) bool { return v.session == "" }, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			resp, err := post(ctx, cli, base+"/login", 64, m)
			if err != nil {
				return err
			}
			defer drain(resp)
			v.session = resp.Header.Get("X-Session")
			return nil
		}},
		{name: "upload+verify", weight: 15, cond: func(v *vus) bool { return v.session != "" }, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			// Streamed large upload, then a nested download round-trip.
			resp, err := post(ctx, cli, base+"/sink", cfg.dataSize, m)
			if err != nil {
				return err
			}
			if got := resp.Header.Get("X-Body-Len"); got != fmt.Sprint(cfg.dataSize) {
				drain(resp)
				if ctx.Err() != nil {
					return ctx.Err()
				}
				m.errs.Add(1)
				return fmt.Errorf("sink len=%s want %d", got, cfg.dataSize)
			}
			drain(resp)
			v.uploaded++
			return get(ctx, cli, base+"/download?n="+fmt.Sprint(small), 200, m) // nested call
		}},
		{name: "bigparse", weight: 12, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return bigParse(ctx, cli, base+"/bigjson?n="+fmt.Sprint(cfg.jsonItems), cfg.jsonItems, m)
		}},
		{name: "stream", weight: 8, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return get(ctx, cli, base+"/stream?chunks=32", 200, m)
		}},
		{name: "gzip", weight: 8, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return gzipGet(ctx, cli, base+"/gziptext?n="+fmt.Sprint(128<<10), m)
		}},
		{name: "headers", weight: 6, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return getHeaders(ctx, cli, base+"/headers", m)
		}},
		{name: "errors", weight: 5, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			code := []int{404, 500, 503}[v.rng.Intn(3)]
			return get(ctx, cli, base+"/status?code="+fmt.Sprint(code), code, m)
		}},
		{name: "slow", weight: 4, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return get(ctx, cli, base+"/slow?ms=40", 200, m)
		}},
		// gRPC unary echo against the second (gRPC) server — exercises the whole
		// grpcserver package (length-prefixed framing + status trailers) with a
		// hand-rolled client, no grpc-go client dependency.
		{name: "grpc", weight: 7, run: func(ctx context.Context, cli *http.Client, _ string, v *vus, m *metrics) error {
			payload := []byte(fmt.Sprintf("echo-%d-%d", v.uploaded, v.rng.Int63()))
			return grpcEcho(ctx, cli, grpcURL, payload, m)
		}},
		// gRPC server-streaming: 1 request → grpcStreamCount responses.
		{name: "grpc-sstream", weight: 4, run: func(ctx context.Context, cli *http.Client, _ string, v *vus, m *metrics) error {
			return grpcServerStream(ctx, cli, grpcURL, []byte(fmt.Sprintf("ss-%d", v.rng.Int63())), m)
		}},
		// gRPC client-streaming: N requests → 1 response (the count).
		{name: "grpc-cstream", weight: 4, run: func(ctx context.Context, cli *http.Client, _ string, v *vus, m *metrics) error {
			return grpcClientStream(ctx, cli, grpcURL, randPayloads(v, 6), m)
		}},
		// gRPC bidi-streaming: N requests ↔ N echoes.
		{name: "grpc-bidi", weight: 4, run: func(ctx context.Context, cli *http.Client, _ string, v *vus, m *metrics) error {
			return grpcBidi(ctx, cli, grpcURL, randPayloads(v, 5), m)
		}},
		// h2c: cleartext HTTP/2 via the poseidon-http-client (dogfoods
		// client↔server) — a hot GET plus a streamed download.
		{name: "h2c", weight: 4, run: func(ctx context.Context, _ *http.Client, _ string, _ *vus, m *metrics) error {
			if err := h2cGet(ctx, h2cCli, "/", m); err != nil {
				return err
			}
			return h2cGet(ctx, h2cCli, "/download?n="+fmt.Sprint(64<<10), m)
		}},
		// Scrape + assert the Prometheus exposition under load, driving the
		// MetricsCollector aggregation → WritePrometheus path end-to-end.
		{name: "metrics", weight: 3, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return scrapeMetrics(ctx, cli, base+"/metrics", m)
		}},
		// Readiness probe — exercises poseidon's HealthHandler (/readyz).
		{name: "health", weight: 3, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return get(ctx, cli, base+"/readyz", 200, m)
		}},
		// Variable-driven branching: only "warm" VUs (that have uploaded a few
		// times) take the heavy adaptive path; the rest stay light.
		{name: "adaptive", weight: 6, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			if v.uploaded > 2 {
				if err := bigParse(ctx, cli, base+"/bigjson?n="+fmt.Sprint(cfg.jsonItems), cfg.jsonItems, m); err != nil {
					return err
				}
				return get(ctx, cli, base+"/download?n="+fmt.Sprint(cfg.dataSize/8+1), 200, m)
			}
			return get(ctx, cli, base+"/", 200, m)
		}},
	}
}

// heavy is the spike scenario: parse a big response + push a large body — the
// sharp burst that unblocks partway through the soak.
func heavy(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics, cfg config) error {
	if err := bigParse(ctx, cli, base+"/bigjson?n="+fmt.Sprint(cfg.jsonItems), cfg.jsonItems, m); err != nil {
		return err
	}
	resp, err := post(ctx, cli, base+"/sink", cfg.dataSize, m)
	if err != nil {
		return err
	}
	drain(resp)
	return get(ctx, cli, base+"/download?n="+fmt.Sprint(cfg.dataSize/4+1), 200, m)
}

func pickWeighted(scs []scenario, v *vus) *scenario {
	total := 0
	for i := range scs {
		if scs[i].cond == nil || scs[i].cond(v) {
			total += scs[i].weight
		}
	}
	if total == 0 {
		return &scs[0]
	}
	r := v.rng.Intn(total)
	for i := range scs {
		if scs[i].cond != nil && !scs[i].cond(v) {
			continue
		}
		if r < scs[i].weight {
			return &scs[i]
		}
		r -= scs[i].weight
	}
	return &scs[0]
}

// ---------------------------------------------------------------------------
// HTTP helpers — every response is fully drained + closed.
// ---------------------------------------------------------------------------

// do issues the request and centralises accounting. A failure is counted as an
// error ONLY if it is genuine — an in-flight request cancelled by our own
// end-of-run/end-of-spike context deadline is expected, not a server failure.
func do(ctx context.Context, cli *http.Client, req *http.Request, m *metrics) (*http.Response, error) {
	m.attempts.Add(1)
	resp, err := cli.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			m.errs.Add(1)
		}
		return nil, err
	}
	m.reqs.Add(1)
	if c, ok := m.status[resp.StatusCode]; ok {
		c.Add(1)
	}
	return resp, nil
}

func get(ctx context.Context, cli *http.Client, url string, wantCode int, m *metrics) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusTooManyRequests && wantCode != http.StatusTooManyRequests {
		drain(resp) // expected rate-limit rejection, not a genuine failure
		return nil
	}
	// The body error matters: in HTTP/2 the status line arrives before the DATA
	// frames, so a 200 header followed by a mid-body RST_STREAM/GOAWAY/reset only
	// surfaces here. Count it (unless it is our own end-of-run cancellation) so
	// the "0 errors" signal actually means large downloads completed.
	n, cerr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	m.bytes.Add(n)
	if cerr != nil {
		if ctx.Err() == nil {
			m.errs.Add(1)
		}
		return cerr
	}
	if resp.StatusCode != wantCode {
		m.errs.Add(1)
		return fmt.Errorf("GET %s: status %d want %d", url, resp.StatusCode, wantCode)
	}
	return nil
}

// post streams a `size`-byte pattern body. It sets ContentLength and GetBody so
// the transport can transparently replay the (otherwise non-rewindable) stream
// on a retryable REFUSED_STREAM — a server may refuse then reopen a stream under
// load, and without GetBody the stdlib h2 client fails such a retry outright
// ("cannot retry … after Request.Body was written").
// h2cGet issues a GET over the poseidon-http-client (cleartext HTTP/2). Because
// that client is HTTP/2-only, a successful round-trip IS an h2c round-trip —
// there is no HTTP/1.1 fallback to guard against. It replicates do()'s counters
// since it bypasses the net/http path.
func h2cGet(ctx context.Context, c *hclient.Client, path string, m *metrics) error {
	m.attempts.Add(1)
	resp := &hclient.Response{}
	if err := c.Do(ctx, hclient.GET(path), resp); err != nil {
		if ctx.Err() == nil {
			m.errs.Add(1)
		}
		return err
	}
	m.reqs.Add(1)
	m.bytes.Add(resp.BytesReceived)
	if sc, ok := m.status[resp.Status]; ok {
		sc.Add(1)
	}
	if resp.Status != 200 {
		m.errs.Add(1)
		return fmt.Errorf("h2c %s: status %d", path, resp.Status)
	}
	return nil
}

func post(ctx context.Context, cli *http.Client, url string, size int64, m *metrics) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, newPatternReader(size))
	req.ContentLength = size
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(newPatternReader(size)), nil }
	req.Header.Set("Content-Type", "application/octet-stream")
	return do(ctx, cli, req, m)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func getHeaders(ctx context.Context, cli *http.Client, url string, m *metrics) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	for i := 0; i < 30; i++ {
		req.Header.Set("X-Req-"+fmt.Sprint(i), fmt.Sprint(i))
	}
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil // expected rate-limit rejection
	}
	if resp.StatusCode != 200 {
		m.errs.Add(1)
		return fmt.Errorf("headers: %d", resp.StatusCode)
	}
	return nil
}

// gzipGet manually advertises gzip so the transport does NOT auto-decompress —
// asserting the middleware actually set Content-Encoding: gzip and the body
// round-trips through gzip.
func gzipGet(ctx context.Context, cli *http.Client, url string, m *metrics) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil // expected rate-limit rejection
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		m.errs.Add(1)
		return fmt.Errorf("gzip: Content-Encoding=%q", resp.Header.Get("Content-Encoding"))
	}
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		m.errs.Add(1)
		return err
	}
	n, err := io.Copy(io.Discard, gr)
	m.bytes.Add(n)
	if err != nil {
		if ctx.Err() == nil {
			m.errs.Add(1)
		}
		return err
	}
	return nil
}

// bigParse streams a large JSON response and counts the "items" array elements
// one at a time (json.Decoder token streaming), so parsing a multi-MiB body
// under load stays memory-bounded — the "minimal resources" requirement.
func bigParse(ctx context.Context, cli *http.Client, url string, want int64, m *metrics) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil // expected rate-limit rejection
	}
	if resp.StatusCode != 200 {
		m.errs.Add(1)
		return fmt.Errorf("bigjson: %d", resp.StatusCode)
	}
	cr := &countReader{r: resp.Body}
	dec := json.NewDecoder(cr)
	// Walk to the "items" array, then Decode each element individually.
	var count int64
	for {
		tok, err := dec.Token()
		if err != nil {
			if ctx.Err() == nil {
				m.errs.Add(1)
			}
			return err
		}
		if s, ok := tok.(string); ok && s == "items" {
			if _, err := dec.Token(); err != nil { // consume '['
				m.errs.Add(1)
				return err
			}
			for dec.More() {
				var item struct {
					ID   int64  `json:"id"`
					Name string `json:"name"`
				}
				if err := dec.Decode(&item); err != nil {
					if ctx.Err() == nil {
						m.errs.Add(1)
					}
					return err
				}
				count++
			}
			break
		}
	}
	m.bytes.Add(cr.n)
	if count != want {
		// A short count almost always means the body read was cut off by our own
		// end-of-run context cancellation (json.Decoder.More() returns false on a
		// truncated stream, masking the underlying ctx error). Only a full-context
		// short count is a genuine failure.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("bigjson: parsed %d items want %d", count, want)
	}
	return nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// grpcFrame length-prefixes a single gRPC message: a 1-byte uncompressed flag,
// a 4-byte big-endian length, then the payload.
func grpcFrame(payload []byte) []byte {
	f := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(f[1:5], uint32(len(payload)))
	copy(f[5:], payload)
	return f
}

// grpcFrames concatenates several messages into one request body. The client
// sends them all up front, then the transport's END_STREAM half-closes the
// stream — which the server reads as the client-side end (io.EOF from recv()).
func grpcFrames(payloads [][]byte) []byte {
	var b []byte
	for _, p := range payloads {
		b = append(b, grpcFrame(p)...)
	}
	return b
}

// grpcCall posts a pre-framed request body to a gRPC method and returns every
// length-prefixed response message, after verifying the grpc-status trailer. It
// speaks the wire format by hand over the shared h2 client (no grpc-go dep), so
// one code path covers unary, server-, client-, and bidi-streaming.
func grpcCall(ctx context.Context, cli *http.Client, grpcBase, method string, reqBody []byte, m *metrics) ([][]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, grpcBase+method, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	if resp.StatusCode != 200 {
		m.errs.Add(1)
		return nil, fmt.Errorf("grpc %s: HTTP status %d", method, resp.StatusCode)
	}
	var msgs [][]byte
	hdr := make([]byte, 5)
	for {
		if _, err := io.ReadFull(resp.Body, hdr); err != nil {
			if err == io.EOF {
				break // clean end of the response stream
			}
			if ctx.Err() == nil {
				m.errs.Add(1)
			}
			return msgs, err
		}
		out := make([]byte, binary.BigEndian.Uint32(hdr[1:5]))
		if _, err := io.ReadFull(resp.Body, out); err != nil {
			if ctx.Err() == nil {
				m.errs.Add(1)
			}
			return msgs, err
		}
		m.bytes.Add(int64(5 + len(out)))
		msgs = append(msgs, out)
	}
	if st := resp.Trailer.Get("grpc-status"); st != "" && st != "0" {
		m.errs.Add(1)
		return msgs, fmt.Errorf("grpc %s: grpc-status=%s", method, st)
	}
	return msgs, nil
}

// grpcEcho does one unary echo and asserts an exact round-trip.
func grpcEcho(ctx context.Context, cli *http.Client, grpcBase string, payload []byte, m *metrics) error {
	msgs, err := grpcCall(ctx, cli, grpcBase, "/loadgen.EchoService/Echo", grpcFrame(payload), m)
	if err != nil {
		return err
	}
	if len(msgs) != 1 || !bytes.Equal(msgs[0], payload) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("grpc echo: got %d msgs, exact-match=%v", len(msgs), len(msgs) == 1 && bytes.Equal(msgs[0], payload))
	}
	return nil
}

// grpcServerStream sends one request and asserts it is echoed grpcStreamCount times.
func grpcServerStream(ctx context.Context, cli *http.Client, grpcBase string, payload []byte, m *metrics) error {
	msgs, err := grpcCall(ctx, cli, grpcBase, "/loadgen.EchoService/EchoServerStream", grpcFrame(payload), m)
	if err != nil {
		return err
	}
	if len(msgs) != grpcStreamCount {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("grpc server-stream: got %d msgs want %d", len(msgs), grpcStreamCount)
	}
	for _, msg := range msgs {
		if !bytes.Equal(msg, payload) {
			m.errs.Add(1)
			return fmt.Errorf("grpc server-stream: message mismatch")
		}
	}
	return nil
}

// grpcClientStream sends len(payloads) messages and asserts the server counted them all.
func grpcClientStream(ctx context.Context, cli *http.Client, grpcBase string, payloads [][]byte, m *metrics) error {
	msgs, err := grpcCall(ctx, cli, grpcBase, "/loadgen.EchoService/EchoClientStream", grpcFrames(payloads), m)
	if err != nil {
		return err
	}
	if len(msgs) != 1 || string(msgs[0]) != fmt.Sprint(len(payloads)) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("grpc client-stream: got %d msgs want count %d", len(msgs), len(payloads))
	}
	return nil
}

// grpcBidi sends len(payloads) messages and asserts each is echoed back in order.
func grpcBidi(ctx context.Context, cli *http.Client, grpcBase string, payloads [][]byte, m *metrics) error {
	msgs, err := grpcCall(ctx, cli, grpcBase, "/loadgen.EchoService/EchoBidi", grpcFrames(payloads), m)
	if err != nil {
		return err
	}
	if len(msgs) != len(payloads) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("grpc bidi: got %d echoes want %d", len(msgs), len(payloads))
	}
	for i := range payloads {
		if !bytes.Equal(msgs[i], payloads[i]) {
			m.errs.Add(1)
			return fmt.Errorf("grpc bidi: echo %d mismatch", i)
		}
	}
	return nil
}

// randPayloads builds n distinct small messages for the streaming scenarios.
func randPayloads(v *vus, n int) [][]byte {
	p := make([][]byte, n)
	for i := range p {
		p[i] = []byte(fmt.Sprintf("msg-%d-%d", i, v.rng.Int63()))
	}
	return p
}

// scrapeMetrics GETs the Prometheus exposition and asserts it rendered a known
// counter — driving the MetricsCollector aggregation → WritePrometheus path
// end-to-end under load. The exposition is small, so reading it whole is bounded.
func scrapeMetrics(ctx context.Context, cli *http.Client, url string, m *metrics) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := do(ctx, cli, req, m)
	if err != nil {
		return err
	}
	body, cerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m.bytes.Add(int64(len(body)))
	if cerr != nil {
		if ctx.Err() == nil {
			m.errs.Add(1)
		}
		return cerr
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil // expected rate-limit rejection
	}
	if resp.StatusCode != 200 {
		m.errs.Add(1)
		return fmt.Errorf("metrics: status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "poseidon_requests_total") {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.errs.Add(1)
		return fmt.Errorf("metrics: exposition missing poseidon_requests_total (%d bytes)", len(body))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

func main() {
	cfg := parseFlags()

	fmt.Printf("loadgen: booting in-process poseidon HTTP/2 server (TLS h2)\n")
	fs, err := newFeatureServer(cfg.rateLimit, cfg.maxBody)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
	defer fs.stop()

	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     fs.clientTLS,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        512,
			MaxIdleConnsPerHost: 512,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true, // we drive gzip explicitly
		},
	}

	scs := buildScenarios(cfg, fs.grpcURL, fs.h2cClient)
	m := newMetrics(scs)

	// pprof CPU profile spans the whole run.
	if cfg.cpuProfile != "" {
		f, err := os.Create(cfg.cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cpuprofile:", err)
			os.Exit(1)
		}
		defer f.Close()
		_ = pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	rs := &resourceSampler{}
	stopSampler := rs.start(250 * time.Millisecond)

	fmt.Printf("loadgen: %d VUs, %s soak, data-size=%s, json-items=%d; spike=%s@+%s vus=%d\n",
		cfg.vus, cfg.duration, human(cfg.dataSize), cfg.jsonItems, cfg.spikeDur, cfg.spikeAfter, cfg.spikeVUs)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.duration)
	defer cancel()

	var wg sync.WaitGroup
	reservoirs := make([]*reservoir, cfg.vus)

	// Sustained VUs.
	for i := 0; i < cfg.vus; i++ {
		i := i
		v := &vus{rng: rand.New(rand.NewSource(cfg.seed + int64(i)))}
		res := newReservoir(65536, v.rng)
		reservoirs[i] = res
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				s := pickWeighted(scs, v)
				t0 := time.Now()
				if err := s.run(ctx, cli, fs.baseURL, v, m); err == nil {
					res.add(time.Since(t0))
				} else if ctx.Err() == nil {
					m.sampleErr(err)
				}
				m.perSc[s.name].Add(1)
			}
		}()
	}

	// Spike: unblocks after spikeAfter, then blasts `heavy` for spikeDur. Each
	// spike VU records into its OWN reservoir (reservoir.add is not concurrency
	// safe) so the burst's own tail latency is visible, reported on a separate
	// line rather than diluted into the sustained single-request distribution.
	spikeReservoirs := make([]*reservoir, cfg.spikeVUs)
	if cfg.spikeAfter > 0 && cfg.spikeDur > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-time.After(cfg.spikeAfter):
			case <-ctx.Done():
				return
			}
			fmt.Printf("loadgen: >>> SPIKE unblocked at +%s: %d VUs bursting for %s\n", time.Since(start).Round(time.Millisecond), cfg.spikeVUs, cfg.spikeDur)
			spikeCtx, spikeCancel := context.WithTimeout(ctx, cfg.spikeDur)
			defer spikeCancel()
			var sw sync.WaitGroup
			for j := 0; j < cfg.spikeVUs; j++ {
				j := j
				sw.Add(1)
				go func() {
					defer sw.Done()
					v := &vus{rng: rand.New(rand.NewSource(cfg.seed*1000 + int64(j)))}
					sr := newReservoir(4096, v.rng)
					spikeReservoirs[j] = sr
					for spikeCtx.Err() == nil {
						t0 := time.Now()
						err := heavy(spikeCtx, cli, fs.baseURL, v, m, cfg)
						if err == nil {
							sr.add(time.Since(t0))
						} else if spikeCtx.Err() == nil {
							m.sampleErr(err)
						}
						m.perSc["spike-heavy"].Add(1)
					}
				}()
			}
			sw.Wait()
			fmt.Printf("loadgen: <<< spike ended at +%s\n", time.Since(start).Round(time.Millisecond))
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)
	stopSampler()

	if cfg.memProfile != "" {
		f, err := os.Create(cfg.memProfile)
		if err == nil {
			runtime.GC()
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
		}
	}

	report(cfg, m, reservoirs, spikeReservoirs, rs, elapsed, fs)
}

// ---------------------------------------------------------------------------
// Resource sampler
// ---------------------------------------------------------------------------

type resourceSampler struct {
	maxHeap    uint64
	sumHeap    uint64
	samples    int64
	maxGor     int
	startNumGC uint32
	endNumGC   uint32
}

func (s *resourceSampler) start(every time.Duration) func() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.startNumGC = ms.NumGC
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > s.maxHeap {
					s.maxHeap = m.HeapAlloc
				}
				s.sumHeap += m.HeapAlloc
				s.samples++
				if g := runtime.NumGoroutine(); g > s.maxGor {
					s.maxGor = g
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		s.endNumGC = ms.NumGC
	}
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

func report(cfg config, m *metrics, reservoirs, spikeReservoirs []*reservoir, rs *resourceSampler, elapsed time.Duration, fs *featureServer) {
	all := mergeReservoirs(reservoirs)
	spikeAll := mergeReservoirs(spikeReservoirs)

	reqs := m.reqs.Load()
	attempts := m.attempts.Load()
	fmt.Printf("\n================ loadgen report ================\n")
	fmt.Printf("elapsed        %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("requests       %d  (%.0f req/s)\n", reqs, float64(reqs)/elapsed.Seconds())
	// error%% is over attempts (which includes transport failures that never
	// produced a response), so the ratio is a true fraction and cannot exceed 100%%.
	fmt.Printf("errors         %d  (%.3f%% of %d attempts)\n", m.errs.Load(), 100*float64(m.errs.Load())/float64(max64(attempts, 1)), attempts)
	fmt.Printf("body bytes     %s  (%.1f MiB/s)\n", human(m.bytes.Load()), float64(m.bytes.Load())/(1<<20)/elapsed.Seconds())
	fmt.Printf("latency        p50=%s p90=%s p95=%s p99=%s max=%s  (sustained, over %d samples)\n",
		pct(all, 0.50), pct(all, 0.90), pct(all, 0.95), pct(all, 0.99), pct(all, 1.0), len(all))
	if len(spikeAll) > 0 {
		fmt.Printf("spike latency  p50=%s p90=%s p95=%s p99=%s max=%s  (burst `heavy`, over %d samples)\n",
			pct(spikeAll, 0.50), pct(spikeAll, 0.90), pct(spikeAll, 0.95), pct(spikeAll, 0.99), pct(spikeAll, 1.0), len(spikeAll))
	}

	fmt.Printf("\nper-scenario iterations:\n")
	names := make([]string, 0, len(m.perSc))
	for n := range m.perSc {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("  %-16s %d\n", n, m.perSc[n].Load())
	}

	fmt.Printf("\nstatus codes seen: ")
	for _, code := range []int{200, 404, 429, 500, 503} {
		fmt.Printf("%d=%d ", code, m.status[code].Load())
	}
	fmt.Println()

	if len(m.errSamples) > 0 {
		type es struct {
			msg string
			n   int
		}
		list := make([]es, 0, len(m.errSamples))
		for k, v := range m.errSamples {
			list = append(list, es{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		fmt.Printf("\nerror samples (%d distinct; genuine failures only, ctx-cancellation excluded):\n", len(list))
		for i, e := range list {
			if i >= 8 {
				fmt.Printf("  … and %d more distinct\n", len(list)-8)
				break
			}
			fmt.Printf("  %5d× %s\n", e.n, e.msg)
		}
	}

	avgHeap := uint64(0)
	if rs.samples > 0 {
		avgHeap = rs.sumHeap / uint64(rs.samples)
	}
	fmt.Printf("\nresource footprint (server + client in one process):\n")
	fmt.Printf("  heap alloc     max=%s  avg=%s\n", human(int64(rs.maxHeap)), human(int64(avgHeap)))
	fmt.Printf("  GC cycles      %d during run\n", rs.endNumGC-rs.startNumGC)
	fmt.Printf("  goroutines     max=%d\n", rs.maxGor)
	fmt.Printf("  tracing spans  %d (Tracing middleware exercised)\n", fs.tracer.spans.Load())
	// Render the server-side Prometheus exposition so a broken WritePrometheus /
	// counter wiring would surface here (the `metrics` scenario also scrapes it
	// under load); the printed report's own numbers come from the client atomics.
	fmt.Printf("  /metrics expo  %d bytes rendered (scraped + asserted under load)\n", len(fs.metrics.WritePrometheus()))
	if cfg.cpuProfile != "" {
		fmt.Printf("\ncpu profile -> %s   (go tool pprof %s)\n", cfg.cpuProfile, cfg.cpuProfile)
	}
	if cfg.memProfile != "" {
		fmt.Printf("heap profile -> %s   (go tool pprof %s)\n", cfg.memProfile, cfg.memProfile)
	}
	fmt.Printf("================================================\n")
}

// mergeReservoirs concatenates and sorts every reservoir's samples for
// percentile extraction. Called after the WaitGroup barrier, so no locking.
func mergeReservoirs(reservoirs []*reservoir) []time.Duration {
	var all []time.Duration
	for _, r := range reservoirs {
		if r != nil {
			all = append(all, r.xs...)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)-1))
	return sorted[i].Round(time.Microsecond)
}

func human(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
