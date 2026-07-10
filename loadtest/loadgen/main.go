package main

import (
	"compress/gzip"
	"context"
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
	flag.Int64Var(&c.jsonItems, "json-items", 30000, "items in the big-JSON response (~>3MiB) for the large-response parse scenario")
	flag.Float64Var(&c.rateLimit, "rate-limit", 100000, "global token-bucket rate (req/s); the soak stays under it, the spike exceeds it to exercise 429s")
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
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for suffix, m := range map[string]int64{
		"GiB": 1 << 30, "MiB": 1 << 20, "KiB": 1 << 10,
		"GB": 1e9, "MB": 1e6, "KB": 1e3, "B": 1,
	} {
		if strings.HasSuffix(s, suffix) {
			mult = m
			s = strings.TrimSuffix(s, suffix)
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
	reqs   atomic.Int64
	errs   atomic.Int64
	bytes  atomic.Int64
	perSc  map[string]*atomic.Int64
	status map[int]*atomic.Int64

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

func buildScenarios(cfg config) []scenario {
	small := int64(1 << 20) // 1 MiB round-trip inside the upload scenario
	return []scenario{
		{name: "ping", weight: 40, run: func(ctx context.Context, cli *http.Client, base string, _ *vus, m *metrics) error {
			return get(ctx, cli, base+"/", 200, m)
		}},
		{name: "login", weight: 8, cond: func(v *vus) bool { return v.session == "" }, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			resp, err := post(ctx, cli, base+"/login", newPatternReader(64), m)
			if err != nil {
				return err
			}
			defer drain(resp)
			v.session = resp.Header.Get("X-Session")
			return nil
		}},
		{name: "upload+verify", weight: 15, cond: func(v *vus) bool { return v.session != "" }, run: func(ctx context.Context, cli *http.Client, base string, v *vus, m *metrics) error {
			// Streamed large upload, then a nested download round-trip.
			resp, err := post(ctx, cli, base+"/sink", newPatternReader(cfg.dataSize), m)
			if err != nil {
				return err
			}
			if got := resp.Header.Get("X-Body-Len"); got != fmt.Sprint(cfg.dataSize) {
				drain(resp)
				if ctx.Err() != nil {
					return ctx.Err()
				}
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
	resp, err := post(ctx, cli, base+"/sink", newPatternReader(cfg.dataSize), m)
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
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	m.bytes.Add(n)
	if resp.StatusCode != wantCode {
		m.errs.Add(1)
		return fmt.Errorf("GET %s: status %d want %d", url, resp.StatusCode, wantCode)
	}
	return nil
}

func post(ctx context.Context, cli *http.Client, url string, body io.Reader, m *metrics) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
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

	scs := buildScenarios(cfg)
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

	// Spike: unblocks after spikeAfter, then blasts `heavy` for spikeDur.
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
					for spikeCtx.Err() == nil {
						_ = heavy(spikeCtx, cli, fs.baseURL, v, m, cfg)
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

	report(cfg, m, reservoirs, rs, elapsed, fs)
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

func report(cfg config, m *metrics, reservoirs []*reservoir, rs *resourceSampler, elapsed time.Duration, fs *featureServer) {
	var all []time.Duration
	for _, r := range reservoirs {
		if r != nil {
			all = append(all, r.xs...)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	reqs := m.reqs.Load()
	fmt.Printf("\n================ loadgen report ================\n")
	fmt.Printf("elapsed        %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("requests       %d  (%.0f req/s)\n", reqs, float64(reqs)/elapsed.Seconds())
	fmt.Printf("errors         %d  (%.3f%%)\n", m.errs.Load(), 100*float64(m.errs.Load())/float64(max64(reqs, 1)))
	fmt.Printf("body bytes     %s  (%.1f MiB/s)\n", human(m.bytes.Load()), float64(m.bytes.Load())/(1<<20)/elapsed.Seconds())
	fmt.Printf("latency        p50=%s p90=%s p95=%s p99=%s max=%s  (over %d samples)\n",
		pct(all, 0.50), pct(all, 0.90), pct(all, 0.95), pct(all, 0.99), pct(all, 1.0), len(all))

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
	ts := fs.metrics // transport metrics source is wired; the /metrics text is the authoritative counter set
	_ = ts
	if cfg.cpuProfile != "" {
		fmt.Printf("\ncpu profile -> %s   (go tool pprof %s)\n", cfg.cpuProfile, cfg.cpuProfile)
	}
	if cfg.memProfile != "" {
		fmt.Printf("heap profile -> %s   (go tool pprof %s)\n", cfg.memProfile, cfg.memProfile)
	}
	fmt.Printf("================================================\n")
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
