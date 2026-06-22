package middleware

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TotalDuration must return the accumulated duration for a known method+path
// and zero for an unrecorded one.
func TestMetricsCollector_TotalDuration(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mc.getOrCreateDuration(durationKey("GET", "/d")).Add(int64(2 * time.Second))

	if got := mc.TotalDuration("GET", "/d"); got != 2*time.Second {
		t.Fatalf("TotalDuration = %v, want 2s", got)
	}
	if got := mc.TotalDuration("GET", "/missing"); got != 0 {
		t.Fatalf("TotalDuration(missing) = %v, want 0", got)
	}
}

// getOrCreateBytes must return the same counter for repeated keys (create then
// hit path).
func TestMetricsCollector_GetOrCreateBytes_HitPath(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	key := durationKey("POST", "/r")

	first := mc.getOrCreateBytes(mc.reqBytes, key)
	first.Add(123)
	second := mc.getOrCreateBytes(mc.reqBytes, key) // hit (already-exists) path

	if first != second {
		t.Fatal("getOrCreateBytes returned different counters for the same key")
	}
	if got := second.Load(); got != 123 {
		t.Fatalf("reqBytes = %d, want 123", got)
	}
}

// TotalRequests must return zero for a method+path+status that was never seen.
func TestMetricsCollector_TotalRequests_Missing(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	if got := mc.TotalRequests("GET", "/never", 200); got != 0 {
		t.Fatalf("TotalRequests(missing) = %d, want 0", got)
	}
}

// metricsRespCollector captures the response status and body of a single
// stream. It embeds noopFrameHandler (defined in middleware_test.go) and
// overrides only OnHeaders/OnData.
type metricsRespCollector struct {
	noopFrameHandler
	status     int
	body       []byte
	gotHeaders bool
}

func (c *metricsRespCollector) OnHeaders(_ frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	c.gotHeaders = true
	dec := hpack.NewDecoder()
	return dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		if string(f.Name) == ":status" {
			n := 0
			for _, b := range f.Value {
				if b < '0' || b > '9' {
					break
				}
				n = n*10 + int(b-'0')
			}
			c.status = n
		}
		return nil
	})
}

func (c *metricsRespCollector) OnData(_ frame.FrameHeader, data []byte, _ uint8) error {
	c.body = append(c.body, data...)
	return nil
}

// MetricsHandler must serve the Prometheus exposition format end-to-end through
// the real server (covers WritePrometheus -> WriteHeaders -> WriteData).
func TestMetricsCollector_MetricsHandler_ServesPrometheus(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()
	mc.getOrCreateCounter(counterKey("GET", "/x", 200)).Add(7)

	ln := startTestServer(t, mc.MetricsHandler())

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	fr := frame.NewFramer(c, c)
	if _, err := c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(frame.SettingsParams{N: 0}); err != nil {
		t.Fatal(err)
	}

	noop := &noopFrameHandler{}
	rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = fr.ReadFrame(rctx, noop) // server SETTINGS
	_, _ = fr.ReadFrame(rctx, noop) // server SETTINGS ACK
	cancel()
	if err := fr.WriteSettingsAck(); err != nil {
		t.Fatal(err)
	}

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/metrics")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatal(err)
	}

	col := &metricsRespCollector{}
	rctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	for range 8 {
		if _, err := fr.ReadFrame(rctx2, col); err != nil {
			break
		}
		if col.gotHeaders && len(col.body) > 0 {
			break
		}
	}

	if col.status != 200 {
		t.Fatalf("status = %d, want 200", col.status)
	}
	if !strings.Contains(string(col.body), "poseidon_requests_total") {
		t.Fatalf("response body missing Prometheus metrics, got: %q", col.body)
	}
}
