package middleware

import (
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// A registered transport source must surface conn/stream/byte/frame and
// rapid-reset/GOAWAY metrics in the Prometheus exposition; with no source
// registered, none of those lines appear.
func TestMetricsCollector_TransportExposition(t *testing.T) {
	t.Parallel()

	mc := NewMetricsCollector()

	// No source → no transport lines.
	if got := mc.WritePrometheus(); strings.Contains(got, "poseidon_connections_active") {
		t.Fatal("transport metrics emitted without a source registered")
	}

	mc.SetTransportSource(func() server.TransportStats {
		return server.TransportStats{
			ActiveConns:     3,
			BytesSent:       1000,
			BytesReceived:   2000,
			FramesSent:      40,
			FramesReceived:  50,
			StreamsAccepted: 7,
			RapidResets:     2,
			GoAways:         1,
		}
	})

	out := mc.WritePrometheus()
	for _, want := range []string{
		"# TYPE poseidon_connections_active gauge",
		"poseidon_connections_active 3",
		"# TYPE poseidon_bytes_sent_total counter",
		"poseidon_bytes_sent_total 1000",
		"poseidon_bytes_received_total 2000",
		"poseidon_frames_sent_total 40",
		"poseidon_frames_received_total 50",
		"poseidon_streams_accepted_total 7",
		"poseidon_rapid_resets_total 2",
		"poseidon_goaways_sent_total 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("WritePrometheus missing %q\n--- output ---\n%s", want, out)
		}
	}

	// Disabling the source removes the lines again.
	mc.SetTransportSource(nil)
	if strings.Contains(mc.WritePrometheus(), "poseidon_connections_active") {
		t.Fatal("transport metrics still emitted after SetTransportSource(nil)")
	}
}
