package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestServer_TransportStats verifies that Server.TransportStats aggregates the
// per-connection ConnStats while a connection is live, and that the cumulative
// counters survive the connection closing (monotonic), with ActiveConns falling
// back to zero.
func TestServer_TransportStats(t *testing.T) {
	srv, err := NewServer(Options{
		Handler: HandlerFunc(func(_ context.Context, _ *Request, w ResponseWriter) error {
			return w.WriteHeaders(200, nil)
		}),
		H2C: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fr := frame.NewFramer(c, c)
	if err := performClientHandshake(c, fr); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
	})
	if err := fr.WriteHeaders(frame.WriteHeadersParams{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if _, err := readResponseHeaders(fr); err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Live aggregation: counters reflect the request once the server has
	// processed its frames. Poll briefly to avoid racing the read loop.
	var live TransportStats
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		live = srv.TransportStats()
		if live.ActiveConns >= 1 && live.StreamsAccepted >= 1 &&
			live.BytesReceived > 0 && live.BytesSent > 0 &&
			live.FramesReceived > 0 && live.FramesSent > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if live.ActiveConns < 1 {
		t.Errorf("ActiveConns = %d, want >= 1", live.ActiveConns)
	}
	if live.StreamsAccepted < 1 {
		t.Errorf("StreamsAccepted = %d, want >= 1", live.StreamsAccepted)
	}
	if live.BytesReceived == 0 || live.BytesSent == 0 {
		t.Errorf("bytes sent/received = %d/%d, want both > 0", live.BytesSent, live.BytesReceived)
	}
	if live.FramesReceived == 0 || live.FramesSent == 0 {
		t.Errorf("frames sent/received = %d/%d, want both > 0", live.FramesSent, live.FramesReceived)
	}

	// Close the server while the connection is still live: it reaps every
	// connection, folding its final counters into the closed totals. ActiveConns
	// must drop to 0, but the cumulative counters must NOT decrease (monotonic).
	if err := srv.Close(); err != nil {
		t.Fatalf("srv.Close: %v", err)
	}
	after := srv.TransportStats()
	if after.ActiveConns != 0 {
		t.Errorf("ActiveConns after close = %d, want 0", after.ActiveConns)
	}
	if after.StreamsAccepted < live.StreamsAccepted {
		t.Errorf("StreamsAccepted dropped %d -> %d after close (counter must be monotonic)",
			live.StreamsAccepted, after.StreamsAccepted)
	}
	if after.BytesReceived < live.BytesReceived {
		t.Errorf("BytesReceived dropped %d -> %d after close (counter must be monotonic)",
			live.BytesReceived, after.BytesReceived)
	}
	if after.FramesReceived < live.FramesReceived {
		t.Errorf("FramesReceived dropped %d -> %d after close (counter must be monotonic)",
			live.FramesReceived, after.FramesReceived)
	}
	// Close sends a GOAWAY to each live connection; that frame must be accounted
	// for in the GOAWAY counter (regression guard for the Close path).
	if after.GoAways < 1 {
		t.Errorf("GoAways after server Close = %d, want >= 1 (Close emits an accounted GOAWAY)", after.GoAways)
	}
}
