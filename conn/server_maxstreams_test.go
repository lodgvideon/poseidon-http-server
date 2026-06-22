package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// TestServerConn_MaxConcurrentStreams_RefusesOverLimit verifies RFC 9113
// §5.1.2: once a client has opened SETTINGS_MAX_CONCURRENT_STREAMS streams, the
// next one is refused with RST_STREAM(REFUSED_STREAM) rather than registered
// (which would let a peer exhaust goroutines/memory with unbounded streams).
func TestServerConn_MaxConcurrentStreams_RefusesOverLimit(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	gotRST := make(chan frame.ErrCode, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			rc := &rstCapture{}
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), rc); err != nil {
						return
					}
					if rc.code != 0 {
						select {
						case gotRST <- rc.code:
						default:
						}
						return
					}
				}
			}()

			openStream := func(id uint32) {
				enc := hpack.NewEncoder()
				block := enc.EncodeBlock(nil, []hpack.HeaderField{
					{Name: []byte(":method"), Value: []byte("POST")},
					{Name: []byte(":scheme"), Value: []byte("https")},
					{Name: []byte(":path"), Value: []byte("/")},
				})
				// No END_STREAM: the stream stays open and counts toward the limit.
				_ = cliFr.WriteHeaders(frame.WriteHeadersParams{
					StreamID:      id,
					BlockFragment: block,
					EndHeaders:    true,
					EndStream:     false,
				})
			}

			// Limit is 2: streams 1 and 3 fit, stream 5 must be refused.
			openStream(1)
			openStream(3)
			openStream(5)

			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: 2},
	}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case code := <-gotRST:
		if code != frame.ErrCodeRefusedStream {
			t.Fatalf("RST code = %v, want REFUSED_STREAM (0x7)", code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server did not RST_STREAM(REFUSED_STREAM) the stream over MaxConcurrentStreams")
	}
	<-done
}
