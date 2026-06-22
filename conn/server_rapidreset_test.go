package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// rapidResetReq opens stream `streamID` with a HEADERS frame (not
// END_STREAM) and immediately follows with RST_STREAM(CANCEL),
// modelling the CVE-2023-44487 attack pattern.
func rapidResetReq(t *testing.T, cliFr *frame.Framer, streamID uint32, code frame.ErrCode) {
	t.Helper()
	enc := hpack.NewEncoder()
	block := enc.EncodeBlock(nil, []hpack.HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("example.test")},
		{Name: []byte(":path"), Value: []byte("/flood")},
	})
	// Errors are expected once the server trips and stops reading the
	// unbuffered pipe; ignore them (do NOT t.Logf — this runs in a writer
	// goroutine that may outlive the test).
	if err := cliFr.WriteHeaders(frame.WriteHeadersParams{
		StreamID:      streamID,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     false,
	}); err != nil {
		return
	}
	_ = cliFr.WriteRSTStream(streamID, code)
}

// TestServerConn_RapidReset_TripsGoAway verifies that a flood of
// open-then-RST_STREAM streams (CVE-2023-44487) causes the server to
// emit GOAWAY(ENHANCE_YOUR_CALM) and tear down the connection once the
// per-connection budget is exceeded.
func TestServerConn_RapidReset_TripsGoAway(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	const maxConcurrent = 100
	// Budget defaults to MaxConcurrentStreams*4 (= 400). Send well past it.
	const floods = 600

	gotGoAway := make(chan goAwayCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Read server frames in the background; capture GOAWAY.
			readDone := make(chan struct{})
			gc := &goAwayCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), gc); err != nil {
						return
					}
					if gc.code != 0 {
						select {
						case gotGoAway <- *gc:
						default:
						}
						return
					}
				}
			}()

			// Write the flood in its own goroutine: net.Pipe is unbuffered,
			// so once the server trips and stops reading, the write blocks.
			// We must not join on it before asserting GOAWAY.
			go func() {
				var sid uint32 = 1
				for range floods {
					rapidResetReq(t, cliFr, sid, frame.ErrCodeCancel)
					sid += 2
				}
			}()

			// Keep the client side alive until the reader observes GOAWAY
			// (or times out), so the server can complete its teardown.
			select {
			case <-readDone:
			case <-time.After(3 * time.Second):
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: maxConcurrent},
	})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case gc := <-gotGoAway:
		if gc.code != frame.ErrCodeEnhanceYourCalm {
			t.Fatalf("GOAWAY code = %v, want ENHANCE_YOUR_CALM (0xB)", gc.code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server did not emit GOAWAY(ENHANCE_YOUR_CALM) under rapid-reset flood")
	}
	<-done

	// Stats must surface the rapid-reset and GOAWAY activity for metrics.
	st := sc.Stats()
	if st.RapidResets == 0 {
		t.Errorf("Stats.RapidResets = 0, want > 0 after a rapid-reset flood")
	}
	if !st.GoAwaySent {
		t.Error("Stats.GoAwaySent = false, want true after the server emitted GOAWAY")
	}
}

// TestServerConn_RapidReset_NoFalsePositive verifies that a small number
// of legitimate client cancellations does NOT trip the mitigation.
func TestServerConn_RapidReset_NoFalsePositive(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	const maxConcurrent = 100
	// A handful of legitimate cancellations — far below the budget.
	const cancels = 10

	sawGoAway := make(chan goAwayCapture, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			readDone := make(chan struct{})
			gc := &goAwayCapture{}
			go func() {
				defer close(readDone)
				for {
					if _, err := cliFr.ReadFrame(context.Background(), gc); err != nil {
						return
					}
					if gc.code != 0 && gc.code != frame.ErrCodeNoError {
						select {
						case sawGoAway <- *gc:
						default:
						}
					}
				}
			}()

			var sid uint32 = 1
			for range cancels {
				rapidResetReq(t, cliFr, sid, frame.ErrCodeCancel)
				sid += 2
				time.Sleep(5 * time.Millisecond)
			}
			// Give the server time to (not) react.
			time.Sleep(300 * time.Millisecond)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: maxConcurrent},
	})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	select {
	case gc := <-sawGoAway:
		if gc.code == frame.ErrCodeEnhanceYourCalm {
			t.Fatalf("false positive: %d legitimate cancels tripped ENHANCE_YOUR_CALM mitigation", cancels)
		}
	case <-time.After(700 * time.Millisecond):
		// Expected: no mitigation GOAWAY.
	}

	if !sc.IsAlive() {
		t.Fatal("connection was torn down by a small number of legitimate cancellations")
	}
	<-done
}

// TestServerConn_RapidReset_Disabled verifies that a negative
// MaxRapidResets disables the mitigation entirely.
func TestServerConn_RapidReset_Disabled(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			go func() {
				gc := &goAwayCapture{}
				for {
					if _, err := cliFr.ReadFrame(context.Background(), gc); err != nil {
						return
					}
				}
			}()
			var sid uint32 = 1
			for range 500 {
				rapidResetReq(t, cliFr, sid, frame.ErrCodeCancel)
				sid += 2
			}
			time.Sleep(200 * time.Millisecond)
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{
		AdvertisedSettings: AdvertisedSettings{MaxConcurrentStreams: 100},
		MaxRapidResets:     -1, // disabled
	})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	time.Sleep(300 * time.Millisecond)
	if !sc.IsAlive() {
		t.Fatal("connection torn down despite mitigation being disabled")
	}
	<-done
}
