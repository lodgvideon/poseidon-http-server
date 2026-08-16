package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// Three defects found by the architecture review of 8 Aug 2026. All three are
// the same shape: a question about stream state answered by re-deriving it at
// the call site instead of asking one place.

// TestConformance_RFC9113_Sec68_LastStreamIDNamesAPeerStream pins
// rfc9113.txt:2013 — the GOAWAY last-stream-id is "the highest-numbered stream
// identifier for which the sender of the GOAWAY frame might have taken some
// action on or might yet take action on", and §5.1.1 reserves even identifiers
// for the server. A server-initiated stream can therefore never be the answer.
//
// lastPeerStreamID scanned every key in the streams map with no parity filter,
// while both counting loops beside it filter. A live push stream raised the
// reported identifier above the highest client stream, so a client concluded
// that requests between the two were processed and stopped retrying them.
func TestConformance_RFC9113_Sec68_LastStreamIDNamesAPeerStream(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	seen := &goAwayLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			for {
				if _, err := cliFr.ReadFrame(context.Background(), seen); err != nil {
					return
				}
			}
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	// Reserve several push streams and leave them open, so the highest key in
	// the streams map is even and far above the only client stream (1).
	for range 3 {
		if _, perr := stream.Push(ctx, goodHeaders("/asset")); perr != nil {
			t.Fatalf("Push: %v", perr)
		}
	}
	_ = sc.Close()
	<-done

	if len(seen.ids) == 0 {
		t.Fatal("no GOAWAY observed")
	}
	last := seen.ids[len(seen.ids)-1]
	if last%2 == 0 {
		t.Errorf("GOAWAY last-stream-id = %d, an even (server-initiated) identifier; §5.1.1 "+
			"reserves those for the server, so it can never name the last PEER stream. "+
			"A client reads this as 'everything up to %d was processed' and stops retrying "+
			"requests the server never saw.", last, last)
	}
	if last != 1 {
		t.Errorf("GOAWAY last-stream-id = %d, want 1 (the only client stream)", last)
	}
}

// TestRegression_ResetReleasesTheStreamEvenWhenTheWriteFails pins the contract
// serverConnOps states for writeServerRSTStream — "It calls markStreamDone
// itself" — on the paths where it did not.
//
// The function set ss.closed and then returned early if the connection was
// already closed or the frame write failed, skipping markStreamDone. The stream
// stayed in the registry with its context uncancelled: the handler goroutine was
// never released, ActiveStreams() over-reported, and because push concurrency is
// counted by scanning the map, the peer's push allowance leaked. All seven
// callers discard the error, so nothing downstream could compensate.
//
// HOW THE WRITE IS BROKEN, and why not by closing the client end (issue #115).
// Closing the client end does break the write, but it also ends the server's
// reader goroutine, and that goroutine's teardown drains the whole stream table
// on its own — releasing this stream without cancelling its context, because it
// signals streams over their event channel instead. Two paths could therefore
// release the entry, and whichever reached the table first decided what the test
// saw. When teardown won, ActiveStreams was 0 (drained) and the context was
// still live (never cancelled), which reads exactly like the defect this test
// exists to catch: 65 of 3600 attempts under -race on a loaded host, every one
// of them expiring at exactly the 1s budget the check used to carry, none of
// them with a DATA RACE to show for it. Failing the write alone leaves the
// reader goroutine running and exactly one path able to release this stream —
// the one under test.
func TestRegression_ResetReleasesTheStreamEvenWhenTheWriteFails(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	failing := &failWritesConn{Conn: srv}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Closed when the assertions are done. The client then holds the connection
	// open for exactly as long as the test needs it, instead of for a guessed
	// number of seconds that can expire mid-assertion.
	held := make(chan struct{})
	defer close(held)

	go func() {
		pipeClient(t, cli, func(cliFr *frame.Framer) {
			// Keep draining, so no server write can block on an unread pipe.
			go func() {
				for {
					if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
						return
					}
				}
			}()
			sendReq(t, cliFr, 1, goodHeaders("/"), false)
			<-held
		})
	}()

	sc, err := NewServerConn(ctx, failing, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if got := sc.ActiveStreams(); got != 1 {
		t.Fatalf("ActiveStreams before reset = %d, want 1", got)
	}

	// From here every frame this server writes fails, and nothing else about the
	// connection changes. This is the ordinary case of a client that vanished,
	// narrowed to the half of it this function has to survive.
	failing.fail.Store(true)

	rstErr := sc.writeServerRSTStream(stream, frame.ErrCodeProtocolError)
	// Pin the arrangement before reading anything into the result: a run in which
	// the write succeeded, or which took the already-closed branch instead, never
	// exercised the failed-write path and must not be allowed to pass for it.
	if rstErr == nil {
		t.Fatal("writeServerRSTStream returned nil: the RST_STREAM write succeeded " +
			"although every write was arranged to fail, so this run never reached " +
			"the path under test")
	}
	if errors.Is(rstErr, ErrConnClosed) {
		t.Fatalf("writeServerRSTStream returned %v: it took the already-closed early "+
			"return, not the failed-write path this test exists for", rstErr)
	}

	if got := sc.ActiveStreams(); got != 0 {
		t.Errorf("ActiveStreams after a failed reset = %d, want 0: the stream was marked "+
			"closed but never released, so its handler goroutine is stranded and the "+
			"registry keeps counting it", got)
	}
	// No budget, because there is nothing to wait for. writeServerRSTStream is
	// documented to call markStreamDone itself, markStreamDone cancels the stream
	// context before it returns, and that call has returned — so the context is
	// cancelled by the time this line runs, or it never will be. A wall-clock
	// budget here could only be a guess about another goroutine, which is what
	// #115 turned out to be.
	select {
	case <-stream.Context().Done():
	default:
		t.Error("stream context still live on return from writeServerRSTStream: the reset " +
			"marked the stream closed but never released it, so its handler goroutine is " +
			"stranded with a context nothing will cancel until the connection ends")
	}
}

// TestConformance_RFC9113_Sec92_HandshakeSettingsApplyToPipelinedStreams pins
// rfc9113.txt:1830 — SETTINGS "applies to the connection, not a single stream"
// — for the stream that arrives inside the handshake window.
//
// A client is allowed to send its preface, SETTINGS and its first HEADERS in one
// TCP segment, and browsers and curl do. The server forwards that HEADERS to the
// real handler during the handshake (deliberately — handshake_regression_test.go
// exists for it), so the stream registers and seeds its send window from
// peerSettings. But peerSettings was published only after the handshake
// returned, and the retroactive INITIAL_WINDOW_SIZE delta never covered it — so
// the stream stayed pinned at the 65 535-byte protocol default however large a
// window the client had advertised.
func TestConformance_RFC9113_Sec92_HandshakeSettingsApplyToPipelinedStreams(t *testing.T) {
	const advertised = 1 << 20

	cli, srv := net.Pipe()
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		// Preface + SETTINGS + HEADERS, written as one batch, as a real client does.
		if _, err := cli.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
			return
		}
		cliFr := frame.NewFramer(cli, cli)
		var p frame.SettingsParams
		p.Pairs[0] = frame.SettingPair{ID: frame.SettingInitialWindowSize, Value: advertised}
		p.N = 1
		go func() {
			_ = cliFr.WriteSettings(p)
			block := hpack.NewEncoder().EncodeBlock(nil, goodHeaders("/"))
			_ = cliFr.WriteHeaders(frame.WriteHeadersParams{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
			})
			_ = cliFr.WriteSettingsAck()
		}()
		for {
			if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
				return
			}
		}
	}()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	stream, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	stream.mu.Lock()
	got := stream.sendWindow
	stream.mu.Unlock()

	if got != advertised {
		t.Errorf("send window for a stream opened in the handshake window = %d, want %d: "+
			"the client's SETTINGS_INITIAL_WINDOW_SIZE never reached it, so every response "+
			"on this stream is throttled to the protocol default", got, advertised)
	}
}

// TestRegression_CodecRecoveryResetReleasesTheStream guards the sibling of the
// reset-release fix. The reader loop recovers two codec-detected stream errors
// (§6.3 a wrong-length PRIORITY, §6.9.1 a zero-increment WINDOW_UPDATE) by
// resetting the stream through writeRSTStreamID — which set ss.closed and never
// deregistered, leaving the stream in the registry with its context uncancelled.
//
// Two client frames reach it, and nothing reclaims the entry: ServerStream.Close
// short-circuits on the ss.closed it just set, the rapid-reset budget does not
// apply (the server sent the reset), and ActiveStreams never returns to zero, so
// IdleTimeout can no longer reap the connection.
func TestRegression_CodecRecoveryResetReleasesTheStream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"wrong_length_PRIORITY", rawFrame(frame.FramePriority, 0, 1, []byte{0, 0, 0, 0})},
		{"zero_increment_WINDOW_UPDATE", rawFrame(frame.FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			sent := make(chan struct{})
			go func() {
				pipeClient(t, cli, func(cliFr *frame.Framer) {
					go func() {
						for {
							if _, err := cliFr.ReadFrame(context.Background(), &fieldRSTCapture{}); err != nil {
								return
							}
						}
					}()
					sendReq(t, cliFr, 1, goodHeaders("/"), false) // stays open
					_, _ = cli.Write(tc.frame)
					close(sent)
					time.Sleep(500 * time.Millisecond)
				})
			}()

			sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
			if err != nil {
				t.Fatalf("NewServerConn: %v", err)
			}
			defer sc.Close()

			stream, err := sc.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("AcceptStream: %v", err)
			}
			<-sent

			deadline := time.Now().Add(2 * time.Second)
			for sc.ActiveStreams() != 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := sc.ActiveStreams(); got != 0 {
				t.Errorf("ActiveStreams after the recovery reset = %d, want 0: the stream was "+
					"closed for writing but never released, so its handler goroutine is "+
					"stranded and IdleTimeout can never reap this connection", got)
			}
			select {
			case <-stream.Context().Done():
			case <-time.After(time.Second):
				t.Error("stream context still live after the recovery reset")
			}
		})
	}
}
