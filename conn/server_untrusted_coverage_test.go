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

// ORIGIN (RFC 8336) and ALTSVC (RFC 7838) are optional extension frames a peer
// may send to a server; the server ignores them. They were 0%-covered no-op
// paths on the untrusted-input surface — exercise both the ignore path and the
// interleaving guard (an extension frame arriving mid-header-block is a
// connection PROTOCOL_ERROR, RFC 9113 §6.10, not a silent ignore).
func TestServerConnHandler_OnOriginAltSvc_IgnoredAndGuarded(t *testing.T) {
	mock := &mockConnOps{streams: make(map[uint32]*ServerStream)}
	h := newServerConnHandler(mock, hpack.NewDecoder(), 0, 0)

	// No open header block → both are silently ignored.
	if err := h.OnOrigin(frame.FrameHeader{}, []string{"https://example.com"}); err != nil {
		t.Fatalf("OnOrigin: unexpected error %v", err)
	}
	if err := h.OnAltSvc(frame.FrameHeader{}, nil); err != nil {
		t.Fatalf("OnAltSvc: unexpected error %v", err)
	}

	// With a HEADERS block still awaiting its CONTINUATION, any other frame type
	// is a connection PROTOCOL_ERROR.
	h.pendingStreamID = 1
	guarded := map[string]func() error{
		"OnOrigin": func() error { return h.OnOrigin(frame.FrameHeader{}, nil) },
		"OnAltSvc": func() error { return h.OnAltSvc(frame.FrameHeader{}, nil) },
	}
	for name, call := range guarded {
		var ce connError
		if err := call(); !errors.As(err, &ce) || ce.code != frame.ErrCodeProtocolError {
			t.Fatalf("%s during open header block: err = %v, want connError(PROTOCOL_ERROR)", name, err)
		}
	}
}

// applyInitialPeerSettings applies the client's initial SETTINGS to the server's
// HPACK encoder; the SETTINGS_HEADER_TABLE_SIZE branch (which resizes the
// encoder's dynamic table) was uncovered. Feed it an explicit table size plus an
// unrelated setting so both the matched and skipped branches run, across a range
// of peer-supplied sizes (including 0 and a large value) — an untrusted peer
// value must never panic the server.
func TestServerConn_ApplyInitialPeerSettings_HeaderTableSize(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan struct{})
	go func() { defer close(done); pipeClient(t, cli, nil) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc, err := NewServerConn(ctx, srv, ServerConnOptions{}.defaulted())
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	defer sc.Close()

	for _, size := range []uint32{0, 1, 4096, 1 << 20} {
		var p frame.SettingsParams
		setPeerSetting(&p, frame.SettingHeaderTableSize, size)
		setPeerSetting(&p, frame.SettingInitialWindowSize, 65535) // exercises the skipped branch
		sc.applyInitialPeerSettings(p)                            // must not panic for any peer value
	}
	if !sc.IsAlive() {
		t.Fatal("connection died applying peer HEADER_TABLE_SIZE settings")
	}
	<-done
}

// settingsRecorder is the transient frame.Handler used during the initial-
// SETTINGS handshake phase; its extension-frame hooks either drop the frame
// (no delegate) or forward it. Cover both branches of OnOrigin/OnAltSvc.
func TestSettingsRecorder_OnOriginAltSvc(t *testing.T) {
	r := &settingsRecorder{} // no delegate → dropped
	if err := r.OnOrigin(frame.FrameHeader{}, []string{"https://example.com"}); err != nil {
		t.Fatalf("OnOrigin (no delegate): %v", err)
	}
	if err := r.OnAltSvc(frame.FrameHeader{}, nil); err != nil {
		t.Fatalf("OnAltSvc (no delegate): %v", err)
	}

	r.delegate = nilHandler{} // delegate present → forwarded
	if err := r.OnOrigin(frame.FrameHeader{}, nil); err != nil {
		t.Fatalf("OnOrigin (delegate): %v", err)
	}
	if err := r.OnAltSvc(frame.FrameHeader{}, nil); err != nil {
		t.Fatalf("OnAltSvc (delegate): %v", err)
	}
}
