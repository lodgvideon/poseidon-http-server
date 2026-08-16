package http3server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// ---------------------------------------------------------------------------
// The client's control stream (issue #128).
//
// Every test here drives a REAL QUIC listener. Two of them speak through the
// production HTTP/3 client, wrapped so it advertises the SETTINGS the test needs;
// the third hand-rolls the HTTP/3 layer on a real QUIC connection, because the
// production client always opens a conforming control stream and the rule under
// test is what happens when a peer does not. Nothing below hands the server the
// value it is supposed to have learned from the wire.
// ---------------------------------------------------------------------------

// rfc9114FieldOverhead is the per-field overhead RFC 9114 §4.2.2 charges when
// sizing a field section: "the length of the name and value in bytes plus an
// overhead of 32 bytes for each field". Spelled out here rather than taken from the
// production constant, so a wrong one there cannot make these tests agree with it.
const rfc9114FieldOverhead = 32

// dialRawPeer establishes a client QUIC connection to addr and returns it with no
// HTTP/3 layer on top, so a test can drive the unidirectional streams by hand.
// The caller owns Poll: there is no reader goroutine.
func dialRawPeer(ctx context.Context, t *testing.T, addr string, pool *x509.CertPool) *quic.Conn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	tp := quic.AppendTransportParams(nil, quic.LocalTransportParams{
		InitialMaxData:                quic.DefaultConnRecvWindow,
		InitialMaxStreamDataBidiLocal: quic.DefaultStreamRecvWindow,
		InitialMaxStreamDataUni:       quic.DefaultStreamRecvWindow,
		InitialMaxStreamsUni:          3, // the server's control + QPACK streams
		MaxIdleTimeout:                30000,
	})
	conn, err := quic.NewConn(uc, &tls.Config{
		ServerName: "example.com",
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
		// Keep the ClientHello inside one Initial packet, as http3.Dial does.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}, tp)
	if err != nil {
		t.Fatalf("quic.NewConn: %v", err)
	}
	if err := conn.Establish(ctx); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// dialWithSettings starts a server for h and dials it with the production HTTP/3
// client advertising exactly settings — the client's own SETTINGS frame on its own
// control stream, sent by the production code, not injected into the server.
func dialWithSettings(ctx context.Context, t *testing.T, h http.Handler, settings []http3.Setting) *http3.Client {
	t.Helper()
	addr, pool := serveTest(ctx, t, h)
	conn := dialRawPeer(ctx, t, addr, pool)
	c, err := http3.NewClient(conn, settings)
	if err != nil {
		t.Fatalf("http3.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// sectionSizes returns the compressed (QPACK) and uncompressed (§4.2.2) sizes of
// the response field section the server will build for status and hdr. The
// uncompressed sum is written out here rather than taken from the production
// helper, so the tests do not agree with a wrong one.
func sectionSizes(status int, hdr http.Header) (compressed, uncompressed uint64) {
	fields := []hpack.HeaderField{{Name: []byte(":status"), Value: []byte(strconv.Itoa(status))}}
	for name, values := range hdr {
		for _, v := range values {
			fields = append(fields, hpack.HeaderField{Name: []byte(strings.ToLower(name)), Value: []byte(v)})
		}
	}
	for i := range fields {
		uncompressed += uint64(len(fields[i].Name)) + uint64(len(fields[i].Value)) + rfc9114FieldOverhead
	}
	return uint64(len(qpack.NewEncoder().EncodeFieldSection(nil, fields))), uncompressed
}

// wantStreamReset asserts err is the server refusing to send the response by
// resetting the request stream, rather than a success or some other failure.
func wantStreamReset(t *testing.T, err error, code uint64) {
	t.Helper()
	if err == nil {
		t.Fatal("Do succeeded: the server sent a response field section it should have refused")
	}
	var rst *http3.StreamResetError
	if !errors.As(err, &rst) {
		t.Fatalf("Do failed with %v (%T), want a stream reset from the server", err, err)
	}
	if rst.Code != code {
		t.Errorf("stream reset code = %#x, want %#x", rst.Code, code)
	}
}

// TestServer_BoundsResponseByClientMaxFieldSectionSize asserts the response field
// section is bounded by the limit the CLIENT advertised, not by the constant this
// server advertises for the requests it accepts. RFC 9114 §4.2.2: "An
// implementation that has received this parameter SHOULD NOT send an HTTP message
// header that exceeds the indicated size, as the peer will likely refuse to
// process it."
//
// The client's limit here (512) is far below the server's own 65536, so a server
// that never reads the client's SETTINGS answers happily and fails this test.
func TestServer_BoundsResponseByClientMaxFieldSectionSize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const clientLimit = 512
	hdr := http.Header{}
	for i := range 16 { // ~16 * (5+64+32) = ~1616 bytes uncompressed
		hdr.Set("x-pad-"+strconv.Itoa(i), strings.Repeat("v", 64))
	}
	_, uncompressed := sectionSizes(http.StatusOK, hdr)
	if uncompressed <= clientLimit {
		t.Fatalf("test premise: field section is %d bytes uncompressed, want > %d", uncompressed, clientLimit)
	}

	c := dialWithSettings(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range hdr {
			w.Header().Set(k, vs[0])
		}
		w.WriteHeader(http.StatusOK)
	}), []http3.Setting{{ID: http3.SettingMaxFieldSectionSize, Value: clientLimit}})

	_, _, err := c.Do(ctx, &http3.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/big"})
	wantStreamReset(t, err, http3.H3InternalError)
}

// TestServer_MeasuresFieldSectionUncompressed asserts the limit is applied to the
// size RFC 9114 §4.2.2 defines — "the uncompressed size of fields, including the
// length of the name and value in bytes plus an overhead of 32 bytes for each
// field" — and not to the length of the QPACK block on the wire.
//
// The response below is chosen so the two disagree: its compressed block fits
// inside the advertised limit while its uncompressed size does not. A server that
// measures the compressed block sends it and fails this test even if it reads the
// client's SETTINGS correctly.
func TestServer_MeasuresFieldSectionUncompressed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const clientLimit = 4096
	hdr := http.Header{}
	// A long run of one Huffman-friendly byte: 5 bits each on the wire, ~8 in the
	// size §4.2.2 counts.
	hdr.Set("X-Pad", strings.Repeat("a", 5000))

	compressed, uncompressed := sectionSizes(http.StatusOK, hdr)
	if compressed >= clientLimit {
		t.Fatalf("test premise: compressed section is %d bytes, want < %d — this response no longer "+
			"separates the compressed measurement from the uncompressed one", compressed, clientLimit)
	}
	if uncompressed <= clientLimit {
		t.Fatalf("test premise: uncompressed section is %d bytes, want > %d", uncompressed, clientLimit)
	}
	t.Logf("field section: %d bytes compressed, %d bytes uncompressed (§4.2.2), client limit %d",
		compressed, uncompressed, clientLimit)

	c := dialWithSettings(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pad", hdr.Get("X-Pad"))
		w.WriteHeader(http.StatusOK)
	}), []http3.Setting{{ID: http3.SettingMaxFieldSectionSize, Value: clientLimit}})

	_, _, err := c.Do(ctx, &http3.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/pad"})
	wantStreamReset(t, err, http3.H3InternalError)
}

// TestServer_ClientSettingsDoNotBreakTheDefaultClient is the other direction: a
// client that advertises no limit at all (the production default, and §7.2.4.1's
// "unlimited") still gets its response. It pins that reading the control stream
// did not turn an ordinary exchange into a refusal.
func TestServer_ClientSettingsDoNotBreakTheDefaultClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := dialWithSettings(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pad", strings.Repeat("a", 5000)) // refused above under a 4096 limit
		w.WriteHeader(http.StatusOK)
	}), []http3.Setting{{ID: http3.SettingQPACKMaxTableCapacity, Value: 0}})

	resp, _, err := c.Do(ctx, &http3.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/pad"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.Status)
	}
}

// wantConnClosed drives conn's Poll until the peer closes the connection and
// asserts the application error code it closed with.
func wantConnClosed(ctx context.Context, t *testing.T, conn *quic.Conn, code uint64) {
	t.Helper()
	for {
		err := conn.Poll(ctx)
		if err == nil {
			continue
		}
		var closed *quic.PeerClosedError
		if !errors.As(err, &closed) {
			t.Fatalf("Poll = %v (%T), want the server to close the connection with %#x", err, err, code)
		}
		if !closed.App || closed.Code != code {
			t.Fatalf("server closed with app=%v code=%#x, want app=true code=%#x", closed.App, closed.Code, code)
		}
		return
	}
}

// TestServer_ControlStreamMustOpenWithSettings asserts the H3_MISSING_SETTINGS
// connection error. RFC 9114 §6.2.1: "Each side MUST initiate a single control
// stream at the beginning of the connection and send its SETTINGS frame as the
// first frame on this stream. If the first frame of the control stream is any
// other frame type, this MUST be treated as a connection error of type
// H3_MISSING_SETTINGS."
//
// The peer here opens a conforming control stream (type 0x00) and puts a GOAWAY on
// it first. A server that accepts the stream and never reads it serves this
// connection normally.
func TestServer_ControlStreamMustOpenWithSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	// Stream type 0x00 (control), then GOAWAY where SETTINGS is required.
	if _, err := ctl.Send(http3.AppendGoaway([]byte{0x00}, 0), false); err != nil {
		t.Fatalf("Send: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3MissingSettings)
}

// TestServer_RejectsSecondSettings asserts H3_FRAME_UNEXPECTED, which covers the
// whole post-SETTINGS legality switch — DATA and HEADERS on a control stream
// (§7.2.1, §7.2.2), a PUSH_PROMISE at a server (§7.2.5) and the reserved
// HTTP/2-carryover types (§7.2.8) all reach the same branch. RFC 9114 §7.2.4: a
// SETTINGS frame "MUST NOT be sent subsequently. If an endpoint receives a second
// SETTINGS frame on the control stream, the endpoint MUST respond with a
// connection error of type H3_FRAME_UNEXPECTED."
func TestServer_RejectsSecondSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	// A conforming control stream, then a second SETTINGS frame on it.
	frame := http3.AppendClientControlStream(nil, []http3.Setting{{ID: http3.SettingMaxFieldSectionSize, Value: 4096}})
	if _, err := ctl.Send(http3.AppendSettings(frame, nil), false); err != nil {
		t.Fatalf("Send: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3FrameUnexpected)
}

// TestServer_RejectsSecondControlStream asserts H3_STREAM_CREATION_ERROR. RFC 9114
// §6.2.1: "Only one control stream per peer is permitted; receipt of a second
// stream claiming to be a control stream MUST be treated as a connection error of
// type H3_STREAM_CREATION_ERROR."
func TestServer_RejectsSecondControlStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	for i := range 2 {
		ctl, err := conn.OpenUniStream()
		if err != nil {
			t.Fatalf("OpenUniStream %d: %v", i, err)
		}
		if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	wantConnClosed(ctx, t, conn, http3.H3StreamCreationError)
}

// TestServer_RejectsClientPushStream asserts H3_STREAM_CREATION_ERROR. RFC 9114
// §6.2.2: "Only servers can push; if a server receives a client-initiated push
// stream, this MUST be treated as a connection error of type
// H3_STREAM_CREATION_ERROR."
func TestServer_RejectsClientPushStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	conn := dialRawPeer(ctx, t, addr, pool)

	push, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := push.Send([]byte{0x01, 0x00}, false); err != nil { // push stream, push ID 0
		t.Fatalf("Send: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3StreamCreationError)
}
