package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"

	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// h2c (HTTP/2 Cleartext) support — RFC 7540 §3.2, §3.4
//
// RFC 9113 marks the h2c upgrade token and the HTTP2-Settings header field as
// obsolete (RFC 9113 §11), so RFC 7540 remains the governing text for the
// Upgrade path implemented here. Conformance tests: server/conformance_h2c_test.go.
// ---------------------------------------------------------------------------

// h2cPreface is the first bytes of the HTTP/2 client connection preface.
var h2cPreface = []byte("PRI * HTTP/2.0")

// detectAndServe performs h2c detection before passing to serveConn.
// If the client sends HTTP/1.1 Upgrade: h2c, we respond with 101 Switching.
// If the client sends the preface directly (prior knowledge), we pass through.
// Otherwise we respond with 400 Bad Request.
// cfg is the TLS config that produced the listener, or nil. H2C and TLS are not
// mutually exclusive — Options.H2C only decides whether the first bytes are
// sniffed — so the config has to reach conn.NewServerConn here too, or the
// RFC 9110 §7.4 check would be silently off for a TLS listener served with
// H2C enabled.
func (s *Server) detectAndServe(ctx context.Context, nc net.Conn, cfg *tls.Config) {
	// Bound the probe in both octets and time before a single byte is parsed.
	// http.ReadRequest accumulates the whole field section in memory with no
	// limit of its own, so an unbounded probe is a memory-exhaustion vector, and
	// a trickled one is Slowloris. The limiter is released once the protocol
	// decision is made — the HTTP/2 frames that follow must not be capped.
	lim := &probeLimitReader{r: nc, remaining: maxProbeHeadBytes}
	br := bufio.NewReaderSize(lim, 1024)
	_ = nc.SetReadDeadline(time.Now().Add(probeTimeout))

	// Peek first bytes to determine protocol.
	head, err := br.Peek(len(h2cPreface))
	if err != nil {
		// Short read — likely connection closed or timeout.
		_ = nc.Close()
		return
	}

	if bytes.Equal(head, h2cPreface) {
		// Prior knowledge h2c — client speaks HTTP/2 directly; no HTTP/1.1 head
		// to bound, and conn.NewServerConn applies its own handshake timeout.
		lim.release()
		_ = nc.SetReadDeadline(time.Time{})
		s.serveConnReader(ctx, nc, br, nil, cfg)
		return
	}

	// Could be HTTP/1.1 with Upgrade: h2c, or plain HTTP/1.1.
	s.handleHTTP1Upgrade(ctx, nc, br, lim, cfg)
}

// maxProbeHeadBytes bounds the HTTP/1.1 request head the h2c probe will read.
// Generous next to any real upgrade request, small next to what an attacker
// would need to matter. net/http's own server defaults to the same 1 MiB for
// MaxHeaderBytes; this is deliberately tighter, since the only request this
// path ever accepts is a bodyless upgrade.
const maxProbeHeadBytes = 64 << 10

// probeTimeout bounds how long the probe may take. Unlike the previous
// ctx-derived deadline it always applies: Serve is normally driven by a
// context with no deadline, so that one never fired.
const probeTimeout = 10 * time.Second

// errProbeHeadTooLarge is returned to http.ReadRequest once the cap is hit, so
// it fails rather than reading on.
var errProbeHeadTooLarge = errors.New("poseidon: h2c probe request head too large")

// probeLimitReader caps reads until release is called. It wraps the connection
// rather than the bufio.Reader so that releasing it cannot lose bytes already
// buffered above.
type probeLimitReader struct {
	r         io.Reader
	remaining int
	released  bool
}

func (l *probeLimitReader) release() { l.released = true }

func (l *probeLimitReader) Read(p []byte) (int, error) {
	if l.released {
		return l.r.Read(p)
	}
	if l.remaining <= 0 {
		return 0, errProbeHeadTooLarge
	}
	if len(p) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= n
	return n, err
}

// writeBadRequest writes a minimal HTTP/1.1 400 response and closes. This
// server speaks only HTTP/2, so every HTTP/1.1 request that is not a conformant
// h2c upgrade ends here — 400 is the only status this path ever produces.
func writeBadRequest(nc net.Conn, reason string) {
	body := reason + "\n"
	_, _ = fmt.Fprintf(nc, "HTTP/1.1 400 Bad Request\r\n"+
		"Content-Type: text/plain\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
	closeStaged(nc)
}

// drainTimeout and drainLimit bound the staged tear-down: how long to keep
// reading, and how much to discard, before closing outright.
const (
	drainTimeout = 500 * time.Millisecond
	drainLimit   = 64 << 10
)

// closeStaged tears the connection down the way RFC 9112 §9.6 prescribes
// (rfc9112.txt:1548): "servers typically close a connection in stages. First,
// the server performs a half-close by closing only the write side of the
// read/write connection. The server then continues to read from the connection
// until it receives a corresponding close by the client ... Finally, the server
// fully closes the connection."
//
// The hazard is stated just above it (:1539): unread client data arriving on a
// fully closed connection makes the TCP stack send a reset, and "the reset
// packet might erase the client's unacknowledged input buffers before they can
// be read and interpreted by the client's HTTP parser" — losing the very
// response just written. Both stages are bounded so a client that neither
// closes nor stops sending cannot pin the goroutine.
func closeStaged(nc net.Conn) {
	if cw, ok := nc.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		_ = nc.SetReadDeadline(time.Now().Add(drainTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(nc, drainLimit))
	}
	_ = nc.Close()
}

// hasListToken reports whether want appears as an element of a comma-separated
// field, across every field line of that name.
//
// Scanning all lines matters: net/http joins repeated field lines in
// Header.Values but its own shouldClose consults only the first, so a "close"
// option on a second Connection line would otherwise slip past. Empty elements
// simply do not match, and TrimSpace covers OWS — which RFC 9110 §5.6.3
// (rfc9110.txt:1774) defines as "*( SP / HTAB )".
func hasListToken(values []string, want string) bool {
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), want) {
				return true
			}
		}
	}
	return false
}

// hasUpgradeToken reports whether the Upgrade header field offers the exact
// token "h2c".
//
// RFC 7540 §3.2 (rfc7540.txt:464): "A server MUST ignore an "h2" token in an
// Upgrade header field." Ignoring means behaving as though it were absent, so
// "h2" is simply never matched here — including in a list such as "h2, h2c",
// where the "h2c" element still counts.
func hasUpgradeToken(values []string) bool {
	return hasListToken(values, "h2c")
}

// validHTTP2SettingsPayload reports whether v is a well-formed HTTP2-Settings
// field value: base64url without padding (RFC 7540 §3.2.1) decoding to a
// SETTINGS frame payload, which is a sequence of 6-octet parameter entries
// (RFC 7540 §6.5.1). An empty payload is legal — SETTINGS "MAY be empty".
func validHTTP2SettingsPayload(v string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return false
	}
	return len(raw)%6 == 0
}

// tokenChar reports whether c is a tchar (RFC 9110 §5.6.2, rfc9110.txt:1735):
//
//	tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//	        "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func tokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// validFieldName reports whether name matches field-name = token
// (RFC 9110 §5.1).
//
// This exists because of RFC 9112 §5.1 (rfc9112.txt:716): "A server MUST
// reject, with a response status code of 400 (Bad Request), any received
// request message that contains whitespace between a header field name and
// colon." Go's net/textproto deliberately accepts a SP there
// (go.dev/issue/34540) and returns the field under a key carrying the trailing
// space, so the check cannot be delegated to http.ReadRequest. A HTAB in the
// same position textproto does reject outright.
//
// Validating the whole name as a token rather than just hunting for a trailing
// space costs the same and covers every other way a name can be malformed.
func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		if !tokenChar(name[i]) {
			return false
		}
	}
	return true
}

// connectionSpecificFields are dropped when translating the HTTP/1.1 upgrade
// request into HTTP/2 request fields. RFC 9113 §8.2.2 forbids them in HTTP/2,
// and "HTTP2-Settings" is meaningful only to the upgrade itself.
var connectionSpecificFields = map[string]bool{
	"connection":        true,
	"upgrade":           true,
	"http2-settings":    true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"host":              true, // carried as :authority
}

// upgradeRequestFields translates the HTTP/1.1 request that initiated the
// upgrade into HTTP/2 request fields: pseudo-headers first (RFC 9113 §8.3),
// then the regular fields with connection-specific ones removed.
func upgradeRequestFields(req *http.Request) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, 4+len(req.Header))
	add := func(name, value string) {
		fields = append(fields, hpack.HeaderField{Name: []byte(name), Value: []byte(value)})
	}
	add(":method", req.Method)
	// The upgrade path is cleartext by construction, so the scheme is "http".
	add(":scheme", "http")
	add(":authority", req.Host)
	add(":path", req.URL.RequestURI())

	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if connectionSpecificFields[lower] {
			continue
		}
		for _, v := range values {
			add(lower, v)
		}
	}
	return fields
}

// handleHTTP1Upgrade processes an HTTP/1.1 request that may contain an
// Upgrade: h2c header. A conformant upgrade gets 101 Switching Protocols and
// the request is carried onto stream 1; anything else gets 400.
//
// Every rejection below is a normative requirement, not a policy choice:
//
//   - HTTP/1.0 request        RFC 9110 §7.8  — MUST ignore the Upgrade field;
//     RFC 9110 §15.2 — MUST NOT send 1xx to an HTTP/1.0 client
//   - no/duplicate/bad Host   RFC 9112 §2.2  — MUST respond 400
//   - "h2" token              RFC 7540 §3.2  — MUST ignore it
//   - no/duplicate            RFC 7540 §3.2.1 — MUST NOT upgrade
//     HTTP2-Settings
//   - request with content    RFC 9112 §9.6  — MUST read the entire body or
//     close; declining the upgrade is always
//     allowed (§3.2: a server "can respond to
//     the request as though the Upgrade header
//     field were absent") and it keeps unread
//     HTTP/1.1 octets from being re-read as
//     HTTP/2 frames.
func (s *Server) handleHTTP1Upgrade(ctx context.Context, nc net.Conn, br *bufio.Reader, lim *probeLimitReader, cfg *tls.Config) {

	req, err := http.ReadRequest(br)
	if err != nil {
		// Includes the duplicate-Host case, which net/http rejects for us.
		writeBadRequest(nc, "Malformed request")
		return
	}

	// RFC 9112 §5.1 — a field name that is not a token means whitespace crept
	// in before the colon, which net/textproto passes through.
	for name := range req.Header {
		if !validFieldName(name) {
			writeBadRequest(nc, "Malformed field name")
			return
		}
	}

	switch {
	case req.ProtoMajor != 1 || req.ProtoMinor < 1:
		// RFC 9110 §7.8 / §15.2 — no upgrade, and never a 1xx, below HTTP/1.1.
		writeBadRequest(nc, "Only h2c supported")
		return
	case req.Host == "":
		// RFC 9112 §2.2 (rfc9112.txt:445).
		writeBadRequest(nc, "Missing Host header field")
		return
	case !hasUpgradeToken(req.Header.Values("Upgrade")):
		writeBadRequest(nc, "Only h2c supported")
		return
	case hasListToken(req.Header.Values("Connection"), "close"):
		// RFC 9112 §9.6 (rfc9112.txt:1521): "A server that receives a "close"
		// connection option MUST initiate closure of the connection ... after it
		// sends the final response ... The server MUST NOT process any further
		// requests received on that connection."
		//
		// Upgrading is the one response that cannot satisfy that: the server
		// would go on to serve an unbounded number of HTTP/2 streams on a
		// connection the client declared finished. Declining is expressly
		// allowed — RFC 7540 §3.2 lets a server "respond to the request as
		// though the Upgrade header field were absent" — and writeBadRequest
		// sends "Connection: close" and closes, which is exactly what the rule
		// asks for.
		writeBadRequest(nc, "Upgrade request must not request connection close")
		return
	}

	// RFC 7540 §3.2.1 (rfc7540.txt:511): exactly one HTTP2-Settings field, and
	// it must actually be a SETTINGS payload.
	settings := req.Header.Values("HTTP2-Settings")
	if len(settings) != 1 || !validHTTP2SettingsPayload(settings[0]) {
		writeBadRequest(nc, "Upgrade requires exactly one valid HTTP2-Settings header field")
		return
	}

	// A body would have to be drained in full before the HTTP/2 preface, or its
	// remaining octets would be parsed as frames. Decline instead.
	if req.ContentLength != 0 || len(req.TransferEncoding) > 0 {
		writeBadRequest(nc, "Upgrade request must not carry content")
		return
	}

	// Send 101 Switching Protocols. RFC 9110 §7.8 requires the Upgrade field
	// naming the protocol switched to, and the "Upgrade" connection option.
	_, _ = fmt.Fprintf(nc,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: h2c\r\n\r\n")

	// Decision made: release the probe bounds before the HTTP/2 frames start.
	lim.release()
	_ = nc.SetReadDeadline(time.Time{})

	// The request owns stream 1 (RFC 7540 §3.2) — carry it into the connection.
	s.serveConnReader(ctx, nc, br, &conn.UpgradedRequest{Headers: upgradeRequestFields(req)}, cfg)
}

// serveConnReader wraps serveConn but uses a buffered reader that may
// have already consumed some bytes from the connection. upgraded is non-nil
// only on the h2c Upgrade path.
func (s *Server) serveConnReader(ctx context.Context, nc net.Conn, br *bufio.Reader, upgraded *conn.UpgradedRequest, cfg *tls.Config) {
	// If the bufio reader has buffered data, we need to present a
	// combined reader to NewServerConn. Wrap with bufioReaderConn.
	rwc := &bufioConn{Conn: nc, Reader: br}
	opts := s.connOpts
	if opts.StreamEventBuffer <= 0 {
		opts.StreamEventBuffer = 8
	}
	opts.UpgradedRequest = upgraded

	sc, err := conn.NewServerConn(ctx, rwc, opts)
	if err != nil {
		s.logger.Printf("poseidon: h2c handshake failed for %s: %v", nc.RemoteAddr(), err)
		_ = nc.Close()
		return
	}

	// Same §3.3/§9.2 admission check as serveConn. Not hypothetical: with
	// Options.H2C set, a real *tls.Conn from ListenAndServeTLSConfig is routed
	// through detectAndServe to here, so skipping it would leave a hole exactly
	// where both mechanisms overlap. nc, not rwc: the bufio wrapper is not a
	// *tls.Conn.
	if cs, ok := tlsAdmissible(nc); !ok {
		s.logger.Printf("poseidon: rejecting %s: alpn=%q tls=%#04x", nc.RemoteAddr(), cs.NegotiatedProtocol, cs.Version)
		_ = sc.GoAway(frame.ErrCodeInadequateSecurity)
		_ = sc.Close()
		return
	}

	s.trackConn(sc, true)
	defer s.trackConn(sc, false)

	s.acceptLoop(ctx, sc, presentedLeaf(cfg, nc))
}

// bufioConn wraps a net.Conn with a bufio.Reader so that peeked bytes
// are not lost when passing to conn.NewServerConn.
type bufioConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *bufioConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *bufioConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}
