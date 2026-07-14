// Package http3server serves HTTP/3 (RFC 9114) to an ordinary http.Handler.
//
// It maps QUIC streams onto HTTP semantics: each client-initiated bidirectional
// stream carries one request/response exchange. The QUIC transport, the HTTP/3
// frame codec, and QPACK field compression all come from poseidon-http-client,
// which owns the wire format for both roles; this package is the http.Handler
// adapter on top.
//
// # Status
//
// It speaks the static-table QPACK profile (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0),
// which is fully conformant and never blocks on head-of-line. Server push, 0-RTT,
// and trailers are not implemented. See the transport's limits in
// poseidon-http-client's quic.Listener: no Retry / address validation and no
// per-peer rate limiting, so front this with a rate limiter before exposing it to
// the internet.
package http3server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
	"github.com/lodgvideon/poseidon-http-client/qpack"
	"github.com/lodgvideon/poseidon-http-client/quic"
)

// Default limits. maxRequestBytes bounds a buffered request; maxFieldSection
// bounds a field section, the value advertised as SETTINGS_MAX_FIELD_SECTION_SIZE.
const (
	maxRequestBytes uint64 = 1 << 20
	maxFieldSection uint64 = 1 << 16
	maxStreamsBidi  uint64 = 100 // concurrent requests a client may have in flight
	maxStreamsUni   uint64 = 4   // client control + QPACK encoder/decoder, with slack
)

// Server serves HTTP/3 requests to Handler.
type Server struct {
	// Handler answers requests. A nil Handler serves http.DefaultServeMux.
	Handler http.Handler
	// TLSConfig must carry the server's certificate(s). ALPN "h3" is filled in
	// when NextProtos is unset.
	TLSConfig *tls.Config
}

// ListenAndServe listens on addr ("host:port") and serves HTTP/3 until ctx is
// cancelled or the listener fails.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	l, err := quic.Listen(addr, s.TLSConfig, quic.ServerTransportParams{
		MaxStreamsBidi: maxStreamsBidi,
		MaxStreamsUni:  maxStreamsUni,
	})
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	return s.Serve(ctx, l)
}

// Serve accepts connections from l and serves each until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l *quic.Listener) error {
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		go s.serveConn(ctx, c)
	}
}

// handler returns the handler to serve with.
func (s *Server) handler() http.Handler {
	if s.Handler != nil {
		return s.Handler
	}
	return http.DefaultServeMux
}

// serveConn drives one connection. This goroutine owns the connection's Poll
// loop — the only thing that reads the socket — and hands each request stream to
// its own goroutine, which waits on that stream's readiness. It mirrors how the
// client drives a connection, so no new concurrency model is introduced.
func (s *Server) serveConn(ctx context.Context, c *quic.Conn) {
	defer func() { _ = c.Close() }()

	if err := s.openControlStream(c); err != nil {
		return
	}
	for {
		if err := c.Poll(ctx); err != nil {
			return // the connection ended: idle timeout, peer close, or ctx
		}
		for rs := c.AcceptBidiStream(); rs != nil; rs = c.AcceptBidiStream() {
			go s.serveRequest(ctx, rs)
		}
		// Accept the client's unidirectional streams (its control and QPACK
		// streams) so they are registered and flow-controlled. Under the
		// static-table profile there is nothing to read from them.
		for us := c.AcceptUniStream(); us != nil; us = c.AcceptUniStream() {
			_ = us
		}
	}
}

// openControlStream opens the server's control stream and sends SETTINGS, which
// RFC 9114 §6.2.1 requires as its first frame. A client that sees no SETTINGS
// treats the connection as an error, so this must precede any response.
func (s *Server) openControlStream(c *quic.Conn) error {
	ctl, err := c.OpenUniStream()
	if err != nil {
		return err
	}
	// The control stream is stream type 0x00 followed by SETTINGS, identically for
	// both roles.
	frame := http3.AppendClientControlStream(nil, []http3.Setting{
		{ID: http3.SettingMaxFieldSectionSize, Value: maxFieldSection},
		// Advertise the static-table QPACK profile: no dynamic table, no blocked
		// streams. This is what our decoder implements.
		{ID: http3.SettingQPACKMaxTableCapacity, Value: 0},
		{ID: http3.SettingQPACKBlockedStreams, Value: 0},
	})
	_, err = ctl.Send(frame, false) // the control stream stays open
	return err
}

// serveRequest reads one request off its stream, runs the handler, and writes the
// response back on the same stream.
func (s *Server) serveRequest(ctx context.Context, rs *quic.Stream) {
	body, err := readRequestStream(ctx, rs)
	if err != nil {
		// The request never arrived whole: the peer reset it, it outgrew the buffer,
		// or the connection is going away.
		_ = rs.Reset(http3.H3RequestCancelled)
		return
	}
	req, err := decodeRequest(body)
	if err != nil {
		_ = rs.Reset(http3.H3MessageError)
		return
	}
	req = req.WithContext(ctx)

	rw := &responseWriter{header: http.Header{}, status: http.StatusOK}
	s.handler().ServeHTTP(rw, req)

	resp, err := encodeResponse(rw)
	if err != nil {
		_ = rs.Reset(http3.H3InternalError)
		return
	}
	_, _ = rs.Send(resp, true) // FIN: the response ends the stream
}

// readRequestStream buffers a whole request. The connection's Poll loop feeds the
// stream; this waits on its readiness until the client signals the end with a FIN.
func readRequestStream(ctx context.Context, rs *quic.Stream) ([]byte, error) {
	var buf []byte
	for {
		// Read the state BEFORE draining. Once a stream reports finished every byte
		// is contiguous, so the Recv below drains the rest. Draining first and then
		// asking would race the connection's Poll loop: data can land in between,
		// and the finished report would send us away without it — a request whose
		// body silently vanishes.
		finished, reset, _ := rs.RecvState()
		buf = append(buf, rs.Recv()...)
		if reset {
			return nil, io.ErrUnexpectedEOF
		}
		if uint64(len(buf)) > maxRequestBytes {
			return nil, io.ErrShortBuffer
		}
		if finished {
			return buf, nil
		}
		if err := rs.WaitReadable(ctx); err != nil {
			return nil, err
		}
	}
}

// decodeRequest turns a request stream's frames into an http.Request: one HEADERS
// frame carrying the QPACK field section, then any DATA frames carrying the body
// (RFC 9114 §4.1).
func decodeRequest(stream []byte) (*http.Request, error) {
	var fr http3.FrameReader
	fr.SetMaxFrameLen(maxRequestBytes)
	fr.Feed(stream)

	var (
		fields []hpack.HeaderField
		body   []byte
		seen   bool
	)
	for {
		typ, payload, err := fr.ReadFrame()
		if errors.Is(err, http3.ErrNeedMore) {
			break // a partial trailing frame: the request holds nothing more
		}
		if err != nil {
			return nil, err
		}
		switch typ {
		case http3.FrameHeaders:
			if seen {
				continue // trailers: not surfaced
			}
			seen = true
			if fields, err = decodeFields(payload); err != nil {
				return nil, err
			}
		case http3.FrameData:
			body = append(body, payload...)
		default:
			// SETTINGS and friends do not belong on a request stream; ignore the
			// frame types that are merely unknown or reserved (§7.2.8).
		}
	}
	if !seen {
		return nil, http3.ErrH3Message
	}
	return buildRequest(fields, body)
}

// decodeFields decodes a QPACK field section under the static-table profile.
func decodeFields(section []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	err := qpack.NewDecoder().DecodeFieldSection(section, nil, func(name, value []byte) error {
		// name/value alias the decoder's scratch, so copy them.
		fields = append(fields, hpack.HeaderField{
			Name:  append([]byte(nil), name...),
			Value: append([]byte(nil), value...),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// buildRequest maps a decoded field section and body onto an http.Request
// (RFC 9114 §4.3.1: :method, :scheme, :path and :authority).
func buildRequest(fields []hpack.HeaderField, body []byte) (*http.Request, error) {
	var method, scheme, path, authority string
	header := http.Header{}
	for _, f := range fields {
		switch string(f.Name) {
		case ":method":
			method = string(f.Value)
		case ":scheme":
			scheme = string(f.Value)
		case ":path":
			path = string(f.Value)
		case ":authority":
			authority = string(f.Value)
		default:
			if len(f.Name) > 0 && f.Name[0] == ':' {
				return nil, http3.ErrH3Message // an unknown pseudo-header
			}
			header.Add(string(f.Name), string(f.Value))
		}
	}
	if method == "" || scheme == "" || path == "" {
		return nil, http3.ErrH3Message
	}
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, http3.ErrH3Message
	}
	req := &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/3.0",
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          authority,
		RequestURI:    path,
	}
	if authority != "" {
		req.URL.Host = authority
	}
	req.URL.Scheme = scheme
	return req, nil
}

// encodeResponse builds the response stream: a HEADERS frame with the QPACK field
// section, then a DATA frame with the body (RFC 9114 §4.1).
func encodeResponse(rw *responseWriter) ([]byte, error) {
	fields := make([]hpack.HeaderField, 0, len(rw.header)+1)
	// :status leads the field section (RFC 9114 §4.3.2).
	fields = append(fields, hpack.HeaderField{
		Name:  []byte(":status"),
		Value: []byte(strconv.Itoa(rw.status)),
	})
	for name, values := range rw.header {
		for _, v := range values {
			fields = append(fields, hpack.HeaderField{
				Name:  []byte(lowerASCII(name)), // field names are lowercase on the wire
				Value: []byte(v),
			})
		}
	}
	section := qpack.NewEncoder().EncodeFieldSection(nil, fields)
	if uint64(len(section)) > maxFieldSection {
		return nil, http3.ErrFieldSectionTooLarge
	}
	out := http3.AppendHeaders(nil, section)
	if rw.body.Len() > 0 {
		out = http3.AppendData(out, rw.body.Bytes())
	}
	return out, nil
}

// lowerASCII lowercases an HTTP field name, which is ASCII by definition.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// responseWriter buffers a handler's response until the whole exchange can be
// framed. HTTP/3 sends the field section as one QPACK block, so the status and
// headers must be final before anything goes on the wire; streaming a body as it
// is written is a later phase.
type responseWriter struct {
	header      http.Header
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}
