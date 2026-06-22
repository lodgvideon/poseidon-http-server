package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// Gzip — response body compression
// ---------------------------------------------------------------------------

// defaultGzipMinSize is the threshold below which compression is skipped.
// Small bodies (<512B) don't benefit from gzip — the overhead exceeds savings.
const defaultGzipMinSize = 512

// defaultGzipLevel is the compression level used by Gzip middleware.
// Level 5 = good balance between speed and ratio (gzip.BestSpeed=1, gzip.BestCompression=9).
const defaultGzipLevel = 5

// Header field names/values reused when rewriting the response.
var (
	hdrContentEncoding = []byte("content-encoding")
	hdrContentLength   = []byte("content-length")
	valGzip            = []byte("gzip")
)

// GzipConfig controls the gzip compression middleware.
type GzipConfig struct {
	// Level is the compression level (1–9). 0 means default (5).
	Level int

	// MinSize is the minimum response body size to compress. Bodies
	// smaller than this are sent uncompressed. Default: 512.
	MinSize int
}

// DefaultGzipConfig returns a sensible GzipConfig for production.
func DefaultGzipConfig() GzipConfig {
	return GzipConfig{
		Level:   defaultGzipLevel,
		MinSize: defaultGzipMinSize,
	}
}

// Gzip returns a middleware that compresses response bodies with gzip
// when the client sends Accept-Encoding: gzip and the response body
// exceeds MinSize.
//
// The middleware works by substituting a wrapping [server.ResponseWriter]
// into the handler chain (possible because ResponseWriter is an interface):
// the wrapper buffers everything the handler writes, then on flush decides
// whether to compress based on the buffered size. When it compresses it adds
// Content-Encoding: gzip and drops any Content-Length, then emits the headers
// and the compressed body in one shot. The whole body is held in memory, so
// this trades streaming for a simpler, allocation-bounded implementation.
//
// When the client does not accept gzip the original writer is passed straight
// through, so the non-gzip path carries zero interception overhead.
func Gzip(cfg GzipConfig) server.Middleware {
	if cfg.Level == 0 {
		cfg.Level = defaultGzipLevel
	}
	if cfg.Level < gzip.HuffmanOnly {
		cfg.Level = gzip.DefaultCompression
	}
	if cfg.MinSize == 0 {
		cfg.MinSize = defaultGzipMinSize
	}

	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			// Pass through untouched when the client cannot accept gzip.
			if !acceptsGzip(req.Headers) {
				return next.ServeHTTP(ctx, req, w)
			}

			gw := &gzipResponseWriter{ResponseWriter: w, cfg: cfg}
			// Flush fires as ServeHTTP unwinds — before the server's
			// post-handler finalization (auto-200 + WriteTrailers) runs
			// on the original writer.
			defer func() { _ = gw.flush() }()
			return next.ServeHTTP(ctx, req, gw)
		})
	}
}

// acceptsGzip checks if the client sent Accept-Encoding: gzip.
func acceptsGzip(headers []hpack.HeaderField) bool {
	for _, h := range headers {
		if string(h.Name) == "accept-encoding" {
			val := string(h.Value)
			return containsToken(val, "gzip")
		}
	}
	return false
}

// containsToken checks if a comma-separated header value contains a token.
func containsToken(val, token string) bool {
	for i := 0; i < len(val); i++ {
		// Skip leading whitespace/commas.
		for i < len(val) && (val[i] == ' ' || val[i] == ',') {
			i++
		}
		// Match token.
		j := 0
		for j < len(token) && i < len(val) && val[i] == token[j] {
			i++
			j++
		}
		if j == len(token) {
			// Ensure word boundary.
			if i >= len(val) || val[i] == ',' || val[i] == ';' || val[i] == ' ' {
				return true
			}
		}
		// Skip to next comma.
		for i < len(val) && val[i] != ',' {
			i++
		}
	}
	return false
}

// gzipResponseWriter wraps a server.ResponseWriter to buffer the response body
// and compress it on flush. It overrides every write method so the handler's
// output is captured rather than sent immediately; this lets flush() inject
// Content-Encoding into the (still unsent) headers once the body size is known.
//
// Both the native (WriteHeaders/WriteData) and stdlib (WriteHeader/Write) write
// paths are supported. Header() and Push are delegated to the wrapped writer.
type gzipResponseWriter struct {
	server.ResponseWriter // wrapped writer; provides Header() and Push delegation

	cfg GzipConfig
	buf bytes.Buffer

	status        int
	wroteHeader   bool                // a header/data method was called
	nativeHeaders []hpack.HeaderField // captured from WriteHeaders (native path)
	usedHTTP      bool                // stdlib WriteHeader/Write path was used
	flushed       bool
}

// WriteHeaders captures the native-path status and fields, deferring the send.
func (g *gzipResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	if g.wroteHeader {
		return nil // idempotent, mirroring the concrete writer
	}
	g.status = status
	g.nativeHeaders = headers
	g.wroteHeader = true
	return nil
}

// WriteData buffers a native-path body chunk.
func (g *gzipResponseWriter) WriteData(p []byte) error {
	if !g.wroteHeader {
		g.status = http.StatusOK
		g.wroteHeader = true
	}
	_, err := g.buf.Write(p)
	return err
}

// WriteHeader captures the stdlib-path status; headers are read from Header()
// at flush.
func (g *gzipResponseWriter) WriteHeader(statusCode int) {
	if g.wroteHeader {
		return
	}
	g.status = statusCode
	g.usedHTTP = true
	g.wroteHeader = true
}

// Write buffers a stdlib-path body chunk.
func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		g.status = http.StatusOK
		g.usedHTTP = true
		g.wroteHeader = true
	}
	return g.buf.Write(p)
}

// WriteTrailers flushes the buffered response before forwarding trailers, so a
// handler that ends its own stream still gets a compressed body.
func (g *gzipResponseWriter) WriteTrailers(trailers []hpack.HeaderField) error {
	if err := g.flush(); err != nil {
		return err
	}
	return g.ResponseWriter.WriteTrailers(trailers)
}

// Status, StatusCode and Written report the buffered state so the handler and
// outer middleware observe consistent values before flush.
func (g *gzipResponseWriter) Status() int     { return g.status }
func (g *gzipResponseWriter) StatusCode() int { return g.status }
func (g *gzipResponseWriter) Written() bool   { return g.wroteHeader }

// flush emits the buffered response to the wrapped writer, compressing when the
// body is large enough. It is idempotent.
func (g *gzipResponseWriter) flush() error {
	if g.flushed {
		return nil
	}
	g.flushed = true
	if !g.wroteHeader {
		// Nothing was written through the wrapper; let the server finalize
		// the response (auto-200 + trailers) on the underlying writer.
		return nil
	}

	body := g.buf.Bytes()
	out := body
	compress := len(body) >= g.cfg.MinSize
	if compress {
		if c, err := gzipCompress(body, g.cfg.Level); err == nil {
			out = c
		} else {
			compress = false // fall back to identity encoding on failure
		}
	}

	status := g.status
	if status == 0 {
		status = http.StatusOK
	}

	if g.usedHTTP {
		return g.flushHTTP(status, out, compress)
	}
	return g.flushNative(status, out, compress)
}

// flushNative emits via the native WriteHeaders/WriteData path.
func (g *gzipResponseWriter) flushNative(status int, out []byte, compress bool) error {
	headers := g.nativeHeaders
	if compress {
		headers = withGzipEncoding(headers)
	}
	if err := g.ResponseWriter.WriteHeaders(status, headers); err != nil {
		return err
	}
	if len(out) > 0 {
		return g.ResponseWriter.WriteData(out)
	}
	return nil
}

// flushHTTP emits via the stdlib WriteHeader/Write path, mutating the wrapped
// writer's Header() map to carry the encoding.
func (g *gzipResponseWriter) flushHTTP(status int, out []byte, compress bool) error {
	if compress {
		h := g.Header() // Header() is not overridden — same as the wrapped writer's
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
	}
	g.ResponseWriter.WriteHeader(status)
	if len(out) > 0 {
		_, err := g.ResponseWriter.Write(out)
		return err
	}
	return nil
}

// Unwrap returns the wrapped writer so server.PusherOf / server.FlusherOf can
// walk the chain to reach optional capabilities (Server Push, base flushing)
// through this wrapper. This is the net/http ResponseController convention; it
// replaces hand-written Push/PushWithScheme/PushWithPriority forwarders.
func (g *gzipResponseWriter) Unwrap() server.ResponseWriter { return g.ResponseWriter }

// Flush drains the buffered (and possibly compressed) response to the wrapped
// writer, then flushes the underlying writer if it supports http.Flusher. It
// implements http.Flusher so a handler can force the response out — the gzip
// buffer is emitted first so flushing does not strand the compressed body.
func (g *gzipResponseWriter) Flush() {
	_ = g.flush()
	if f, ok := server.FlusherOf(g.ResponseWriter); ok {
		f.Flush()
	}
}

// withGzipEncoding returns headers with Content-Length removed (the compressed
// length differs) and Content-Encoding: gzip appended.
func withGzipEncoding(headers []hpack.HeaderField) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(headers)+1)
	for _, h := range headers {
		if bytes.EqualFold(h.Name, hdrContentLength) {
			continue
		}
		out = append(out, h)
	}
	return append(out, hpack.HeaderField{Name: hdrContentEncoding, Value: valGzip})
}

// gzipCompress gzips src at the given level and returns the compressed bytes.
func gzipCompress(src []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(src); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DefaultMaxDecompressedSize bounds the output of [DecompressBody] to mitigate
// decompression bombs — a tiny gzip stream that inflates to gigabytes and
// exhausts memory. Callers needing a different ceiling use [DecompressBodyLimit].
const DefaultMaxDecompressedSize = 10 << 20 // 10 MiB

// ErrBodyTooLarge is returned while reading a body opened by [DecompressBody]
// or [DecompressBodyLimit] when the decompressed size exceeds the limit.
var ErrBodyTooLarge = errors.New("poseidon: decompressed body exceeds limit")

// gzipReadCloser wraps a gzip.Reader so callers can decompress
// gzip-compressed request bodies.
type gzipReadCloser struct {
	gr   io.ReadCloser
	body io.Closer // underlying source; gzip.Reader.Close does not close it
}

// Read decompresses data from the underlying gzip reader.
func (g *gzipReadCloser) Read(p []byte) (int, error) {
	return g.gr.Read(p)
}

// Close closes the gzip reader and the underlying source body. gzip.Reader.Close
// only finalizes the decompressor, so we close the source explicitly to avoid
// leaking it.
func (g *gzipReadCloser) Close() error {
	err := g.gr.Close()
	if g.body != nil {
		if cerr := g.body.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// limitedDecompressReader caps total decompressed output at a fixed budget and
// returns [ErrBodyTooLarge] if the source would produce more. A body exactly at
// the limit is allowed; only strictly larger input is rejected.
//
// It deliberately does NOT use io.LimitReader, which signals EOF at the limit
// and so silently truncates — turning an attack into a plausibly-valid short
// body. Instead, once the budget is spent it probes one more byte from the
// underlying reader: any byte means the source is larger than the limit; a
// clean EOF means the body fit exactly.
type limitedDecompressReader struct {
	gr   io.ReadCloser
	body io.Closer // underlying source; gzip.Reader.Close does not close it
	n    int64     // remaining decompressed-byte budget
}

func (l *limitedDecompressReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		// Budget spent: probe for any further byte. The io.Reader contract
		// permits a transient (0, nil), so loop until we observe a byte (the
		// source is larger than the limit) or a terminal error/EOF (the body
		// fit exactly).
		var probe [1]byte
		for {
			m, err := l.gr.Read(probe[:])
			if m > 0 {
				return 0, ErrBodyTooLarge
			}
			if err != nil {
				return 0, err
			}
		}
	}
	// Never hand the caller more than the budget allows.
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.gr.Read(p)
	l.n -= int64(n)
	return n, err
}

// Close closes the gzip reader and the underlying source body (see
// gzipReadCloser.Close).
func (l *limitedDecompressReader) Close() error {
	err := l.gr.Close()
	if l.body != nil {
		if cerr := l.body.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// DecompressBody decompresses a gzip-compressed request body, bounding the
// decompressed size at [DefaultMaxDecompressedSize] to guard against
// decompression bombs. Reading past that ceiling yields [ErrBodyTooLarge].
// The returned ReadCloser must be closed by the caller. Use
// [DecompressBodyLimit] to choose a different ceiling (or to opt out of it).
func DecompressBody(body io.ReadCloser) (io.ReadCloser, error) {
	return DecompressBodyLimit(body, DefaultMaxDecompressedSize)
}

// DecompressBodyLimit is like [DecompressBody] but caps the decompressed output
// at maxBytes: reading a body that inflates beyond maxBytes yields
// [ErrBodyTooLarge] rather than streaming unbounded data. A body whose
// decompressed size equals maxBytes exactly is allowed. A maxBytes <= 0 disables
// the limit (unbounded — use only for trusted input). The returned ReadCloser
// must be closed by the caller.
func DecompressBodyLimit(body io.ReadCloser, maxBytes int64) (io.ReadCloser, error) {
	gr, err := gzip.NewReader(body)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	if maxBytes <= 0 {
		return &gzipReadCloser{gr: gr, body: body}, nil
	}
	return &limitedDecompressReader{gr: gr, body: body, n: maxBytes}, nil
}
