package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
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
// The middleware buffers the response body, compresses it, and sends
// it in one shot. For streaming responses (WriteData called multiple
// times), each chunk is compressed independently via a gzip writer.
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
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w *server.ResponseWriter) error {
			// Check if client accepts gzip.
			if !acceptsGzip(req.Headers) {
				return next.ServeHTTP(ctx, req, w)
			}

			// Wrap the response writer with a gzip buffer.
			gw := &gzipResponseWriter{
				ResponseWriter: w,
				cfg:            cfg,
				buf:            &bytes.Buffer{},
			}
			defer gw.flush()

			return next.ServeHTTP(ctx, req, gw.asResponseWriter())
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

// gzipResponseWriter wraps ResponseWriter to intercept WriteData calls
// and buffer them for gzip compression.
type gzipResponseWriter struct {
	*server.ResponseWriter
	cfg       GzipConfig
	buf       *bytes.Buffer
	headerSent bool
	compress  bool
}

func (g *gzipResponseWriter) asResponseWriter() *server.ResponseWriter {
	return g.ResponseWriter
}

// Write intercepts the http.ResponseWriter.Write path.
func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	return g.buf.Write(p)
}

// WriteData intercepts the native Poseidon WriteData path.
func (g *gzipResponseWriter) WriteData(p []byte) error {
	_, err := g.buf.Write(p)
	return err
}

// WriteHeaders intercepts header writes to inject content-encoding.
func (g *gzipResponseWriter) WriteHeaders(status int, headers []hpack.HeaderField) error {
	// Decide whether to compress based on buffered size.
	g.compress = g.buf.Len() >= g.cfg.MinSize || status >= 400

	if g.compress && !g.headerSent {
		headers = append(headers, hpack.HeaderField{
			Name:  []byte("content-encoding"),
			Value: []byte("gzip"),
		})
		g.headerSent = true
	}

	return g.ResponseWriter.WriteHeaders(status, headers)
}

// flush compresses the buffered data and writes it to the underlying stream.
func (g *gzipResponseWriter) flush() {
	if g.buf.Len() == 0 {
		return
	}

	// Decide: compress if body is large enough.
	shouldCompress := g.buf.Len() >= g.cfg.MinSize

	// Ensure headers sent.
	if !g.ResponseWriter.Written() {
		extra := []hpack.HeaderField(nil)
		if shouldCompress {
			extra = append(extra, hpack.HeaderField{
				Name:  []byte("content-encoding"),
				Value: []byte("gzip"),
			})
		}
		_ = g.ResponseWriter.WriteHeaders(http.StatusOK, extra)
	}

	if shouldCompress {
		// Compress and write.
		if err := compressTo(g.ResponseWriter, g.buf.Bytes(), g.cfg.Level); err != nil {
			// Fallback: write uncompressed.
			_ = g.ResponseWriter.WriteData(g.buf.Bytes())
		}
	} else {
		_ = g.ResponseWriter.WriteData(g.buf.Bytes())
	}
}

// compressTo gzips src and writes it to the ResponseWriter.
func compressTo(w *server.ResponseWriter, src []byte, level int) error {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return err
	}
	if _, err := zw.Write(src); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return w.WriteData(buf.Bytes())
}

// gzipReadCloser wraps a gzip.Reader so callers can decompress
// gzip-compressed request bodies.
type gzipReadCloser struct {
	gr io.ReadCloser
}

// Read decompresses data from the underlying gzip reader.
func (g *gzipReadCloser) Read(p []byte) (int, error) {
	return g.gr.Read(p)
}

// Close closes the underlying gzip reader.
func (g *gzipReadCloser) Close() error {
	return g.gr.Close()
}

// DecompressBody decompresses a gzip-compressed request body.
// Returns a ReadCloser that must be closed by the caller.
func DecompressBody(body io.ReadCloser) (io.ReadCloser, error) {
	gr, err := gzip.NewReader(body)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	return &gzipReadCloser{gr: gr}, nil
}
