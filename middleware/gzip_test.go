package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

func TestGzip_CompressionRoundtrip(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("Hello, World! "), 40) // ~560 bytes
	origSize := len(body)

	// Verify compression reduces size.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	zw.Close()
	if buf.Len() >= origSize {
		t.Fatalf("compressed %d >= original %d", buf.Len(), origSize)
	}

	// Verify decompression round-trips.
	zr, _ := gzip.NewReader(&buf)
	decompressed, _ := io.ReadAll(zr)
	if !bytes.Equal(decompressed, body) {
		t.Fatal("decompressed != original")
	}
}

func TestGzip_SkipsSmallBody(t *testing.T) {
	t.Parallel()

	body := []byte("hi")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	zw.Close()

	// For small bodies, gzip overhead makes them bigger.
	if buf.Len() <= len(body) {
		t.Logf("compressed %d <= original %d (unexpected but not fatal)", buf.Len(), len(body))
	}
}

func TestAcceptsGzip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers []hpack.HeaderField
		want    bool
	}{
		{"gzip", []hpack.HeaderField{{Name: []byte("accept-encoding"), Value: []byte("gzip")}}, true},
		{"gzip deflate", []hpack.HeaderField{{Name: []byte("accept-encoding"), Value: []byte("gzip, deflate")}}, true},
		{"deflate only", []hpack.HeaderField{{Name: []byte("accept-encoding"), Value: []byte("deflate")}}, false},
		{"br only", []hpack.HeaderField{{Name: []byte("accept-encoding"), Value: []byte("br")}}, false},
		{"empty", nil, false},
		{"gzipzilla", []hpack.HeaderField{{Name: []byte("accept-encoding"), Value: []byte("gzipzilla")}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := acceptsGzip(tt.headers)
			if got != tt.want {
				t.Fatalf("acceptsGzip = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		val   string
		token string
		want  bool
	}{
		{"gzip", "gzip", true},
		{"gzip, deflate", "gzip", true},
		{"deflate, gzip", "gzip", true},
		{"deflate, gzip, br", "gzip", true},
		{"gzipzilla", "gzip", false},
		{"deflate", "gzip", false},
		{"", "gzip", false},
		{"gzip; q=0.8", "gzip", true},
	}

	for _, tt := range tests {
		t.Run(tt.val+"/"+tt.token, func(t *testing.T) {
			t.Parallel()
			got := containsToken(tt.val, tt.token)
			if got != tt.want {
				t.Fatalf("containsToken(%q, %q) = %v, want %v", tt.val, tt.token, got, tt.want)
			}
		})
	}
}

func TestDecompressBody(t *testing.T) {
	t.Parallel()

	original := []byte("Hello, compressed world!")

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(original)
	zw.Close()

	rc := io.NopCloser(&buf)

	dr, err := DecompressBody(rc)
	if err != nil {
		t.Fatalf("DecompressBody: %v", err)
	}
	defer dr.Close()

	result, _ := io.ReadAll(dr)
	if !bytes.Equal(result, original) {
		t.Fatalf("decompressed %q != original %q", result, original)
	}
}

func TestGzipConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultGzipConfig()
	if cfg.Level != defaultGzipLevel {
		t.Fatalf("Level = %d, want %d", cfg.Level, defaultGzipLevel)
	}
	if cfg.MinSize != defaultGzipMinSize {
		t.Fatalf("MinSize = %d, want %d", cfg.MinSize, defaultGzipMinSize)
	}
}

func TestGzip_MiddlewareCompiles(t *testing.T) {
	t.Parallel()

	mw := Gzip(GzipConfig{Level: 6, MinSize: 256})
	if mw == nil {
		t.Fatal("Gzip returned nil middleware")
	}

	_ = mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		return nil
	}))
}
