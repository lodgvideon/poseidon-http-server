package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// What survives ToHTTPHandler (#211).
//
// HTTPRequestToRequest took the authority and scheme from r.URL, which net/http
// fills in only for client-shaped requests. On a request a SERVER receives, the
// URL is the path-only request-target and the authority lives in r.Host, so both
// arrived empty — and the adapter pair ToHTTPHandler(FromHTTPHandler(h)) then
// answered 400 to everything, because NewHTTPRequest refuses an http/https
// target with no authority.
//
// The pair is what the adapters exist for: a Poseidon handler mounted on a
// stdlib mux, which is how cmd/poseidon-server mounts pprof.
// ---------------------------------------------------------------------------

func TestHTTPRequestToRequest_ServerShapedRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		req           func() *http.Request
		wantAuthority string
		wantScheme    string
		wantPath      string
	}{
		{
			name:          "plain server request",
			req:           func() *http.Request { return httptest.NewRequest(http.MethodGet, "/x", nil) },
			wantAuthority: "example.com",
			wantScheme:    "http",
			wantPath:      "/x",
		},
		{
			name: "server request over TLS",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/x", nil)
				r.TLS = &tls.ConnectionState{}
				return r
			},
			wantAuthority: "example.com",
			wantScheme:    "https",
			wantPath:      "/x",
		},
		{
			name: "an explicit Host header wins over nothing",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/x", nil)
				r.Host = "vhost.example:8443"
				return r
			},
			wantAuthority: "vhost.example:8443",
			wantScheme:    "http",
			wantPath:      "/x",
		},
		{
			// Request.Path is documented as the raw :path, query included. Taking
			// r.URL.Path alone dropped it, so a round trip through both adapters
			// lost every query parameter.
			name:          "the query string is part of the path",
			req:           func() *http.Request { return httptest.NewRequest(http.MethodGet, "/s?q=1&r=2", nil) },
			wantAuthority: "example.com",
			wantScheme:    "http",
			wantPath:      "/s?q=1&r=2",
		},
		{
			// Client-shaped requests still work: this is the form NewHTTPRequest
			// produces on the inbound path, and it must keep round-tripping.
			name: "client-shaped absolute URL still works",
			req: func() *http.Request {
				r, err := http.NewRequest(http.MethodGet, "https://origin.example/a?b=1", nil)
				if err != nil {
					t.Fatalf("building the request: %v", err)
				}
				return r
			},
			wantAuthority: "origin.example",
			wantScheme:    "https",
			wantPath:      "/a?b=1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := HTTPRequestToRequest(tc.req())
			if got.Authority != tc.wantAuthority {
				t.Errorf("Authority = %q, want %q", got.Authority, tc.wantAuthority)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, tc.wantScheme)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
		})
	}
}

// TestAdapterPair_SurvivesAStdlibMux is the composition the adapters exist for
// and the one that answered 400 to everything.
func TestAdapterPair_SurvivesAStdlibMux(t *testing.T) {
	t.Parallel()

	var sawURL string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawURL = r.URL.RequestURI()
		w.WriteHeader(http.StatusTeapot)
	})

	mux := http.NewServeMux()
	mux.Handle("/y", ToHTTPHandler(FromHTTPHandler(inner)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/y?a=1", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418; the adapter pair dropped a server-shaped request", rec.Code)
	}
	if sawURL != "/y?a=1" {
		t.Errorf("inner handler saw %q, want %q — the query did not survive the round trip", sawURL, "/y?a=1")
	}
}

// TestToHTTPHandler_NativeHandlerSeesTheAuthority covers the simpler half: a
// native handler behind the adapter must be able to do virtual-host routing.
func TestToHTTPHandler_NativeHandlerSeesTheAuthority(t *testing.T) {
	t.Parallel()

	var gotAuthority, gotScheme string
	native := HandlerFunc(func(_ context.Context, req *Request, w ResponseWriter) error {
		gotAuthority, gotScheme = req.Authority, req.Scheme
		return w.WriteHeaders(http.StatusOK, nil)
	})

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = "tenant-a.example"
	r.TLS = &tls.ConnectionState{}
	ToHTTPHandler(native).ServeHTTP(httptest.NewRecorder(), r)

	if gotAuthority != "tenant-a.example" {
		t.Errorf("Authority = %q, want %q — Host-based routing is blind without it", gotAuthority, "tenant-a.example")
	}
	if gotScheme != "https" {
		t.Errorf("Scheme = %q, want https for a TLS request", gotScheme)
	}
}
