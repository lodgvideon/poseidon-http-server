package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServerDoesNotLinkNetHTTPPprof is a regression test for issue #210.
//
// net/http/pprof registers seven handlers on http.DefaultServeMux from its
// init. While PprofHandler lived in this package, that made a *blank import* of
// package server enough to arm /debug/pprof/ on the default mux of every
// consumer — 200, with goroutine stacks, heap contents and the process command
// line. Nothing had to call the constructor. The handler now lives in
// server/pprof, which a caller has to name.
//
// The property is asserted behaviourally rather than by parsing an import list,
// because what actually matters is the state of the default mux in a process
// that imported this package — which is exactly what this test binary is. Any
// future file in package server (or in its non-test dependencies) that pulls in
// net/http/pprof turns this red.
//
// The toolchain view of the same fact, for a human checking by hand:
//
//	go list -deps ./server | grep net/http/pprof   # must print nothing
func TestServerDoesNotLinkNetHTTPPprof(t *testing.T) {
	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace",
		"/debug/pprof/heap",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if _, pattern := http.DefaultServeMux.Handler(req); pattern != "" {
			t.Errorf("http.DefaultServeMux serves %q (pattern %q): package server links "+
				"net/http/pprof again — move the import into server/pprof (issue #210)",
				path, pattern)
		}
	}
}
