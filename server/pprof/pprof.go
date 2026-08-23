// Package pprof serves the Go runtime profiling endpoints as a Poseidon
// [server.Handler].
//
// # Why this is not in package server
//
// Importing [net/http/pprof] has a side effect: its init registers seven
// handlers on [http.DefaultServeMux]. While this handler lived in package
// server, that side effect reached every consumer of the library — a blank
// import of the server package was enough to make /debug/pprof/ answer 200 on
// the default mux, serving goroutine stacks, heap contents and the process
// command line to whoever could reach it. Nothing had to call the constructor;
// the import edge alone did it. That was issue #210.
//
// Keeping the import in a leaf package the caller has to name puts the side
// effect where the decision is. If you import this package you have asked for
// pprof; if you do not, package server no longer links it at all — which
// server/pprof_isolation_test.go asserts on every run.
//
// # Exposure
//
// These endpoints expose sensitive runtime internals and must never be
// reachable publicly. Mount them explicitly behind authentication or on a
// private listener:
//
//	import pprofhandler "github.com/lodgvideon/poseidon-http-server/server/pprof"
//
//	srv.Handle("/debug/pprof/", pprofhandler.Handler())
//
// /debug/pprof/profile blocks for the requested duration (30s by default), so
// give the listener carrying it a write timeout that admits it.
package pprof

import (
	"net/http"
	httppprof "net/http/pprof"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// Handler returns a [server.Handler] serving the standard Go runtime profiling
// endpoints:
//
//	/debug/pprof/         — the HTML index, plus the named profiles
//	                        (heap, goroutine, allocs, block, mutex, threadcreate)
//	/debug/pprof/cmdline  — the running program's command line
//	/debug/pprof/profile  — a 30s (or ?seconds=N) CPU profile
//	/debug/pprof/symbol   — symbol lookups for program counters
//	/debug/pprof/trace    — an execution trace
//
// The handler is built over an isolated [http.ServeMux]: it does not read or
// write [http.DefaultServeMux], so what it serves is exactly what is listed
// above regardless of what else the process has registered globally.
func Handler() server.Handler {
	mux := http.NewServeMux()

	// Index handles "/debug/pprof/" and dispatches the named profiles
	// (heap, goroutine, allocs, block, mutex, threadcreate) by trailing path.
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)

	return server.FromHTTPHandler(mux)
}
