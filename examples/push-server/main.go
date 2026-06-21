// Package main demonstrates HTTP/2 Server Push (RFC 7540 §8.2) with priority
// hints (RFC 7540 §5.3) on the Poseidon server.
//
// When a client requests GET /, the handler type-asserts the ResponseWriter to
// server.Pusher and proactively PUSH_PROMISEs the two sub-resources the page
// needs (/style.css and /app.js) BEFORE sending the HTML — so they arrive
// without a second round trip. Each pushed stream carries an RFC 7540 priority
// payload via Pusher.PushWithPriority, so the client can hint that the
// stylesheet (render-blocking) should be served ahead of the script.
//
// Server Push is exposed on the OPTIONAL server.Pusher interface (mirroring
// net/http.Pusher): the core server.ResponseWriter stays small, and a handler
// reaches Push only after a successful type assertion. Push MUST be called
// before the main response headers are written.
//
// NOTE: most browsers have deprecated HTTP/2 Server Push, but it remains valid
// in the protocol and useful between services. Use an HTTP/2 client that
// surfaces pushed streams (e.g. nghttp) to observe the promises:
//
//	go run ./examples/push-server
//	nghttp -ans http://localhost:8080/      # lists the PUSH_PROMISE streams
//	curl --http2-prior-knowledge http://localhost:8080/   # main response only
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/middleware"
	"github.com/lodgvideon/poseidon-http-server/server"
)

const (
	indexHTML = `<!doctype html>
<html><head><link rel="stylesheet" href="/style.css"></head>
<body><h1>Poseidon Push</h1><script src="/app.js"></script></body></html>
`
	styleCSS = "body { font-family: sans-serif; color: #036; }\n"
	appJS    = "console.log('hello from poseidon push');\n"
)

func main() {
	app := server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
		path, _ := splitPath(req.Path)
		switch path {
		case "/style.css":
			return writeBody(w, "text/css", styleCSS)
		case "/app.js":
			return writeBody(w, "application/javascript", appJS)
		case "/":
			// Promise the sub-resources before sending the HTML, if the writer
			// supports push. Push must happen before WriteHeaders/WriteData.
			if p, ok := w.(server.Pusher); ok {
				pushWithPriority(p, "/style.css", "text/css", styleCSS,
					// Render-blocking CSS: highest weight (255), depends on the
					// root stream (0), non-exclusive.
					&frame.Priority{StreamDep: 0, Weight: 255})
				pushWithPriority(p, "/app.js", "application/javascript", appJS,
					// Script: lower weight so the client may favor the CSS.
					&frame.Priority{StreamDep: 0, Weight: 32})
			}
			return writeBody(w, "text/html", indexHTML)
		default:
			return w.WriteHeaders(404, nil)
		}
	})

	srv, err := server.NewServer(server.Options{
		Addr:        ":8080",
		Handler:     app,
		IdleTimeout: 30 * time.Second,
		Middleware: []server.Middleware{
			middleware.Recovery(nil),
			middleware.AccessLog(stdLogger{}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Println("Poseidon push server listening on :8080 (h2c)")
		if err := srv.Serve(ctx, ln); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("draining...")
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	_ = srv.Shutdown(drainCtx)
	log.Println("bye")
}

// pushWithPriority promises one sub-resource with a priority hint and writes its
// body on the pushed stream. Errors are logged, not fatal: push is best-effort
// (the client may refuse, or the writer may not support it).
func pushWithPriority(p server.Pusher, path, contentType, body string, prio *frame.Priority) {
	pushed, err := p.PushWithPriority(path, nil, prio)
	if err != nil {
		log.Printf("push %s: %v", path, err)
		return
	}
	if err := writeBody(pushed, contentType, body); err != nil {
		log.Printf("push body %s: %v", path, err)
	}
}

// writeBody sends a complete response with a content-type header and a body.
func writeBody(w server.ResponseWriter, contentType, body string) error {
	headers := []hpack.HeaderField{
		{Name: []byte("content-type"), Value: []byte(contentType)},
	}
	if err := w.WriteHeaders(200, headers); err != nil {
		return err
	}
	return w.WriteData([]byte(body))
}

// splitPath returns the path component of a raw :path value, dropping the query.
func splitPath(raw string) (path, query string) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '?' {
			return raw[:i], raw[i+1:]
		}
	}
	return raw, ""
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...interface{}) { log.Printf(format, args...) }
