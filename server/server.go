package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

var ErrServerClosed = errors.New("server: server closed")

type Logger interface {
	Printf(format string, args ...interface{})
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...interface{}) { log.Printf(format, args...) }

type Options struct {
	Addr                     string
	Handler                  Handler
	HTTPHandler              http.Handler
	Middleware               []Middleware
	ConnOpts                 conn.ServerConnOptions
	MaxConcurrentConnections int
	GracefulShutdownTimeout  time.Duration
	Logger                   Logger

	// H2C enables HTTP/2 cleartext (prior knowledge + HTTP/1.1 Upgrade).
	// When false (default), the server expects direct HTTP/2 connections
	// (typically over TLS). When true, the server detects HTTP/1.1 Upgrade
	// requests and responds with 101 Switching Protocols.
	H2C bool

	// StreamingBody enables io.ReadCloser body instead of buffering.
	// When true, Request.BodyReader is set and Body is nil.
	StreamingBody bool
}

func (o Options) validate() error {
	if o.Handler == nil && o.HTTPHandler == nil {
		return errors.New("server: Handler or HTTPHandler is required")
	}
	return nil
}

func (o Options) resolvedHandler() Handler {
	h := o.Handler
	if h == nil {
		h = FromHTTPHandler(o.HTTPHandler)
	}
	if len(o.Middleware) > 0 {
		h = Chain(o.Middleware...)(h)
	}
	return h
}

type Server struct {
	handler  Handler
	connOpts conn.ServerConnOptions
	opts     Options
	logger   Logger
	mu       sync.Mutex
	closed   bool
	listener net.Listener
	conns    map[*conn.ServerConn]struct{}
	done     chan struct{}
	closeCh  chan struct{}
}

func NewServer(opts Options) (*Server, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = stdLogger{}
	}
	if opts.GracefulShutdownTimeout <= 0 {
		opts.GracefulShutdownTimeout = 30 * time.Second
	}
	return &Server{
		handler:  opts.resolvedHandler(),
		connOpts: opts.ConnOpts,
		opts:     opts,
		logger:   logger,
		conns:    make(map[*conn.ServerConn]struct{}),
		done:     make(chan struct{}),
		closeCh:  make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	s.logger.Printf("poseidon: listening on %s", ln.Addr())
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closeCh:
				return ErrServerClosed
			default:
				return err
			}
		}
		if s.opts.MaxConcurrentConnections > 0 &&
			s.ConnCount() >= s.opts.MaxConcurrentConnections {
			s.logger.Printf("poseidon: rejecting %s: max connections", nc.RemoteAddr())
			nc.Close()
			continue
		}
		go func() {
			if s.opts.H2C {
				s.detectAndServe(ctx, nc)
			} else {
				s.serveConn(ctx, nc)
			}
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, nc net.Conn) {
	opts := s.connOpts
	if opts.StreamEventBuffer <= 0 {
		opts.StreamEventBuffer = 8
	}
	sc, err := conn.NewServerConn(ctx, nc, opts)
	if err != nil {
		s.logger.Printf("poseidon: handshake failed for %s: %v", nc.RemoteAddr(), err)
		nc.Close()
		return
	}
	s.trackConn(sc, true)
	defer s.trackConn(sc, false)
	for {
		stream, err := sc.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.serveStream(ctx, stream)
	}
}

func (s *Server) serveStream(ctx context.Context, stream *conn.ServerStream) {
	var req *Request

	// Read HEADERS first.
	ev, err := stream.Recv(ctx)
	if err != nil {
		return
	}
	if ev.Type != conn.EventHeaders {
		_ = stream.Close()
		return
	}

	req = s.buildRequest(ev.Headers, stream.ID())
	if ev.EndStream {
		s.dispatchAndClose(ctx, stream, req)
		return
	}

	// Streaming mode: attach io.ReadCloser and dispatch immediately.
	if s.opts.StreamingBody {
		req.BodyReader = newStreamBody(ctx, stream)
		s.dispatchAndClose(ctx, stream, req)
		return
	}

	// Buffered mode: collect DATA frames then dispatch.
	s.serveStreamBuffered(ctx, stream, req)
}

// serveStreamBuffered collects DATA/Trailers frames and dispatches.
func (s *Server) serveStreamBuffered(ctx context.Context, stream *conn.ServerStream, req *Request) {
	var bodyChunks [][]byte
	for {
		ev, err := stream.Recv(ctx)
		if err != nil {
			return
		}
		switch ev.Type {
		case conn.EventData:
			if ev.Data != nil {
				bodyChunks = append(bodyChunks, ev.Data)
			}
			if ev.EndStream {
				req.Body = joinChunks(bodyChunks)
				s.dispatchAndClose(ctx, stream, req)
				return
			}
		case conn.EventTrailers:
			req.Trailers = ev.Headers
			if ev.EndStream {
				req.Body = joinChunks(bodyChunks)
				s.dispatchAndClose(ctx, stream, req)
				return
			}
		case conn.EventReset:
			_ = stream.Close()
			return
		case conn.EventHeaders:
			// Extra HEADERS (illegal mid-stream), ignore.
		}
	}
}

func (s *Server) dispatchAndClose(ctx context.Context, stream *conn.ServerStream, req *Request) {
	if req == nil {
		_ = stream.Close()
		return
	}
	w := NewResponseWriter(stream)
	if err := s.handler.ServeHTTP(ctx, req, w); err != nil {
		s.logger.Printf("poseidon: handler error on stream %d: %v", stream.ID(), err)
		if !w.Written() {
			_ = w.WriteHeaders(500, nil)
		}
		_ = stream.Close()
		return
	}
	if !w.Written() {
		_ = w.WriteHeaders(200, nil)
	}
	_ = stream.Close()
}

func (s *Server) buildRequest(headers []hpack.HeaderField, streamID uint32) *Request {
	req := &Request{Headers: headers, streamID: streamID}
	for _, h := range headers {
		switch string(h.Name) {
		case ":method":
			req.Method = string(h.Value)
		case ":path":
			req.Path = string(h.Value)
		case ":scheme":
			req.Scheme = string(h.Value)
		case ":authority":
			req.Authority = string(h.Value)
		}
	}
	return req
}

func joinChunks(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		return nil
	}
	if len(chunks) == 1 {
		return chunks[0]
	}
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func (s *Server) trackConn(sc *conn.ServerConn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[sc] = struct{}{}
	} else {
		delete(s.conns, sc)
	}
}

func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Addr returns the listener address, or nil if not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for sc := range s.conns {
		_ = sc.Close()
		delete(s.conns, sc)
	}
	return nil
}
