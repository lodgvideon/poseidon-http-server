package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-server/conn"
)

// ---------------------------------------------------------------------------
// Graceful shutdown — GOAWAY + drain
// ---------------------------------------------------------------------------

// ErrShutdownTimeout is returned when Shutdown exceeds the configured timeout.
var ErrShutdownTimeout = errors.New("server: graceful shutdown timed out")

// Shutdown performs a graceful shutdown:
//
//  1. Sends GOAWAY(NO_ERROR) to all active connections.
//  2. Waits for in-flight streams to complete or context to expire.
//  3. Closes all connections and the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	conns := make([]*conn.ServerConn, 0, len(s.conns))
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	// Phase 1: send GOAWAY to all connections.
	var wg sync.WaitGroup
	for _, sc := range conns {
		wg.Add(1)
		go func(c *conn.ServerConn) {
			defer wg.Done()
			_ = c.GoAway(frame.ErrCodeNoError)
		}(sc)
	}
	wg.Wait()

	// Phase 2: wait for drain or timeout.
	timeout := s.opts.GracefulShutdownTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.mu.Lock()
				n := len(s.conns)
				s.mu.Unlock()
				if n == 0 {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case <-drainDone:
		// All drained.
	case <-ctx.Done():
		// Timeout — fall through to force close.
	}

	return s.Close()
}
