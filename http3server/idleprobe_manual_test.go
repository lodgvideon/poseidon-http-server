//go:build idleprobe

// This file is the manual idle-bound probe for issue #186.
//
// It is excluded from every default build by the idleprobe tag: the arms below
// wait minutes for a connection to be reaped, which is measurement, not a unit
// test. Run it deliberately:
//
//	go test -tags idleprobe -run TestIdleProbe -timeout 20m -v ./http3server/
//
// What it measures: how long Server.serveConn holds a connection whose peer has
// stopped acknowledging, as a function of Server.IdleTimeout and of whether the
// peer ever acknowledged anything at all. The peer's view of the network is a
// relay this file owns, so "the peer went deaf" is an injected, counted fault
// rather than a hope about scheduling.
package http3server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/quic"
)

// relay is a UDP man-in-the-middle between a test peer and the server under test.
// Datagrams from the peer always reach the server; datagrams from the server reach
// the peer only while the gate is open, which is how "the peer stopped reading its
// socket" becomes a fault this test injects and counts rather than one it assumes.
type relay struct {
	front *net.UDPConn // the peer dials this
	back  *net.UDPConn // connected to the real server
	gate  atomic.Bool  // server->peer datagrams pass while true

	mu       sync.Mutex
	peerAddr *net.UDPAddr

	toServer      atomic.Uint64
	toPeer        atomic.Uint64
	droppedToPeer atomic.Uint64
}

// newRelay starts a relay in front of serverAddr with its gate open.
func newRelay(t *testing.T, serverAddr string) *relay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("relay front: %v", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("relay resolve: %v", err)
	}
	back, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("relay back: %v", err)
	}
	_ = front.SetReadBuffer(4 << 20)
	_ = back.SetReadBuffer(4 << 20)
	r := &relay{front: front, back: back}
	r.gate.Store(true)
	t.Cleanup(func() {
		_ = front.Close()
		_ = back.Close()
	})
	go r.pumpToServer()
	go r.pumpToPeer()
	return r
}

func (r *relay) addr() string { return r.front.LocalAddr().String() }

func (r *relay) pumpToServer() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := r.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.peerAddr = addr
		r.mu.Unlock()
		if _, err := r.back.Write(buf[:n]); err != nil {
			return
		}
		r.toServer.Add(1)
	}
}

func (r *relay) pumpToPeer() {
	buf := make([]byte, 2048)
	for {
		n, err := r.back.Read(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		peer := r.peerAddr
		r.mu.Unlock()
		if peer == nil {
			continue
		}
		if !r.gate.Load() {
			r.droppedToPeer.Add(1)
			continue
		}
		if _, err := r.front.WriteToUDP(buf[:n], peer); err != nil {
			return
		}
		r.toPeer.Add(1)
	}
}

// probeServeConn mirrors Server.serveConn exactly, except that it returns the
// error that ended the connection instead of discarding it. serveConn's own
// return is timed separately (the realServe arm) to show this mirror is faithful;
// the error is what tells an idle close apart from a loss-recovery give-up, and
// serveConn cannot report it.
func probeServeConn(ctx context.Context, s *Server, c *quic.Conn) error {
	defer func() { _ = c.Close() }()
	if err := s.openControlStream(c); err != nil {
		return err
	}
	cs := newConnState()
	cs.tlsState = c.ConnectionState()
	for {
		if err := c.Poll(ctx); err != nil {
			return err
		}
		if err := cs.serviceUni(c); err != nil {
			return err
		}
		for rs := c.AcceptBidiStream(); rs != nil; rs = c.AcceptBidiStream() {
			go s.serveRequest(ctx, c, rs, cs)
		}
	}
}

// arm is one measurement.
type arm struct {
	name string
	idle time.Duration // Server.IdleTimeout
	// peerPolls drives the peer's transport. With the gate shut it can receive
	// nothing, so it still acknowledges nothing after the shut instant.
	peerPolls bool
	// gateShut is when server->peer forwarding stops, measured from just after
	// the peer's Establish returns. Negative means never.
	gateShut time.Duration
	// requestAfter, when positive, has the peer send one conforming request that
	// long after the gate shuts. The peer->server direction still flows, so the
	// server answers; its answer is dropped and so is never acknowledged. This is
	// the ordinary-traffic shape of the same fault: unlike the silent arms the
	// server HAS an RTT sample by now, so it measures the ladder at a realistic
	// ptoBase rather than at the 2*kInitialRtt fallback.
	requestAfter time.Duration
	realServe    bool          // observe Server.serveConn itself rather than the mirror
	budget       time.Duration // give up waiting here and report STILL RUNNING
}

type armResult struct {
	held time.Duration
	err  error
}

func runArm(t *testing.T, a arm) (armResult, *relay) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := &Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		IdleTimeout: a.idle,
	}
	cert, pool := testCert(t)
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := quic.Listen("127.0.0.1:0", srv.TLSConfig, srv.transportParams())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	r := newRelay(t, l.Addr().String())

	done := make(chan armResult, 1)
	go func() {
		c, aerr := l.Accept(ctx)
		if aerr != nil {
			done <- armResult{err: aerr}
			return
		}
		start := time.Now()
		var perr error
		if a.realServe {
			srv.serveConn(ctx, c)
		} else {
			perr = probeServeConn(ctx, srv, c)
		}
		done <- armResult{held: time.Since(start), err: perr}
	}()

	// The peer advertises no max_idle_timeout of its own, so RFC 9000 §10.1 leaves
	// the server's value as the only one in effect.
	dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
	defer dialCancel()
	conn := dialRawPeerIdle(dialCtx, t, r.addr(), pool, 0)
	if a.gateShut >= 0 {
		time.AfterFunc(a.gateShut, func() { r.gate.Store(false) })
	}
	if a.peerPolls {
		go func() {
			for conn.Poll(ctx) == nil { //nolint:revive // driving the peer's transport is the whole body
			}
		}()
	}
	if a.requestAfter > 0 {
		time.AfterFunc(a.gateShut+a.requestAfter, func() {
			rs, err := conn.OpenStream()
			if err != nil {
				return
			}
			_, _ = rs.Send(headersFrame(validFields), true)
		})
	}

	select {
	case res := <-done:
		return res, r
	case <-time.After(a.budget):
		return armResult{held: a.budget, err: errors.New("STILL RUNNING at the budget")}, r
	}
}

func logArm(t *testing.T, a arm, res armResult, r *relay) {
	t.Helper()
	t.Logf("ARM %-22s held=%-14v isIdleTimeout=%v err=%v (%T) | datagrams: s->p fwd=%d dropped=%d, p->s fwd=%d",
		a.name, res.held.Round(10*time.Millisecond),
		errors.Is(res.err, quic.ErrIdleTimeout), res.err, res.err,
		r.toPeer.Load(), r.droppedToPeer.Load(), r.toServer.Load())
}

// TestIdleProbe is the whole measurement. Every arm is the same server, the same
// peer and the same relay; only IdleTimeout and whether the peer ever
// acknowledged anything differ.
//
// The ticket's stated mechanism — RFC 9000 §10.1's idle period floored at three
// backed-off PTOs — predicts an ending error of quic.ErrIdleTimeout at
// lastActivity+3*ptoBase<<8, and NO bound at all when the server advertises no
// max_idle_timeout. The competing account — the PTO ladder itself giving up at
// maxPTOBackoff=8, with ptoBase pinned at 2*kInitialRtt=666ms because a
// server-role quic.Conn is built with a zero rttStats and this peer never lets it
// take a sample — predicts 666ms*(2^9-1) = 340.3s, a plain read timeout rather
// than ErrIdleTimeout, and the SAME hold at every setting including "none".
//
// The ackedOnce arm is the direct test of the ptoBase half: it differs from
// silent/idle=1s in one thing only, that the server received an acknowledgement
// before the peer went deaf. If ptoBase is what sets the scale, that arm must
// come back roughly 25x faster.
func TestIdleProbe(t *testing.T) {
	arms := []arm{
		{name: "silent/idle=1s", idle: time.Second, budget: 480 * time.Second},
		{name: "silent/idle=1s/serveConn", idle: time.Second, realServe: true, budget: 480 * time.Second},
		{name: "silent/idle=30s", idle: 30 * time.Second, budget: 480 * time.Second},
		{name: "silent/idle=none", idle: -1, budget: 480 * time.Second},
		{name: "silent/idle=600s", idle: 600 * time.Second, budget: 480 * time.Second},
		// The peer runs its transport for 300ms, long enough to acknowledge the
		// server's first 1-RTT flight, and only then goes deaf.
		{name: "ackedOnce/idle=1s", idle: time.Second, peerPolls: true, gateShut: 300 * time.Millisecond, budget: 300 * time.Second},
		// ackedOnce, and then one request whose response the peer never sees. This
		// is the ordinary-traffic shape: a client that vanishes mid-exchange.
		{name: "reqThenDeaf/idle=1s", idle: time.Second, peerPolls: true, gateShut: 300 * time.Millisecond,
			requestAfter: 200 * time.Millisecond, budget: 300 * time.Second},
		// Control: nothing is dropped, the peer acknowledges throughout. If this
		// does not close at the advertised value then the instrument, not the
		// server, is what the other arms measured.
		{name: "control/idle=1s", idle: time.Second, peerPolls: true, gateShut: -1, budget: 60 * time.Second},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			res, r := runArm(t, a)
			logArm(t, a, res, r)
		})
	}
}
