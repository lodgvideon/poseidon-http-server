package conn

// Outbound flow-control parking.
//
// A writer that runs out of send credit has to wait for the peer to hand some
// back. What it waits FOR is specific: either its own stream's window
// (RFC 9113 §6.9.1, replenished by a WINDOW_UPDATE naming that stream) or the
// connection window (replenished by a WINDOW_UPDATE on stream 0). Those two
// grants arrive as separate frames and unblock disjoint sets of writers.
//
// This file exists because a sync.Cond cannot express that. Cond has exactly
// two notifications — Signal, which wakes an arbitrary waiter, and Broadcast,
// which wakes all of them — and neither matches the event. Signal is unusable:
// a per-stream WINDOW_UPDATE for stream 7 that happens to wake the writer
// parked on stream 3 leaves stream 7's writer asleep with credit sitting
// unused, and nothing will wake it until the peer sends another frame. So the
// only safe Cond notification is Broadcast, and Broadcast wakes every parked
// writer on the connection so that (typically) one of them can proceed. At 64
// parked streams one WINDOW_UPDATE cost 64 goroutine wakeups, 64 re-acquisitions
// of fcOutMu and 63 immediate re-parks — measured at ~140ns against ~6ns with
// nobody parked (#118).
//
// What this does INSTEAD of broadcasting under a lock: the parked writers are
// held in intrusive linked lists, and each one carries its own single-slot
// wakeup channel. A notifier walks only the writers its grant can actually
// unblock and sends to those. There is no shared condition variable and no
// notify list, so the cost of a grant is proportional to the number of writers
// it releases rather than to the number parked. Concretely:
//
//   - a per-stream WINDOW_UPDATE walks that stream's own short list
//     (ServerStream.fcHead) and touches no other stream;
//   - a connection WINDOW_UPDATE wakes only writers that already hold stream
//     credit, since a connection grant cannot unblock a writer whose own stream
//     window is empty — and skips the walk entirely when there are none;
//   - context cancellation is not a notification at all: the parked writer
//     selects on ctx.Done() itself, which deleted the watchdog goroutine the
//     old slow path spawned per blocking write.
//
// The cost paid for that: parking allocates a waiter node and its channel.
// CLAUDE.md's rule is explicit — "when a design trades a lock for an
// allocation, take the allocation" — and this trade is better than that rule
// requires, because the allocation is not new. The path it replaces already
// allocated a channel AND a goroutine AND a closure per park (see the deleted
// acquireSendCreditsSlow), so a park with a cancellable context, which is every
// park a real handler makes, allocates strictly less than before. Writers that
// never block never touch this file: the node is declared in parkForSendCredits,
// not in acquireSendCredits, so the non-blocking fast path has nothing to
// escape and stays at 0 allocs/op.
//
// LOCKING. Every field below, both link pairs included, is guarded by
// ServerConn.fcOutMu. That is deliberate and load-bearing: it means a wake
// never needs ss.mu, so the documented lock order (fcOutMu, then ss.mu) cannot
// be inverted by a notifier, and no wake path can deadlock against a writer
// debiting its window.

// fcWaiter is one writer parked in acquireSendCredits.
//
// It lives in the parking frame of parkForSendCredits and is linked into two
// lists at once: the connection-wide list rooted at ServerConn.fcHead, and its
// own stream's list rooted at ServerStream.fcHead. Two lists rather than one
// because the two grants ask different questions — "who is on stream 7" and
// "who is waiting on the connection" — and answering either by filtering a
// single list would put the walk back.
type fcWaiter struct {
	ss *ServerStream

	// ready carries wakeups. Capacity one, and every send is non-blocking, so a
	// notifier is never delayed by a waiter that has not run yet and repeated
	// wakeups before the waiter is scheduled collapse into one.
	ready chan struct{}

	// needConn records WHY this writer parked, sampled at park time: true when
	// it holds stream credit and only the connection window is empty. It is the
	// exact predicate fcWakeConn selects on.
	//
	// Sampling can go stale in one direction only — a concurrent writer on the
	// same stream can drain the stream window after this was set — and that
	// direction is safe: the waiter is woken anyway, re-evaluates from scratch
	// and re-parks with needConn false. The unsafe direction, a waiter that
	// should be woken and is not, cannot arise, because the stream window can
	// only GROW under fcOutMu and every site that grows it wakes this stream.
	needConn bool

	// queued makes unlinking idempotent: a waiter that returns from its select
	// unlinks itself without having to know whether a notifier already did.
	queued bool

	connPrev, connNext *fcWaiter
	strPrev, strNext   *fcWaiter
}

// fcPark links w into both lists. Caller holds sc.fcOutMu.
func (sc *ServerConn) fcPark(w *fcWaiter) {
	if w.queued {
		return
	}
	w.queued = true

	w.connPrev = nil
	w.connNext = sc.fcHead
	if sc.fcHead != nil {
		sc.fcHead.connPrev = w
	}
	sc.fcHead = w

	w.strPrev = nil
	w.strNext = w.ss.fcHead
	if w.ss.fcHead != nil {
		w.ss.fcHead.strPrev = w
	}
	w.ss.fcHead = w

	if w.needConn {
		sc.fcConnBlocked++
	}
}

// fcUnpark unlinks w from both lists. Idempotent. Caller holds sc.fcOutMu.
func (sc *ServerConn) fcUnpark(w *fcWaiter) {
	if !w.queued {
		return
	}
	w.queued = false

	if w.connPrev != nil {
		w.connPrev.connNext = w.connNext
	} else {
		sc.fcHead = w.connNext
	}
	if w.connNext != nil {
		w.connNext.connPrev = w.connPrev
	}
	w.connPrev, w.connNext = nil, nil

	if w.strPrev != nil {
		w.strPrev.strNext = w.strNext
	} else {
		w.ss.fcHead = w.strNext
	}
	if w.strNext != nil {
		w.strNext.strPrev = w.strPrev
	}
	w.strPrev, w.strNext = nil, nil

	if w.needConn {
		sc.fcConnBlocked--
	}
}

// fcWake unlinks w and makes it runnable. Caller holds sc.fcOutMu.
//
// Unlinking on wake, rather than leaving the waiter listed until it runs, keeps
// every list to writers that are actually still parked — so a burst of grants
// does not re-walk waiters that are already on their way out.
func (sc *ServerConn) fcWake(w *fcWaiter) {
	sc.fcUnpark(w)
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

// fcWakeAll wakes every parked writer on the connection.
//
// For the two events that change every waiter's answer at once and nothing
// narrower would be correct for: the connection closing, and a
// SETTINGS_INITIAL_WINDOW_SIZE increase, which RFC 9113 §6.9.2 applies
// retroactively to every open stream's send window. Caller holds sc.fcOutMu.
func (sc *ServerConn) fcWakeAll() {
	for w := sc.fcHead; w != nil; {
		next := w.connNext // fcWake unlinks w, so read the link first
		sc.fcWake(w)
		w = next
	}
}

// fcWakeConn wakes writers released by a CONNECTION-level grant.
//
// Only writers that already hold stream credit qualify. A writer whose own
// stream window is empty cannot be helped by connection credit — its available
// send is min(stream, connection) and the stream side is the zero — so waking it
// is pure cost, and it is the majority case whenever a server is streaming
// bodies to many clients at once. When no writer is in that state the counter
// makes this O(1) and the walk never starts. Caller holds sc.fcOutMu.
func (sc *ServerConn) fcWakeConn() {
	if sc.fcConnBlocked == 0 {
		return
	}
	for w := sc.fcHead; w != nil; {
		next := w.connNext
		if w.needConn {
			sc.fcWake(w)
		}
		w = next
	}
}

// fcWakeStream wakes the writers parked on ss after ss's own send window grew.
//
// Walks ss's list only, so a WINDOW_UPDATE for one stream costs nothing on any
// other stream — the whole point of the exercise. Caller holds sc.fcOutMu.
func (sc *ServerConn) fcWakeStream(ss *ServerStream) {
	for w := ss.fcHead; w != nil; {
		next := w.strNext
		sc.fcWake(w)
		w = next
	}
}
