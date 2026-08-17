package conn

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkFCOutStreamGrant measures a PER-STREAM WINDOW_UPDATE against the
// number of streams parked in acquireSendCredits.
//
// Its sibling BenchmarkFCOutCondBroadcast measures the connection-level grant.
// This one measures the other half, and the half #118 names as unambiguous: a
// WINDOW_UPDATE naming stream N can only ever release writers on stream N, so
// every waiter it wakes on any other stream is waste by construction. Nothing
// measured that before this benchmark, which is why the ticket could only quote
// the connection-level figure.
//
// The grant lands on ONE stream while `waiters` streams are parked, so the
// number this reports is "what one stream's WINDOW_UPDATE costs when the
// connection is busy". A design that wakes only the named stream's writers is
// flat in `waiters`; a broadcast is linear in it.
//
// Deliberately shaped to compile against the pre-#118 tree as well, so the
// before/after comparison is one binary swap and not a rewrite: it touches only
// onWindowUpdate, acquireSendCredits, fcOutMu and the two window fields, all of
// which predate the change.
func BenchmarkFCOutStreamGrant(b *testing.B) {
	for _, waiters := range []int{0, 1, 8, 64} {
		b.Run(fmt.Sprintf("waiters=%d", waiters), func(b *testing.B) {
			// One stream per waiter plus one that the measured WINDOW_UPDATE
			// names. The target stream carries no waiter of its own: the cost
			// under test is what the grant pays for the OTHER streams' waiters,
			// and giving it a waiter would add a real wakeup to every iteration
			// and hide exactly that.
			nStreams := waiters + 1
			sc, streams, _ := benchParConn(b, nStreams)
			target := streams[waiters]

			// Park every other stream with no credit of any kind.
			sc.fcOutMu.Lock()
			sc.peerConnSendWindow = 0
			sc.fcOutMu.Unlock()

			var started, finished atomic.Int64
			var wg sync.WaitGroup
			for i := range waiters {
				ss := streams[i]
				ss.mu.Lock()
				ss.sendWindow = 0
				ss.mu.Unlock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					started.Add(1)
					_, _ = sc.acquireSendCredits(context.Background(), ss, 1)
					finished.Add(1)
				}()
			}
			for started.Load() < int64(waiters) {
				time.Sleep(time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond) // let them all reach the park

			b.ResetTimer()
			b.ReportAllocs()
			for i := range b.N {
				if i&0xFFFFF == 0 {
					// Keep the target's window far from 2^31-1 without paying a
					// reset per iteration.
					target.mu.Lock()
					target.sendWindow = 0
					target.mu.Unlock()
				}
				if err := sc.onWindowUpdate(target.id, 1); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			// The parked writers must have stayed parked for the whole measured
			// region: none of them was named by any of those grants, and the only
			// other exits are credit, context and connection close.
			if got := finished.Load(); got != 0 {
				b.Fatalf("%d of %d waiters left acquireSendCredits during the run", got, waiters)
			}
			_ = sc.Close()
			wg.Wait()
		})
	}
}
