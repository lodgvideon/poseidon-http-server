package conn

import (
	"fmt"
	"sync"

	"github.com/lodgvideon/poseidon-http-client/frame"
)

// HeaderSlabPool recycles the byte backing for HPACK-decoded header fields.
var HeaderSlabPool = &sync.Pool{
	New: func() any {
		b := make([]byte, 0, 512)
		return &b
	},
}

// --- serverConnOps implementation on *ServerConn ---

// lookupStream returns the stream for the given ID, or nil.
func (sc *ServerConn) lookupStream(id uint32) *ServerStream {
	sc.smu.Lock()
	defer sc.smu.Unlock()
	return sc.streams[id]
}

// registerStream adds a new stream to the registry and delivers it
// to AcceptStream via acceptCh.
func (sc *ServerConn) registerStream(id uint32, s *ServerStream) {
	sc.smu.Lock()
	sc.streams[id] = s
	sc.smu.Unlock()
	sc.atomicStreamsAccepted.Add(1)

	// Wire the stream back to this conn (needed for handler -> acceptCh).
	s.sc = sc

	select {
	case sc.acceptCh <- s:
	default:
		// Accept channel full — reject the stream.
		_ = s.Close()
	}
}

// markStreamDone cleans up a finished stream.
func (sc *ServerConn) markStreamDone(id uint32) {
	sc.smu.Lock()
	defer sc.smu.Unlock()
	delete(sc.streams, id)
}

// writeSettingsAck sends a SETTINGS ACK.
func (sc *ServerConn) writeSettingsAck() error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WriteSettingsAck(); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// writePingAck echoes a PING with ACK=1.
func (sc *ServerConn) writePingAck(payload [8]byte) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WritePing(true, payload); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// applyPeerSettings applies client SETTINGS after the handshake.
func (sc *ServerConn) applyPeerSettings(s frame.SettingsParams) error {
	const maxWindow = int64(1<<31 - 1)

	sc.psMu.Lock()
	for i := 0; i < s.N; i++ {
		p := s.Pairs[i]
		setPeerSetting(&sc.peerSettings, p.ID, p.Value)
	}
	sc.psMu.Unlock()

	for i := 0; i < s.N; i++ {
		p := s.Pairs[i]
		if p.ID == frame.SettingHeaderTableSize {
			sc.enc.SetMaxDynamicTableSize(p.Value)
		}
	}
	return nil
}

// onWindowUpdate handles inbound WINDOW_UPDATE.
func (sc *ServerConn) onWindowUpdate(streamID, increment uint32) error {
	const maxWindow = int32(1<<31 - 1)
	if streamID == 0 {
		sc.fcOutMu.Lock()
		newVal := int64(sc.peerConnSendWindow) + int64(increment)
		if newVal > int64(maxWindow) {
			sc.fcOutMu.Unlock()
			return fmt.Errorf("WINDOW_UPDATE overflowed connection send window")
		}
		sc.peerConnSendWindow = int32(newVal)
		sc.fcOutCond.Broadcast()
		sc.fcOutMu.Unlock()
		return nil
	}
	// Per-stream window update.
	s := sc.lookupStream(streamID)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	newVal := int64(s.sendWindow) + int64(increment)
	if newVal > int64(maxWindow) {
		s.mu.Unlock()
		return fmt.Errorf("stream %d: WINDOW_UPDATE overflow", streamID)
	}
	s.sendWindow = int32(newVal)
	s.mu.Unlock()
	sc.fcOutMu.Lock()
	sc.fcOutCond.Broadcast()
	sc.fcOutMu.Unlock()
	return nil
}

// onDataReceived debits flow-control windows for an inbound DATA frame.
func (sc *ServerConn) onDataReceived(s *ServerStream, length uint32) error {
	debit := int32(length)

	s.mu.Lock()
	s.recvWindow -= debit
	if s.recvWindow < 0 {
		s.mu.Unlock()
		return fmt.Errorf("stream %d: flow control error", s.id)
	}
	s.recvRefundPending += length
	streamRefund := uint32(0)
	if s.recvRefundPending >= recvWindowRefundThreshold {
		streamRefund = s.recvRefundPending
		s.recvRefundPending = 0
		s.recvWindow += int32(streamRefund)
	}
	s.mu.Unlock()

	sc.fcMu.Lock()
	sc.connRecvWindow -= debit
	if sc.connRecvWindow < 0 {
		sc.fcMu.Unlock()
		return fmt.Errorf("connection flow control error")
	}
	sc.connRefundPending += length
	connRefund := uint32(0)
	if sc.connRefundPending >= recvWindowRefundThreshold {
		connRefund = sc.connRefundPending
		sc.connRefundPending = 0
		sc.connRecvWindow += int32(connRefund)
	}
	sc.fcMu.Unlock()

	if streamRefund > 0 {
		if err := sc.writeWindowUpdate(s.id, streamRefund); err != nil {
			return err
		}
	}
	if connRefund > 0 {
		if err := sc.writeWindowUpdate(0, connRefund); err != nil {
			return err
		}
	}
	return nil
}

// writeWindowUpdate emits a WINDOW_UPDATE frame.
func (sc *ServerConn) writeWindowUpdate(streamID, increment uint32) error {
	if sc.closed.Load() {
		return ErrConnClosed
	}
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if err := sc.fr.WriteWindowUpdate(streamID, increment); err != nil {
		return err
	}
	sc.bumpFramesSent()
	return nil
}

// setPeerSetting merges a SETTINGS pair into params.
func setPeerSetting(params *frame.SettingsParams, id frame.SettingID, val uint32) {
	for i := 0; i < params.N; i++ {
		if params.Pairs[i].ID == id {
			params.Pairs[i].Value = val
			return
		}
	}
	if params.N < len(params.Pairs) {
		params.Pairs[params.N] = frame.SettingPair{ID: id, Value: val}
		params.N++
	}
}
