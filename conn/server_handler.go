package conn

import (
	"github.com/lodgvideon/poseidon-http-client/frame"
	"github.com/lodgvideon/poseidon-http-client/hpack"
)

// serverConnOps is the contract server_handler.go needs from ServerConn.
type serverConnOps interface {
	lookupStream(id uint32) *ServerStream
	registerStream(id uint32, s *ServerStream)
	markStreamDone(id uint32)
	writeSettingsAck() error
	writePingAck(payload [8]byte) error
	deliverPingAck(payload [8]byte)
	applyPeerSettings(s frame.SettingsParams) error
	onWindowUpdate(streamID, increment uint32) error
	onDataReceived(s *ServerStream, length uint32) error
}

// serverConnHandler bridges frame.Handler into per-ServerStream events.
type serverConnHandler struct {
	streams serverConnOps
	dec     *hpack.Decoder

	scratch          []hpack.HeaderField
	pendingStreamID  uint32
	pendingBuf       []byte
	pendingEndStream bool
	pendingTrailer   bool
}

func newServerConnHandler(streams serverConnOps, dec *hpack.Decoder) *serverConnHandler {
	return &serverConnHandler{
		streams: streams,
		dec:     dec,
		scratch: make([]hpack.HeaderField, 0, 16),
	}
}

func (h *serverConnHandler) OnData(fh frame.FrameHeader, p []byte, _ uint8) error {
	s := h.streams.lookupStream(fh.StreamID)
	if s == nil {
		return nil
	}
	if err := h.streams.onDataReceived(s, fh.Length); err != nil {
		return err
	}
	end := fh.Flags&frame.FlagDataEndStream != 0
	dataCopy := append([]byte(nil), p...)
	if end {
		s.markRemoteEnd()
		h.streams.markStreamDone(fh.StreamID)
	}
	s.push(StreamEvent{Type: EventData, Data: dataCopy, EndStream: end})
	return nil
}

func (h *serverConnHandler) OnHeaders(fh frame.FrameHeader, hb frame.HeaderBlock, _ *frame.Priority, _ uint8) error {
	end := fh.Flags&frame.FlagHeadersEndStream != 0
	endHeaders := fh.Flags&frame.FlagHeadersEndHeaders != 0

	s := h.streams.lookupStream(fh.StreamID)
	isNew := s == nil

	if isNew {
		s = newServerStream(fh.StreamID, 8, nil, int32(connInitialRecvWindow))
		h.streams.registerStream(fh.StreamID, s)
	}

	if !endHeaders {
		h.pendingStreamID = fh.StreamID
		h.pendingBuf = append(h.pendingBuf[:0], hb...)
		h.pendingEndStream = end
		h.pendingTrailer = !isNew && s.headersReceived
		return nil
	}

	isTrailer := false
	if !isNew {
		isTrailer = s.headersReceived
	}

	if !isTrailer {
		s.headersReceived = true
	}
	return h.emitHeaderBlock(s, hb, end, isTrailer)
}

func (h *serverConnHandler) OnContinuation(fh frame.FrameHeader, hb frame.HeaderBlock) error {
	s := h.streams.lookupStream(fh.StreamID)
	if s == nil || h.pendingStreamID != fh.StreamID {
		return nil
	}
	h.pendingBuf = append(h.pendingBuf, hb...)
	if fh.Flags&frame.FlagContinuationEndHeaders == 0 {
		return nil
	}
	end := h.pendingEndStream
	isTrailer := h.pendingTrailer
	if !isTrailer {
		s.headersReceived = true
	}
	return h.emitHeaderBlock(s, h.pendingBuf, end, isTrailer)
}

func (h *serverConnHandler) emitHeaderBlock(s *ServerStream, hb []byte, endStream, isTrailer bool) error {
	h.scratch = h.scratch[:0]
	err := h.dec.DecodeBlock(hb, func(f hpack.HeaderField) error {
		h.scratch = append(h.scratch, f)
		return nil
	})
	if err != nil {
		_ = s.Close()
		return err
	}

	evType := EventHeaders
	if isTrailer {
		evType = EventTrailers
	}
	if endStream {
		s.markRemoteEnd()
		h.streams.markStreamDone(s.id)
	}

	// Copy headers for the event.
	slabPtr := HeaderSlabPool.Get().(*[]byte)
	*slabPtr = (*slabPtr)[:0]
	copied := make([]hpack.HeaderField, len(h.scratch))
	for i, f := range h.scratch {
		nameOff := len(*slabPtr)
		*slabPtr = append(*slabPtr, f.Name...)
		valOff := len(*slabPtr)
		*slabPtr = append(*slabPtr, f.Value...)
		endOff := len(*slabPtr)
		copied[i] = hpack.HeaderField{
			Name:      (*slabPtr)[nameOff:valOff:valOff],
			Value:     (*slabPtr)[valOff:endOff:endOff],
			Sensitive: f.Sensitive,
		}
	}

	s.push(StreamEvent{
		Type:      evType,
		Headers:   copied,
		Slab:      slabPtr,
		EndStream: endStream,
	})
	return nil
}

func (h *serverConnHandler) OnPriority(frame.FrameHeader, frame.Priority) error { return nil }

func (h *serverConnHandler) OnRSTStream(fh frame.FrameHeader, code frame.ErrCode) error {
	s := h.streams.lookupStream(fh.StreamID)
	if s == nil {
		return nil
	}
	s.markRemoteEnd()
	h.streams.markStreamDone(fh.StreamID)
	s.push(StreamEvent{Type: EventReset, RSTCode: code, EndStream: true})
	return nil
}

func (h *serverConnHandler) OnSettings(fh frame.FrameHeader, s frame.SettingsParams) error {
	if fh.Flags&frame.FlagSettingsAck != 0 {
		return nil
	}
	if err := h.streams.applyPeerSettings(s); err != nil {
		return err
	}
	return h.streams.writeSettingsAck()
}

func (h *serverConnHandler) OnPushPromise(frame.FrameHeader, uint32, frame.HeaderBlock, uint8) error {
	// RFC 7540 §8.2: server must not receive PUSH_PROMISE from client.
	// Connection error of type PROTOCOL_ERROR.
	return connError{code: frame.ErrCodeProtocolError, msg: "server received PUSH_PROMISE"}
}

func (h *serverConnHandler) OnPing(fh frame.FrameHeader, payload [8]byte) error {
	if fh.Flags&frame.FlagPingAck != 0 {
		h.streams.deliverPingAck(payload)
		return nil
	}
	return h.streams.writePingAck(payload)
}

func (h *serverConnHandler) OnGoAway(frame.FrameHeader, uint32, frame.ErrCode, []byte) error {
	return nil
}

func (h *serverConnHandler) OnWindowUpdate(fh frame.FrameHeader, increment uint32) error {
	return h.streams.onWindowUpdate(fh.StreamID, increment)
}

// OnOrigin handles ORIGIN frames (RFC 8336). Silently ignored — server side.
func (h *serverConnHandler) OnOrigin(frame.FrameHeader, []string) error { return nil }

func (h *serverConnHandler) OnAltSvc(frame.FrameHeader, []frame.AltSvcEntry) error { return nil }

var _ frame.Handler = (*serverConnHandler)(nil)
