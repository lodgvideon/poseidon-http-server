package http3server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// Request-stream frame SEQUENCE (issue #167).
//
// #145 covered which frame TYPES may appear on a request stream. This is the other
// half of RFC 9114 §4.1: the order they may appear in.
//
//	"An HTTP message (request or response) consists of:
//	 1. the header section, including message control data, sent as a single
//	    HEADERS frame,
//	 2. optionally, the content, if present, sent as a series of DATA frames, and
//	 3. optionally, the trailer section, if present, sent as a single HEADERS frame."
//
//	"Receipt of an invalid sequence of frames MUST be treated as a connection error
//	 of type H3_FRAME_UNEXPECTED.  In particular, a DATA frame before any HEADERS
//	 frame, or a HEADERS or DATA frame after the trailing HEADERS frame, is
//	 considered invalid."
//
// Before the fix this server enforced neither clause. The case that matters is DATA
// after the trailing HEADERS: it was concatenated onto the body, so a handler read
// "bodyafter" with ContentLength 9 where a conformant intermediary reading the same
// stream sees a 4-byte body ending at the trailers. That disagreement about where a
// message ends is the shape of a request-smuggling differential, which is why this
// file leads with the test that pins what a handler is handed.
// ---------------------------------------------------------------------------

// trailerFields is a plausible trailer section.
var trailerFields = []hpack.HeaderField{field("x-checksum", "deadbeef")}

// requestFrames assembles a request stream from complete HTTP/3 frames.
func requestFrames(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func headersFrame(fields []hpack.HeaderField) []byte {
	return http3.AppendHeaders(nil, encodeSection(fields))
}

func dataFrame(payload string) []byte {
	return http3.AppendData(nil, []byte(payload))
}

// wantSequenceError asserts decodeRequest refused the stream as a CONNECTION error
// carrying H3_FRAME_UNEXPECTED, and — the security half — that it did not hand back
// a request at all. §4.1 admits no partial acceptance: truncating the message at the
// trailers and serving that would let a handler observe part of a message as if it
// were the whole of one, which is the same disagreement in a quieter form.
func wantSequenceError(t *testing.T, name string, req *http.Request, err error) {
	t.Helper()
	if req != nil {
		body, _ := io.ReadAll(req.Body)
		t.Errorf("%s: decodeRequest served the stream (body=%q, ContentLength=%d); RFC 9114 §4.1 makes "+
			"this sequence a connection error of type H3_FRAME_UNEXPECTED", name, body, req.ContentLength)
	}
	var cfe *connFrameError
	if !errors.As(err, &cfe) {
		t.Errorf("%s: decodeRequest err = %v (%T), want a *connFrameError so the CONNECTION is closed "+
			"rather than the stream reset", name, err, err)
		return
	}
	if cfe.code != http3.H3FrameUnexpected {
		t.Errorf("%s: close code = %#x, want %#x (H3_FRAME_UNEXPECTED)", name, cfe.code, http3.H3FrameUnexpected)
	}
}

// TestDecodeRequest_InvalidSequences pins all three clauses §4.1 names.
func TestDecodeRequest_InvalidSequences(t *testing.T) {
	t.Parallel()

	headers := headersFrame(validFields)
	trailers := headersFrame(trailerFields)

	cases := map[string][]byte{
		// The smuggling shape: a conformant reader ends the body at the trailers.
		"DATA after the trailing HEADERS": requestFrames(headers, dataFrame("body"), trailers, dataFrame("after")),
		// The same clause with no content at all before the trailers.
		"DATA after bodyless trailers": requestFrames(headers, trailers, dataFrame("after")),
		// "a HEADERS ... after the trailing HEADERS frame": a message carries at
		// most two field sections.
		"a third HEADERS frame": requestFrames(headers, trailers, trailers),
		// "a DATA frame before any HEADERS frame".
		"DATA before any HEADERS": requestFrames(dataFrame("early"), headers),
		"DATA before HEADERS, with content after": requestFrames(
			dataFrame("early"), headers, dataFrame("body")),
	}
	for name, stream := range cases {
		req, err := decodeRequest(stream)
		wantSequenceError(t, name, req, err)
	}
}

// TestDecodeRequest_ValidSequencesStillServed is the other direction, and the reason
// the check cannot be "one HEADERS, then DATA, then nothing". §4.1 makes the trailer
// section legal and optional, and §4.1 also says "Frames of unknown types (Section
// 9), including reserved frames (Section 7.2.8) MAY be sent on a request or push
// stream before, after, or interleaved with other frames described in this section"
// — so an unknown frame in any of those positions must not move the sequence state.
// A server that rejected these would kill live traffic, which is the more dangerous
// direction of this fix.
func TestDecodeRequest_ValidSequencesStillServed(t *testing.T) {
	t.Parallel()

	headers := headersFrame(validFields)
	trailers := headersFrame(trailerFields)
	grease := http3.AppendFrameHeader(nil, 0x21, 0) // 0x1f*0 + 0x21

	cases := map[string]struct {
		stream []byte
		body   string
	}{
		"HEADERS only":                        {requestFrames(headers), ""},
		"HEADERS + DATA":                      {requestFrames(headers, dataFrame("body")), "body"},
		"HEADERS + DATA + DATA":               {requestFrames(headers, dataFrame("bo"), dataFrame("dy")), "body"},
		"HEADERS + DATA + trailers":           {requestFrames(headers, dataFrame("body"), trailers), "body"},
		"HEADERS + trailers":                  {requestFrames(headers, trailers), ""},
		"GREASE before HEADERS":               {requestFrames(grease, headers, dataFrame("body")), "body"},
		"GREASE between DATA frames":          {requestFrames(headers, dataFrame("bo"), grease, dataFrame("dy")), "body"},
		"GREASE after the trailing HEADERS":   {requestFrames(headers, dataFrame("body"), trailers, grease), "body"},
		"trailers then GREASE then no others": {requestFrames(headers, trailers, grease), ""},
	}
	for name, tc := range cases {
		req, err := decodeRequest(tc.stream)
		if err != nil {
			t.Errorf("%s: decodeRequest err = %v, want the request served (§4.1)", name, err)
			continue
		}
		body, rerr := io.ReadAll(req.Body)
		if rerr != nil {
			t.Errorf("%s: reading Body: %v", name, rerr)
			continue
		}
		if string(body) != tc.body {
			t.Errorf("%s: body = %q, want %q", name, body, tc.body)
		}
		if req.ContentLength != int64(len(tc.body)) {
			t.Errorf("%s: ContentLength = %d, want %d", name, req.ContentLength, len(tc.body))
		}
	}
}

// TestServer_DataAfterTrailersClosesConnection asserts the verdict reaches the
// connection, over a real QUIC listener, with the exact stream from issue #167.
//
// A pure decoder test cannot reach this half: §4.1 says "connection error", and the
// difference between resetting the stream and closing the connection is the whole
// point — a peer whose stream is merely reset keeps the connection and can retry the
// same trick on the next one. RFC 9114 §8 makes the code observable to the peer by
// construction ("an HTTP/3 implementation can terminate a QUIC connection and
// communicate the reason using an error code from Section 8.1"), so asserting the
// peer sees H3_FRAME_UNEXPECTED asserts what this server sends, not a timing
// accident at the peer.
//
// The handler records anything it is given: after the fix it must never run, and if
// a regression makes it run again the failure names the body it was handed.
func TestServer_DataAfterTrailersClosesConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	served := make(chan string, 4)
	addr, pool := serveTest(ctx, t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		served <- string(body)
	}))
	conn := dialRawPeer(ctx, t, addr, pool)

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ctl.Send(http3.AppendClientControlStream(nil, nil), false); err != nil {
		t.Fatalf("Send control: %v", err)
	}

	rs, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// HEADERS, DATA, trailing HEADERS, DATA — and FIN, so the server reads the whole
	// stream rather than waiting for more.
	stream := requestFrames(headersFrame(validFields), dataFrame("body"),
		headersFrame(trailerFields), dataFrame("after"))
	if _, err := rs.Send(stream, true); err != nil {
		t.Fatalf("Send request: %v", err)
	}

	wantConnClosed(ctx, t, conn, http3.H3FrameUnexpected)

	select {
	case body := <-served:
		t.Fatalf("the handler ran with body %q: the bytes after the trailer section were folded into "+
			"the request body (issue #167)", body)
	default:
	}
}
