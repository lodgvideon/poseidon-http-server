package http3server

import (
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-client/http3"
)

// ---------------------------------------------------------------------------
// The advertised field-section limit, applied to what arrives (#212 group G).
//
// openControlStream advertises SETTINGS_MAX_FIELD_SECTION_SIZE = maxFieldSection
// and encodeResponse has always held this server's own responses to it. Nothing
// applied it inbound: the only bound was the 1 MiB whole-request cap, so a peer
// could send a section sixteen times the advertised size and have every field of
// it decoded and materialised.
// ---------------------------------------------------------------------------

// sectionOf builds a QPACK field section of n fields with the given name and
// value lengths, and returns it with the §4.2.2 size it should be charged.
// The charge is computed with rfc9114FieldOverhead, the test-local 32, not with
// the production fieldLineOverhead — clientsettings_test.go spells that constant
// out precisely "so a wrong one there cannot make these tests agree with it", and
// borrowing the production value here would hand back that independence.
func sectionOf(n, nameLen, valLen int) (section []byte, charged uint64) {
	name := make([]byte, nameLen)
	for i := range name {
		name[i] = 'a' + byte(i%26)
	}
	val := make([]byte, valLen)
	for i := range val {
		val[i] = 'x'
	}
	extra := make([]hpack.HeaderField, 0, n)
	for i := range n {
		// Distinct names, so nothing collapses into one field line.
		nm := append(append([]byte("x-"), []byte(strconv.Itoa(i))...), name...)
		extra = append(extra, hpack.HeaderField{Name: nm, Value: val})
	}
	fields := withFields(extra...)
	for i := range fields {
		charged += uint64(len(fields[i].Name)) + uint64(len(fields[i].Value)) + rfc9114FieldOverhead
	}
	return encodeSection(fields), charged
}

func TestDecodeFields_HoldsTheAdvertisedLimit(t *testing.T) {
	t.Parallel()

	t.Run("under the limit decodes", func(t *testing.T) {
		t.Parallel()
		section, charged := sectionOf(40, 8, 512)
		if charged >= maxFieldSection {
			t.Fatalf("fixture is %d bytes, expected it under the %d-byte limit", charged, maxFieldSection)
		}
		got, err := decodeFields(section)
		if err != nil {
			t.Fatalf("a %d-byte section was refused under a %d-byte limit: %v", charged, maxFieldSection, err)
		}
		if len(got) != 40+len(validFields) {
			t.Errorf("decoded %d fields, want %d", len(got), 40+len(validFields))
		}
	})

	t.Run("over the limit is refused", func(t *testing.T) {
		t.Parallel()
		section, charged := sectionOf(200, 8, 512)
		if charged <= maxFieldSection {
			t.Fatalf("fixture is %d bytes, expected it over the %d-byte limit", charged, maxFieldSection)
		}
		if _, err := decodeFields(section); !errors.Is(err, errRequestFieldsTooLarge) {
			t.Fatalf("err = %v, want errRequestFieldsTooLarge", err)
		}
	})
}

// TestDecodeFields_ChargesTheUncompressedSize is the reason the check sits on the
// decoded fields rather than on the frame's byte length.
//
// §4.2.2 sizes a section on "the uncompressed size of fields, including the
// length of the name and value in bytes plus an overhead of 32 bytes for each
// field". The 32 bytes per field are invisible on the wire, so a section of many
// tiny fields is small as bytes and large as a field section — a peer can blow
// past a 64 KiB limit with a frame of a few KiB. Gating on the frame length
// would miss it entirely.
func TestDecodeFields_ChargesTheUncompressedSize(t *testing.T) {
	t.Parallel()

	// Empty values, one-octet-ish names: almost all of the charge is the
	// per-field overhead.
	section, charged := sectionOf(2100, 0, 0)
	if charged <= maxFieldSection {
		t.Fatalf("fixture charges %d, expected it over the %d-byte limit", charged, maxFieldSection)
	}
	if uint64(len(section)) >= maxFieldSection {
		t.Fatalf("fixture is %d wire bytes; the point is that it is SMALLER than the "+
			"%d-byte limit it exceeds once decoded", len(section), maxFieldSection)
	}
	t.Logf("%d wire bytes decode into a %d-byte field section (limit %d)",
		len(section), charged, maxFieldSection)

	if _, err := decodeFields(section); !errors.Is(err, errRequestFieldsTooLarge) {
		t.Fatalf("err = %v, want errRequestFieldsTooLarge — the limit was measured on "+
			"the compressed bytes, not the field section", err)
	}
}

// TestDecodeRequest_SurfacesTheFieldLimit pins that the verdict survives the
// decode chain, so serveRequest can route it to the 431 answer.
func TestDecodeRequest_SurfacesTheFieldLimit(t *testing.T) {
	t.Parallel()

	section, _ := sectionOf(200, 8, 512)
	req, err := decodeRequest(http3.AppendHeaders(nil, section))
	assertRequestContract(t, req, err)
	if !errors.Is(err, errRequestFieldsTooLarge) {
		t.Fatalf("err = %v, want errRequestFieldsTooLarge", err)
	}
	// Not a malformed message and not a frame-layer fault: neither verdict may
	// claim it, or the peer gets a reset instead of an answer.
	var cfe *connFrameError
	if errors.As(err, &cfe) {
		t.Error("an oversize field section closed the connection")
	}
	if errors.Is(err, http3.ErrH3Message) {
		t.Error("an oversize field section was reported as a malformed message")
	}
}

// TestRefusalBodies_MatchTheirContentLength guards the same drift the 413's body
// comment names: §4.1.2 makes a response whose Content-Length
// disagrees with its DATA malformed, and these two are written in different
// places.
func TestRefusalBodies_MatchTheirContentLength(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		body   []byte
	}{
		"431 field section": {http.StatusRequestHeaderFieldsTooLarge, oversizeFieldsBody},
		"413 request body":  {http.StatusRequestEntityTooLarge, oversizeBody},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Mirrors what refuseWith builds, then reads the field section back off
			// the encoded response — so this checks what a peer would receive, not
			// what the writer was handed.
			rw := &responseWriter{header: http.Header{}, status: tc.status}
			rw.header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			_, _ = rw.body.Write(tc.body)

			fields := decodeResponseFields(t, mustEncode(t, rw))
			if got := string(fields[0].Value); got != strconv.Itoa(tc.status) {
				t.Errorf(":status = %s, want %d", got, tc.status)
			}
			if want, declared := strconv.Itoa(rw.body.Len()), headerValue(fields, "content-length"); declared != want {
				t.Errorf("content-length %q but %s body bytes; §4.1.2 makes that malformed", declared, want)
			}
		})
	}
}

// NOT COVERED END TO END: the 431 reaching a peer.
//
// The enforcement above is unit-tested; the answer is not driven over a real
// connection, and the reason is the harness rather than the code.
//
// A conformant peer cannot produce the input: http3.Client refuses to send a
// section past the peer's SETTINGS_MAX_FIELD_SECTION_SIZE, which is correct of
// it. A hand-rolled dialRawPeer stream did not work either — with the server
// instrumented, readRequestStream saw 0 bytes and timed out, so the request never
// arrived. The mechanism was not run to ground; what is established is only that
// the existing raw-peer helpers, which every other raw test uses to assert
// CONNECTION CLOSURE and nothing else, do not support send-then-receive.
//
// What that leaves untested is refuseOversizeFields, which is refuseOversizeRequest
// with a different status and body — and that one IS covered end to end, by
// TestServer_OversizeRequestIsAnswered (#179). The drift risk between the body and
// its Content-Length is covered above. A raw-peer harness that can both send and
// receive would close the gap and would pay for itself across the other
// raw-stream tests, which today can only assert connection closure.
