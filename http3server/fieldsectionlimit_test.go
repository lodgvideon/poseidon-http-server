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
func sectionOf(n, nameLen, valLen int) (section []byte, charged uint64) {
	fields := make([]hpack.HeaderField, 0, n+len(validFields))
	fields = append(fields, validFields...)
	for _, f := range validFields {
		charged += uint64(len(f.Name)) + uint64(len(f.Value)) + fieldLineOverhead
	}
	name := make([]byte, nameLen)
	for i := range name {
		name[i] = 'a' + byte(i%26)
	}
	val := make([]byte, valLen)
	for i := range val {
		val[i] = 'x'
	}
	for i := range n {
		// Distinct names, so nothing collapses into one field line.
		nm := append(append([]byte("x-"), []byte(strconv.Itoa(i))...), name...)
		fields = append(fields, hpack.HeaderField{Name: nm, Value: val})
		charged += uint64(len(nm)) + uint64(len(val)) + fieldLineOverhead
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

// TestOversizeFieldsBody_LengthMatchesItsContentLength guards the same drift the
// 413's body comment names: §4.1.2 makes a response whose Content-Length
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
			var declared string
			for _, f := range fields {
				if string(f.Name) == "content-length" {
					declared = string(f.Value)
				}
			}
			if want := strconv.Itoa(rw.body.Len()); declared != want {
				t.Errorf("content-length %q but %s body bytes; §4.1.2 makes that malformed", declared, want)
			}
		})
	}
}

// NOT COVERED END TO END: the 431 reaching a peer.
//
// The enforcement above is unit-tested; the answer is not driven over a real
// connection, and the reason is the harness rather than the code. A conformant
// peer cannot produce the input — http3.Client refuses to send a section past the
// peer'''s SETTINGS_MAX_FIELD_SECTION_SIZE, which is correct of it — and a
// hand-rolled dialRawPeer stream deadlocks instead: nothing drives the client
// connection'''s transmit side while the test blocks waiting to receive, so the
// request never reaches the server (verified: readRequestStream saw 0 bytes and
// timed out).
//
// What that leaves untested is refuseOversizeFields, which is refuseOversizeRequest
// with a different status and body — and that one IS covered end to end, by
// TestServer_OversizeRequestIsAnswered (#179). The drift risk between the body and
// its Content-Length is covered above. A raw-peer harness that can both send and
// receive would close the gap and would pay for itself across the other
// raw-stream tests, which today can only assert connection closure.
