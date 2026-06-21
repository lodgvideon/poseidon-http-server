package server

import (
	"strings"
	"testing"
)

// FuzzRequestPath fuzzes the :path -> Path/RawQuery split logic
// (splitPathQuery). It must never panic on arbitrary :path values
// (including ones with multiple '?', no '?', leading/trailing '?',
// embedded NULs, or invalid UTF-8) and must satisfy these invariants:
//
//   - path is a prefix of the input (the bytes before the first '?').
//   - when a '?' is present, input == path + "?" + rawQuery.
//   - when no '?' is present, path == input and rawQuery == "".
//   - splitting only ever happens at the FIRST '?'.
func FuzzRequestPath(f *testing.F) {
	// Seeds: valid + boundary inputs.
	f.Add("/")
	f.Add("")
	f.Add("/api/v1/users")
	f.Add("/api/v1/users?limit=10")
	f.Add("/search?q=a?b=c")       // multiple '?'
	f.Add("?")                     // bare question mark
	f.Add("/path?")               // trailing '?'
	f.Add("?leadingquery")         // leading '?'
	f.Add("/p\x00ath?q=\x00")     // embedded NUL bytes
	f.Add("/\xff\xfe?\xff")        // invalid UTF-8
	f.Add("*")                     // OPTIONS asterisk-form
	f.Add("/very/long/" + strings.Repeat("a", 1024) + "?" + strings.Repeat("b", 1024))

	f.Fuzz(func(t *testing.T, raw string) {
		path, rawQuery := splitPathQuery(raw)

		idx := strings.IndexByte(raw, '?')
		if idx < 0 {
			// No '?': everything is the path, empty query.
			if path != raw {
				t.Fatalf("no '?' but path=%q != raw=%q", path, raw)
			}
			if rawQuery != "" {
				t.Fatalf("no '?' but rawQuery=%q is non-empty", rawQuery)
			}
			return
		}

		// '?' present at idx: reconstruct must equal the original.
		if path != raw[:idx] {
			t.Fatalf("path=%q != raw[:%d]=%q", path, idx, raw[:idx])
		}
		if want := raw[idx+1:]; rawQuery != want {
			t.Fatalf("rawQuery=%q != raw[%d:]=%q", rawQuery, idx+1, want)
		}
		if got := path + "?" + rawQuery; got != raw {
			t.Fatalf("reconstruct %q != raw %q", got, raw)
		}
		// The split must be at the FIRST '?': path must contain no '?'.
		if strings.IndexByte(path, '?') >= 0 {
			t.Fatalf("path %q contains '?' (split not at first occurrence)", path)
		}
	})
}
