package server

import (
	"net/http"
	"sync/atomic"
	"time"
)

// Date response field (RFC 9110 §6.6.1).
//
// RFC 9110 §6.6.1: "An origin server with a clock (as defined in Section
// 5.6.7) MUST generate a Date header field in all 2xx (Successful), 3xx
// (Redirection), and 4xx (Client Error) responses, and MAY generate a Date
// header field in 1xx (Informational) and 5xx (Server Error) responses."
//
// Only the MUST range is generated. 1xx and 5xx are a MAY and are left alone
// deliberately, so the behaviour is a decision rather than an oversight.

// sFieldDate is the lowercase field name, reused rather than re-minted per
// response (ADR-0001).
var sFieldDate = []byte("date")

// dateEntry is one second's worth of formatted Date value. The value is
// immutable once stored, so readers may share it without copying.
type dateEntry struct {
	sec int64
	val []byte
}

// cachedDate holds the most recently formatted Date. Formatting a timestamp
// allocates, and the response header path is on the zero-allocation contract,
// so the result is reused for the whole second it is valid for — the same
// approach net/http takes.
var cachedDate atomic.Pointer[dateEntry]

// httpDate returns now formatted as an HTTP-date (§5.6.7 IMF-fixdate).
//
// Hot path: one atomic load and an integer compare for all but the first call
// in any given second. A race between two goroutines crossing a second boundary
// is benign — both compute the same value for the same second.
func httpDate(now time.Time) []byte {
	sec := now.Unix()
	if e := cachedDate.Load(); e != nil && e.sec == sec {
		return e.val
	}
	val := now.UTC().AppendFormat(make([]byte, 0, len(http.TimeFormat)), http.TimeFormat)
	cachedDate.Store(&dateEntry{sec: sec, val: val})
	return val
}

// dateRequired reports whether RFC 9110 §6.6.1 obliges a Date field for this
// status code: 2xx, 3xx and 4xx.
func dateRequired(status int) bool {
	return status >= 200 && status < 500
}
