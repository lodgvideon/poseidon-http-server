package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/lodgvideon/poseidon-http-server/server"
)

// newJSONLogger returns an *slog.Logger writing JSON records into buf at Debug
// level (so every record is captured), with the time attribute removed so
// records are deterministic.
func newJSONLogger(buf *bytes.Buffer) *slog.Logger {
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return slog.New(h)
}

// decodeRecords parses newline-delimited JSON slog records from buf.
func decodeRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var recs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		recs = append(recs, m)
	}
	return recs
}

// invokeMiddleware runs the middleware once with the given request and a
// handler that sets the supplied status, returning the underlying writer.
func invokeMiddleware(t *testing.T, mw server.Middleware, req *server.Request, status int) {
	t.Helper()
	h := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, w server.ResponseWriter) error {
		return w.WriteHeaders(status, nil)
	}))
	w := newFakeRW()
	if err := h.ServeHTTP(context.Background(), req, w); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
}

func TestStructuredAccessLog_RecordContents(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newJSONLogger(buf)

	// RequestID injects the id into context; chain it before the access log.
	chain := server.Chain(RequestID(), StructuredAccessLog(logger))
	req := &server.Request{Method: "GET", Path: "/users"}
	invokeMiddleware(t, chain, req, 200)

	recs := decodeRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d: %s", len(recs), buf.String())
	}
	r := recs[0]

	if r["method"] != "GET" {
		t.Errorf("method = %v, want GET", r["method"])
	}
	if r["path"] != "/users" {
		t.Errorf("path = %v, want /users", r["path"])
	}
	// JSON numbers decode to float64.
	if got, ok := r["status"].(float64); !ok || int(got) != 200 {
		t.Errorf("status = %v, want 200", r["status"])
	}
	id, ok := r["request_id"].(string)
	if !ok || id == "" {
		t.Errorf("request_id missing or empty: %v", r["request_id"])
	}
	if _, ok := r["duration_ms"]; !ok {
		t.Errorf("duration_ms attribute missing: %v", r)
	}
}

func TestStructuredAccessLog_LevelByStatusClass(t *testing.T) {
	cases := []struct {
		status    int
		wantLevel string
	}{
		{200, "INFO"},
		{204, "INFO"},
		{301, "INFO"},
		{404, "WARN"},
		{499, "WARN"},
		{500, "ERROR"},
		{503, "ERROR"},
	}
	for _, tc := range cases {
		buf := &bytes.Buffer{}
		logger := newJSONLogger(buf)
		mw := StructuredAccessLog(logger)
		req := &server.Request{Method: "GET", Path: "/x"}
		invokeMiddleware(t, mw, req, tc.status)

		recs := decodeRecords(t, buf)
		if len(recs) != 1 {
			t.Fatalf("status %d: expected 1 record, got %d", tc.status, len(recs))
		}
		if recs[0]["level"] != tc.wantLevel {
			t.Errorf("status %d: level = %v, want %v", tc.status, recs[0]["level"], tc.wantLevel)
		}
	}
}

func TestStructuredAccessLog_OmitsEmptyRequestID(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newJSONLogger(buf)
	mw := StructuredAccessLog(logger)
	// No RequestID middleware → empty id → attribute omitted.
	req := &server.Request{Method: "POST", Path: "/y"}
	invokeMiddleware(t, mw, req, 200)

	recs := decodeRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if _, present := recs[0]["request_id"]; present {
		t.Errorf("request_id should be omitted when empty, got %v", recs[0]["request_id"])
	}
}

func TestStructuredAccessLog_LogsOnPanic(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newJSONLogger(buf)
	mw := StructuredAccessLog(logger)

	h := mw(server.HandlerFunc(func(_ context.Context, _ *server.Request, _ server.ResponseWriter) error {
		panic("boom")
	}))
	req := &server.Request{Method: "GET", Path: "/panic"}
	w := newFakeRW()

	defer func() {
		// Panic must propagate (not be swallowed).
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate")
		}
		// And the access log defer should still have emitted a record.
		recs := decodeRecords(t, buf)
		if len(recs) != 1 {
			t.Fatalf("expected 1 record after panic, got %d: %s", len(recs), buf.String())
		}
		if recs[0]["path"] != "/panic" {
			t.Errorf("path = %v, want /panic", recs[0]["path"])
		}
		if recs[0]["status"] != float64(500) {
			t.Errorf("status on panic = %v, want 500", recs[0]["status"])
		}
		if recs[0]["level"] != "ERROR" {
			t.Errorf("level on panic = %v, want ERROR", recs[0]["level"])
		}
	}()

	_ = h.ServeHTTP(context.Background(), req, w)
}

func TestLoggerFromSlog_PrintfProducesRecord(t *testing.T) {
	buf := &bytes.Buffer{}
	slogger := newJSONLogger(buf)

	// LoggerFromSlog returns the legacy Logger interface.
	lg := LoggerFromSlog(slogger)
	lg.Printf("hello %s = %d", "answer", 42)

	recs := decodeRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0]["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", recs[0]["level"])
	}
	if recs[0]["msg"] != "hello answer = 42" {
		t.Errorf("msg = %v, want formatted string", recs[0]["msg"])
	}
}

func TestLoggerFromSlog_RoutesAccessLog(t *testing.T) {
	buf := &bytes.Buffer{}
	slogger := newJSONLogger(buf)

	// Existing Printf-based AccessLog routed through slog without changes.
	mw := AccessLog(LoggerFromSlog(slogger))
	req := &server.Request{Method: "GET", Path: "/legacy"}
	invokeMiddleware(t, mw, req, 200)

	recs := decodeRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	msg, _ := recs[0]["msg"].(string)
	if msg == "" || !strings.Contains(msg, "/legacy") {
		t.Errorf("msg = %q, want it to contain /legacy", msg)
	}
}
