package grpcserver

import (
	"testing"
)

func TestCode_String(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{OK, "OK"},
		{Canceled, "Canceled"},
		{Internal, "Internal"},
		{Unimplemented, "Unimplemented"},
		{Code(99), "Code(99)"},
	}
	for _, tt := range tests {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("Code(%d).String() = %q, want %q", uint32(tt.code), got, tt.want)
		}
	}
}

func TestRPCStatus_Error(t *testing.T) {
	s := Statusf(NotFound, "user %d not found", 42)
	want := "rpc error: code = NotFound desc = user 42 not found"
	if s.Error() != want {
		t.Errorf("Error() = %q, want %q", s.Error(), want)
	}
}

func TestStatusToTrailers_OK(t *testing.T) {
	trailers := StatusToTrailers(StatusOK())
	if len(trailers) != 2 {
		t.Fatalf("len = %d, want 2", len(trailers))
	}
	if trailers[0][0] != HeaderGRPCStatus || trailers[0][1] != "0" {
		t.Errorf("status trailer = %v", trailers[0])
	}
}

func TestStatusToTrailers_Error(t *testing.T) {
	s := Statusf(Unavailable, "service down")
	trailers := StatusToTrailers(s)

	st := TrailersToStatus(trailers)
	if st.Code != Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code)
	}
	if st.Message != "service down" {
		t.Errorf("message = %q", st.Message)
	}
}

func TestTrailersToStatus_Missing(t *testing.T) {
	st := TrailersToStatus(nil)
	if st.Code != Internal {
		t.Errorf("code = %v, want Internal", st.Code)
	}
}

func TestTrailersToStatus_InvalidCode(t *testing.T) {
	st := TrailersToStatus([][2]string{{HeaderGRPCStatus, "not-a-number"}})
	if st.Code != Internal {
		t.Errorf("code = %v, want Internal", st.Code)
	}
}

func TestStatusOK(t *testing.T) {
	s := StatusOK()
	if s.Code != OK || s.Message != "" {
		t.Errorf("StatusOK() = %+v", s)
	}
}
