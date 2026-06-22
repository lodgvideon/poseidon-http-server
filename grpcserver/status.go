package grpcserver

import (
	"fmt"
	"strconv"
)

// ---------------------------------------------------------------------------
// gRPC Status Codes (google.golang.org/grpc/codes)
// ---------------------------------------------------------------------------

// Code is a gRPC status code.
type Code uint32

const (
	OK                 Code = 0
	Canceled           Code = 1
	Unknown            Code = 2
	InvalidArgument    Code = 3
	DeadlineExceeded   Code = 4
	NotFound           Code = 5
	AlreadyExists      Code = 6
	PermissionDenied   Code = 7
	ResourceExhausted  Code = 8
	FailedPrecondition Code = 9
	Aborted            Code = 10
	OutOfRange         Code = 11
	Unimplemented      Code = 12
	Internal           Code = 13
	Unavailable        Code = 14
	DataLoss           Code = 15
	Unauthenticated    Code = 16
)

// String returns the canonical name of the status code.
func (c Code) String() string {
	switch c {
	case OK:
		return "OK"
	case Canceled:
		return "Canceled"
	case Unknown:
		return "Unknown"
	case InvalidArgument:
		return "InvalidArgument"
	case DeadlineExceeded:
		return "DeadlineExceeded"
	case NotFound:
		return "NotFound"
	case AlreadyExists:
		return "AlreadyExists"
	case PermissionDenied:
		return "PermissionDenied"
	case ResourceExhausted:
		return "ResourceExhausted"
	case FailedPrecondition:
		return "FailedPrecondition"
	case Aborted:
		return "Aborted"
	case OutOfRange:
		return "OutOfRange"
	case Unimplemented:
		return "Unimplemented"
	case Internal:
		return "Internal"
	case Unavailable:
		return "Unavailable"
	case DataLoss:
		return "DataLoss"
	case Unauthenticated:
		return "Unauthenticated"
	default:
		return fmt.Sprintf("Code(%d)", uint32(c))
	}
}

// ---------------------------------------------------------------------------
// gRPC Status
// ---------------------------------------------------------------------------

// RPCStatus holds a gRPC status code and description.
//
//nolint:errname // gRPC convention uses "Status" not "StatusError"
type RPCStatus struct {
	Code    Code
	Message string
}

// Error implements the error interface.
func (s RPCStatus) Error() string {
	return fmt.Sprintf("rpc error: code = %s desc = %s", s.Code, s.Message)
}

// StatusOK returns a success status.
func StatusOK() RPCStatus {
	return RPCStatus{Code: OK, Message: ""}
}

// Statusf creates a status with formatted message.
func Statusf(code Code, format string, args ...any) RPCStatus {
	return RPCStatus{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Trailers (grpc-status, grpc-message, grpc-status-details-bin)
// ---------------------------------------------------------------------------

const (
	HeaderGRPCStatus        = "grpc-status"
	HeaderGRPCMessage       = "grpc-message"
	HeaderGRPCStatusDetails = "grpc-status-details-bin"
	HeaderGRPCTimeout       = "grpc-timeout"
	HeaderContentType       = "content-type"
	ContentTypeGRPC         = "application/grpc"
	HeaderTE                = "te"
)

// StatusToTrailers converts an RPCStatus to HTTP/2 trailer pairs.
func StatusToTrailers(s RPCStatus) [][2]string {
	return [][2]string{
		{HeaderGRPCStatus, strconv.FormatInt(int64(s.Code), 10)},
		{HeaderGRPCMessage, s.Message},
	}
}

// TrailersToStatus extracts an RPCStatus from HTTP/2 trailer pairs.
func TrailersToStatus(trailers [][2]string) RPCStatus {
	st := RPCStatus{Code: Internal, Message: "missing grpc-status"}
	for _, kv := range trailers {
		switch kv[0] {
		case HeaderGRPCStatus:
			code, err := strconv.ParseInt(kv[1], 10, 32)
			if err != nil {
				return Statusf(Internal, "invalid grpc-status: %s", kv[1])
			}
			st.Code = Code(code) //nolint:gosec // code validated by ParseInt range
		case HeaderGRPCMessage:
			st.Message = kv[1]
		}
	}
	return st
}
