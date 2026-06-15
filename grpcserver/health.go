package grpcserver

import (
	"context"
	"errors"
	"sync"
)

// ---------------------------------------------------------------------------
// gRPC Health Checking Protocol (grpc.health.v1)
//
// Implements the standard gRPC health check service so that k8s liveness/
// readiness probes, service meshes, and grpcurl can verify server health.
//
// ref: https://github.com/grpc/grpc/blob/master/doc/health-checking.md
// ---------------------------------------------------------------------------

// ServingStatus describes the health of a service.
type ServingStatus int32

const (
	// ServingStatusUnknown indicates the service state is unknown.
	ServingStatusUnknown ServingStatus = 0

	// ServingStatusServing indicates the service is healthy and ready.
	ServingStatusServing ServingStatus = 1

	// ServingStatusNotServing indicates the service is not serving.
	ServingStatusNotServing ServingStatus = 2

	// ServingStatusServiceUnknown indicates the service name is not registered.
	ServingStatusServiceUnknown ServingStatus = 3
)

// healthPathCheck is the gRPC path for the Check unary method.
const healthPathCheck = "/grpc.health.v1.Health/Check"

// healthPathWatch is the gRPC path for the Watch server-streaming method.
const healthPathWatch = "/grpc.health.v1.Health/Watch"

// HealthServiceName is the fully qualified gRPC service name.
const HealthServiceName = "grpc.health.v1.Health"

// ErrServiceNotFound is returned when a health check targets an unknown service.
var ErrServiceNotFound = errors.New("grpcserver: service not found in health registry")

// HealthServer implements the grpc.health.v1 health checking protocol.
//
// It tracks per-service ServingStatus and supports both unary Check and
// server-streaming Watch RPCs.
type HealthServer struct {
	mu       sync.RWMutex
	status   map[string]ServingStatus
	watchers map[string][]chan ServingStatus
}

// NewHealthServer creates a HealthServer with all services set to Unknown.
func NewHealthServer() *HealthServer {
	return &HealthServer{
		status:   make(map[string]ServingStatus),
		watchers: make(map[string][]chan ServingStatus),
	}
}

// SetServingStatus updates the health status for a service and notifies
// all active watchers.
func (h *HealthServer) SetServingStatus(service string, status ServingStatus) {
	h.mu.Lock()
	h.status[service] = status
	channels := make([]chan ServingStatus, len(h.watchers[service]))
	copy(channels, h.watchers[service])
	h.mu.Unlock()

	for _, ch := range channels {
		select {
		case ch <- status:
		default:
			// Watcher buffer full — non-blocking send, latest wins.
		}
	}
}

// Status returns the current serving status for a service.
func (h *HealthServer) Status(service string) ServingStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s, ok := h.status[service]; ok {
		return s
	}
	return ServingStatusServiceUnknown
}

// Shutdown marks all services as NotServing and notifies watchers.
func (h *HealthServer) Shutdown() {
	h.mu.Lock()
	services := make([]string, 0, len(h.status))
	for svc := range h.status {
		services = append(services, svc)
	}
	h.mu.Unlock()

	for _, svc := range services {
		h.SetServingStatus(svc, ServingStatusNotServing)
	}
}

// RegisterHealthService registers the health check service on the given
// ServiceRegistrar. The Health service name itself is excluded from health
// tracking.
func (h *HealthServer) RegisterHealthService(r *ServiceRegistrar) {
	r.RegisterService(&ServiceDesc{
		Name: HealthServiceName,
		Methods: []MethodDesc{
			{
				Name: "Check",
				UnaryHandler: func(_ context.Context, reqPayload []byte) ([]byte, error) {
					serviceName := decodeHealthCheckRequest(reqPayload)
					status := h.Status(serviceName)
					return encodeHealthCheckResponse(status), nil
				},
			},
			{
				Name: "Watch",
				ServerStreamH: func(ctx context.Context, reqPayload []byte, send StreamSender) error {
					serviceName := decodeHealthCheckRequest(reqPayload)

					// Send initial status.
					status := h.Status(serviceName)
					if err := send(encodeHealthCheckResponse(status)); err != nil {
						return err
					}

					// Subscribe to updates.
					ch := h.subscribe(serviceName)
					defer h.unsubscribe(serviceName, ch)

					for {
						select {
						case <-ctx.Done():
							return nil
						case s, ok := <-ch:
							if !ok {
								return nil
							}
							if err := send(encodeHealthCheckResponse(s)); err != nil {
								return err
							}
						}
					}
				},
			},
		},
	})
}

func (h *HealthServer) subscribe(service string) chan ServingStatus {
	ch := make(chan ServingStatus, 4)
	h.mu.Lock()
	h.watchers[service] = append(h.watchers[service], ch)
	h.mu.Unlock()
	return ch
}

func (h *HealthServer) unsubscribe(service string, ch chan ServingStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	watchers := h.watchers[service]
	for i, w := range watchers {
		if w == ch {
			h.watchers[service] = append(watchers[:i], watchers[i+1:]...)
			close(ch)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Protobuf wire encoding (zero external deps)
// ---------------------------------------------------------------------------

// decodeHealthCheckRequest extracts the service name from a
// HealthCheckRequest protobuf message.
// Field 1: string service = 1 (wire type 2).
func decodeHealthCheckRequest(data []byte) string {
	return extractStringField(data, 1)
}

// encodeHealthCheckRequest encodes a HealthCheckRequest protobuf message.
// Field 1: string service = 1 (wire type 2).
func encodeHealthCheckRequest(service string) []byte {
	return appendStringField(nil, 1, service)
}

// encodeHealthCheckResponse encodes a HealthCheckResponse protobuf message.
// HealthCheckResponse { HealthCheckResponse.ServingStatus status = 1; }
// ServingStatus is an enum (wire type 0).
func encodeHealthCheckResponse(status ServingStatus) []byte {
	// Field 1, wire type 0 (varint): tag = (1 << 3) | 0 = 0x08
	return []byte{0x08, byte(status)}
}
