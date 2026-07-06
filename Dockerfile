# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Poseidon HTTP server — production container image.
#
# The builder stage compiles cmd/poseidon-server into a fully static, CGO-free
# binary. Dependencies (including github.com/lodgvideon/poseidon-http-client, a
# normal tagged module dependency) are fetched from the Go module proxy — no
# sibling checkout or replace directive is involved.
#
# Build:
#   docker build \
#     --build-arg version=$(git describe --tags --always --dirty) \
#     --build-arg commit=$(git rev-parse --short HEAD) \
#     --build-arg date=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     -t poseidon-server:latest .
# ---------------------------------------------------------------------------

# ----------------------------- builder stage -------------------------------
FROM golang:1.26-alpine AS builder

# Version metadata injected into the binary via -ldflags (mirrors the Makefile
# `build` target). Defaults keep an unattended `docker build` working.
ARG version=dev
ARG commit=none
ARG date=unknown

# ca-certificates for TLS to the Go module proxy; git for any direct-mode
# (VCS) module fetch fallback.
RUN apk add --no-cache git ca-certificates

WORKDIR /src/poseidon-http-server

# Copy the server module files first to leverage layer caching for deps.
COPY go.mod go.sum ./

# Warm the module cache from the committed go.sum.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy the rest of the server source.
COPY . .

# Build a static binary. CGO_ENABLED=0 + the default Go networking stack yields
# a self-contained executable that runs on distroless/static or scratch.
#   -s -w        strip symbol table and DWARF to shrink the binary
#   -trimpath    drop local filesystem paths for reproducibility
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}" \
        -o /out/poseidon-server \
        ./cmd/poseidon-server

# ----------------------------- runtime stage -------------------------------
# distroless/static:nonroot — no shell, no package manager, minimal attack
# surface. Ships ca-certificates and /etc/passwd with a "nonroot" user (uid
# 65532). The binary is static, so this base is sufficient.
FROM gcr.io/distroless/static:nonroot

# OCI image metadata.
ARG version=dev
ARG commit=none
ARG date=unknown
LABEL org.opencontainers.image.title="poseidon-server" \
      org.opencontainers.image.description="Production-grade HTTP/2 server (h2c by default)" \
      org.opencontainers.image.source="https://github.com/lodgvideon/poseidon-http-server" \
      org.opencontainers.image.version="${version}" \
      org.opencontainers.image.revision="${commit}" \
      org.opencontainers.image.created="${date}"

# Copy ONLY the binary from the builder stage.
COPY --from=builder /out/poseidon-server /usr/local/bin/poseidon-server

# Run as the non-root user provided by the distroless base (uid:gid 65532:65532).
USER nonroot:nonroot

# Default listen address is :8080 (see cmd/poseidon-server: POSEIDON_ADDR).
EXPOSE 8080

# No HEALTHCHECK: the distroless runtime has no shell and the server speaks
# HTTP/2 cleartext (h2c) by default, which a plain `wget`/`curl` HEALTHCHECK
# cannot probe anyway. In Kubernetes, configure liveness/readiness probes
# against the HTTP endpoints /healthz and /readyz (or the gRPC health service
# grpc.health.v1) instead.

ENTRYPOINT ["/usr/local/bin/poseidon-server"]
