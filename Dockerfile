# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Poseidon HTTP server — production container image.
#
# The module uses a RELATIVE replace directive in go.mod:
#
#     replace github.com/lodgvideon/poseidon-http-client => ../poseidon-http-client
#
# so a naive in-image `go build` fails: the sibling repository is not part of
# the Docker build context. The builder stage below resolves this by cloning
# poseidon-http-client into the sibling path that the replace directive points
# at (../poseidon-http-client relative to the copied server source), then
# producing a fully static, CGO-free binary.
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

# Pin the sibling client revision for reproducible builds; override with
# --build-arg client_ref=<sha|tag> when a specific version is required.
ARG client_ref=main

# git is needed to clone the sibling client repo; ca-certificates so the
# module proxy / TLS clone works.
RUN apk add --no-cache git ca-certificates

# Lay the source out so that the go.mod replace target resolves:
#   /src/poseidon-http-server   <- this repo (build context)
#   /src/poseidon-http-client   <- sibling, cloned below
WORKDIR /src/poseidon-http-server

# Clone the sibling client into ../poseidon-http-client (relative to the server
# source), matching the replace directive. Done before COPY so it is cached
# independently of server-source changes.
RUN git clone --depth 1 --branch "${client_ref}" \
        https://github.com/lodgvideon/poseidon-http-client.git \
        /src/poseidon-http-client

# Copy the server module files first to leverage layer caching for deps.
COPY go.mod ./
COPY go.su[m] ./

# Warm the module cache. The server module has no committed go.sum, so allow
# go to resolve and record checksums during the build.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download all || true

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
