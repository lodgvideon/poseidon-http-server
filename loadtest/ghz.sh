#!/usr/bin/env bash
# ghz.sh — gRPC load test against the Poseidon gRPC example service (h2c).
#
# Targets hello.HelloService/SayHello on a plaintext (h2c) listener. ghz speaks
# HTTP/2 cleartext when invoked with --insecure (no TLS handshake), which matches
# the server's h2c-only transport.
#
# Server under test: examples/grpc-server (listens on :9090, h2c). Start it with:
#   go run ./examples/grpc-server
#
# Tool: ghz (https://ghz.sh). Install:
#   - Go:     go install github.com/bojand/ghz/cmd/ghz@latest
#   - macOS:  brew install ghz
#   - Release binaries: https://github.com/bojand/ghz/releases
#
# Usage:
#   loadtest/ghz.sh [HOST:PORT]
#
# Tunable via environment (with defaults):
#   ADDR         target host:port           (default 127.0.0.1:9090)
#   PROTO        proto file                 (default loadtest/hello.proto)
#   CALL         fully-qualified method     (default hello.HelloService/SayHello)
#   TOTAL        total requests (-n)        (default 100000)
#   CONCURRENCY  concurrent requests (-c)   (default 100)
#   DATA         request JSON payload       (default {"name":"poseidon"})
#   DURATION     run for a fixed time (-z), e.g. 30s — overrides TOTAL when set
#   CONFIG       use a ghz JSON config file instead of CLI flags (e.g. loadtest/ghz.json)
#
# What to read in the output:
#   - "Requests/sec"          → throughput (RPS)
#   - "Latency distribution"  → p50/p90/p95/p99 latency percentiles
#   - "Status code distribution: OK N" → all calls should be OK
#
# Examples:
#   loadtest/ghz.sh
#   CONCURRENCY=200 TOTAL=500000 loadtest/ghz.sh
#   DURATION=30s loadtest/ghz.sh 127.0.0.1:9090
#   CONFIG=loadtest/ghz.json loadtest/ghz.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ADDR="${1:-${ADDR:-127.0.0.1:9090}}"
PROTO="${PROTO:-$HERE/hello.proto}"
CALL="${CALL:-hello.HelloService/SayHello}"
TOTAL="${TOTAL:-100000}"
CONCURRENCY="${CONCURRENCY:-100}"
DATA="${DATA:-{\"name\":\"poseidon\"}}"

if ! command -v ghz >/dev/null 2>&1; then
  cat >&2 <<'EOF'
ghz not found. Install it:
  Go:     go install github.com/bojand/ghz/cmd/ghz@latest
  macOS:  brew install ghz
  Binary: https://github.com/bojand/ghz/releases
EOF
  exit 127
fi

# Config-file mode: let ghz read everything from JSON (host passed on CLI).
if [ -n "${CONFIG:-}" ]; then
  echo "==> ghz (config: ${CONFIG}) ${ADDR}"
  exec ghz --config "$CONFIG" "$ADDR"
fi

# --insecure → plaintext h2c (no TLS). Matches the server's h2c transport.
args=(--insecure --proto "$PROTO" --call "$CALL" -c "$CONCURRENCY" -d "$DATA")

if [ -n "${DURATION:-}" ]; then
  args+=(-z "$DURATION")
else
  args+=(-n "$TOTAL")
fi

echo "==> ghz (h2c, insecure) ${ADDR} ${CALL}"
echo "    concurrency=${CONCURRENCY} proto=${PROTO}"
if [ -n "${DURATION:-}" ]; then
  echo "    duration=${DURATION}"
else
  echo "    total=${TOTAL}"
fi
echo

exec ghz "${args[@]}" "$ADDR"
