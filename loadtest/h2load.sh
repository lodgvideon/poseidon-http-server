#!/usr/bin/env bash
# h2load.sh — HTTP/2 cleartext (h2c) load test against poseidon-server.
#
# Drives the server's "GET /" endpoint over HTTP/2 prior-knowledge (no TLS,
# no Upgrade dance) using h2load from nghttp2. The server is h2c only, so we
# MUST force prior-knowledge with `--h2c` (nghttp2 >= 1.x) which speaks the
# HTTP/2 connection preface directly over cleartext TCP.
#
# Tool: h2load (part of nghttp2). Install:
#   - Debian/Ubuntu: apt-get install -y nghttp2-client
#   - macOS:         brew install nghttp2
#   - Alpine:        apk add nghttp2
#
# Usage:
#   loadtest/h2load.sh [URL]
#
# Tunable via environment (with defaults):
#   URL          target URL                 (default http://127.0.0.1:8080/)
#   REQUESTS     total requests (-n)        (default 100000)
#   CLIENTS      concurrent clients (-c)    (default 100)
#   THREADS      worker threads (-t)        (default 4)
#   MAX_CONCURRENT  max concurrent streams per client (-m) (default 32)
#   WARMUP       warmup duration, e.g. 2s   (default unset)
#   DURATION     run for a fixed time (-D), e.g. 30 — overrides REQUESTS when set
#
# What to read in the output:
#   - "finished in ... req/s"            → throughput (RPS)
#   - "time for request: ... min/max/mean/sd +/- percentile"
#       the mean and the percentile column give p50/p95/p99-style latency
#   - "status codes: N 2xx"              → all responses should be 2xx
#
# Examples:
#   loadtest/h2load.sh
#   REQUESTS=500000 CLIENTS=200 loadtest/h2load.sh
#   DURATION=30 CLIENTS=200 loadtest/h2load.sh http://127.0.0.1:8080/
set -euo pipefail

URL="${1:-${URL:-http://127.0.0.1:8080/}}"
REQUESTS="${REQUESTS:-100000}"
CLIENTS="${CLIENTS:-100}"
THREADS="${THREADS:-4}"
MAX_CONCURRENT="${MAX_CONCURRENT:-32}"

if ! command -v h2load >/dev/null 2>&1; then
  cat >&2 <<'EOF'
h2load not found. Install the nghttp2 client tools:
  Debian/Ubuntu: sudo apt-get install -y nghttp2-client
  macOS:         brew install nghttp2
  Alpine:        apk add nghttp2
EOF
  exit 127
fi

# h2c prior-knowledge: speak HTTP/2 directly over cleartext TCP.
args=(--h2c -t "$THREADS" -c "$CLIENTS" -m "$MAX_CONCURRENT")

if [ -n "${WARMUP:-}" ]; then
  args+=(--warm-up-time "$WARMUP")
fi

if [ -n "${DURATION:-}" ]; then
  # Duration mode: -D runs for N seconds, ignoring -n.
  args+=(-D "$DURATION")
else
  args+=(-n "$REQUESTS")
fi

echo "==> h2load (h2c prior-knowledge) ${URL}"
echo "    clients=${CLIENTS} threads=${THREADS} max-concurrent-streams=${MAX_CONCURRENT}"
if [ -n "${DURATION:-}" ]; then
  echo "    duration=${DURATION}s"
else
  echo "    requests=${REQUESTS}"
fi
echo

exec h2load "${args[@]}" "$URL"
