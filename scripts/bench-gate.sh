#!/usr/bin/env bash
# bench-gate.sh — detect benchmark regressions against a committed baseline using benchstat.
#
# Usage: scripts/bench-gate.sh
# Env:
#   BENCH_BASELINE   baseline file (default: testdata/benchmarks/baseline.txt)
#   BENCH_THRESHOLD  max allowed % regression before failing (default: 10)
#   BENCH_PKGS       packages to benchmark (default: ./...)
#   GO               go binary (default: go)
#
# Invoked by `make bench-gate`. Behaviour:
#   - No baseline yet            -> record current run as the baseline and PASS.
#   - benchstat not installed    -> soft-pass with an install hint (does not block).
#   - Baseline + benchstat       -> compare; FAIL if any significant regression > threshold.
set -euo pipefail

GO="${GO:-go}"
BASELINE="${BENCH_BASELINE:-testdata/benchmarks/baseline.txt}"
THRESHOLD="${BENCH_THRESHOLD:-10}"
PKGS="${BENCH_PKGS:-./...}"

mkdir -p "$(dirname "$BASELINE")"
current="$(mktemp 2>/dev/null || echo bench-current.txt)"

echo "bench-gate: running benchmarks ($PKGS)…"
"$GO" test -bench=. -benchmem -benchtime=2s -count=10 -run='^$' "$PKGS" | tee "$current"

if [ ! -s "$BASELINE" ]; then
  cp "$current" "$BASELINE"
  echo "bench-gate: no baseline found — recorded current run as baseline at '$BASELINE'."
  echo "bench-gate: commit that file; future runs compare against it. PASS."
  exit 0
fi

if ! command -v benchstat >/dev/null 2>&1; then
  echo "bench-gate: benchstat not installed — skipping regression comparison (soft pass)." >&2
  echo "bench-gate: install with: go install golang.org/x/perf/cmd/benchstat@latest" >&2
  exit 0
fi

echo "bench-gate: comparing vs baseline '$BASELINE' (fail threshold +${THRESHOLD}%)…"
report="bench-gate-report.txt"
benchstat "$BASELINE" "$current" | tee "$report"

# benchstat marks regressions as +NN.NN% (improvements -NN.NN%, insignificant ~).
worst="$(grep -oE '\+[0-9]+(\.[0-9]+)?%' "$report" | tr -d '+%' | sort -gr | head -n1 || true)"

if [ -n "${worst:-}" ] && awk -v w="$worst" -v t="$THRESHOLD" 'BEGIN { exit !(w+0 > t+0) }'; then
  echo "bench-gate: FAIL — largest regression +${worst}% exceeds threshold +${THRESHOLD}%." >&2
  exit 1
fi

echo "bench-gate: PASS — no regression beyond +${THRESHOLD}%."
