#!/usr/bin/env bash
# bench-gate.sh — detect benchmark regressions against a committed baseline using benchstat.
#
# Usage: scripts/bench-gate.sh
# Env:
#   BENCH_BASELINE         baseline file (default: testdata/benchmarks/baseline.txt)
#   BENCH_CURRENT          compare this already-recorded run instead of benchmarking now.
#                          The hook that makes this gate testable on known inputs.
#   BENCH_THRESHOLD        max allowed % regression in sec/op before failing (default: 50)
#   BENCH_ALLOC_THRESHOLD  max allowed % regression in allocs/op (default: 0 — exact)
#   BENCH_GATE_BYTES       set to 1 to gate B/op as well (default: 0 — off, see #99)
#   BENCH_PKGS             packages to benchmark (default: ./...)
#   GO                     go binary (default: go)
#
# Invoked by `make bench-gate`. Behaviour:
#   - No baseline yet            -> record current run as the baseline and PASS.
#   - benchstat not installed    -> soft-pass with an install hint (does not block).
#   - Baseline + benchstat       -> compare; FAIL per the metric policy below.
#
# Metric policy (#126). The three metrics are not equally measurable, so they are
# not gated alike:
#
#   allocs/op — deterministic. An allocation count does not drift with load or
#     thermals, and ADR-0001 promises 0 allocs/op on the native write path. So the
#     gate is exact here: any increase benchstat calls significant is a failure,
#     including a 0 -> N increase, which benchstat renders as "?" because a
#     percentage against a zero baseline is undefined. This is the gate's teeth.
#
#     Note the counterpart cost: benchstat needs enough samples to call a small
#     regression significant, so raise -count rather than lowering the limit.
#
#   sec/op — not deterministic on a shared machine, and the drift is *significant*,
#     not just noisy. Three runs of byte-identical code on the reference host
#     produced +15.7% at p=0.000 in two of the three pairwise comparisons; #126
#     records +38.4% on a busier minute. A limit under that floor fails on
#     scheduling and thermals rather than on code, so the default sits above the
#     largest figure recorded so far. The cost is real and deliberate: a sec/op
#     regression smaller than the limit is invisible to this gate. Lower the floor
#     before lowering the limit — tighten BENCH_THRESHOLD on a dedicated quiet
#     runner once that runner has recorded its own floor (#110).
#
#   B/op — not gated at all today. conn's bench harness charges a 1 MiB drain
#     buffer to the benchmark about half the time (#99), so B/op swings between 0
#     and 1MiB/N on identical code. Set BENCH_GATE_BYTES=1 once #99 is fixed.
#
# Two kinds of row are never failures, for the same reason — benchstat did not
# report a result:
#   - a "~" delta: benchstat could not distinguish the two samples;
#   - the geomean row: an aggregate, carrying no significance test at all.
set -euo pipefail

GO="${GO:-go}"
BASELINE="${BENCH_BASELINE:-testdata/benchmarks/baseline.txt}"
THRESHOLD="${BENCH_THRESHOLD:-50}"
ALLOC_THRESHOLD="${BENCH_ALLOC_THRESHOLD:-0}"
GATE_BYTES="${BENCH_GATE_BYTES:-0}"
PKGS="${BENCH_PKGS:-./...}"

mkdir -p "$(dirname "$BASELINE")"
current="$(mktemp 2>/dev/null || echo bench-current.txt)"

if [ -n "${BENCH_CURRENT:-}" ]; then
  echo "bench-gate: BENCH_CURRENT set — comparing recorded run '$BENCH_CURRENT' (no benchmarks run)."
  cp "$BENCH_CURRENT" "$current"
else
  echo "bench-gate: running benchmarks ($PKGS)…"
  "$GO" test -bench=. -benchmem -benchtime=2s -count=10 -run='^$' "$PKGS" | tee "$current"
fi

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

echo "bench-gate: comparing vs baseline '$BASELINE'"
echo "bench-gate: limits — sec/op +${THRESHOLD}%, allocs/op +${ALLOC_THRESHOLD}%, B/op $([ "$GATE_BYTES" = "1" ] && echo "+${THRESHOLD}%" || echo "not gated (#99)")"
report="bench-gate-report.txt"
benchstat "$BASELINE" "$current" | tee "$report"

# Decide on benchstat's CSV, not on its text table. The CSV puts the delta and the
# significance verdict in fixed columns; scraping the text for "+NN%" (what this
# script used to do) cannot tell a "~" row from a real one, cannot see a "?"
# zero-baseline delta at all — so it missed the 0 -> 1 allocs/op regression that
# ADR-0001 exists to prevent — and counted the geomean row, which has no p-value.
csv="$(mktemp 2>/dev/null || echo bench-gate-report.csv)"
benchstat -format=csv "$BASELINE" "$current" >"$csv" 2>/dev/null

# CSV shape, per metric table:
#   ,<baseline file>,,<current file>,,,
#   ,<metric>,CI,<metric>,CI,vs base,P
#   <name>,<old>,<CI>,<new>,<CI>,<delta>,<p>
#   geomean,<old>,,<new>,,<delta>,
# Fields are read from the right so a benchmark name containing a comma cannot
# shift the columns that matter.
findings="$(mktemp 2>/dev/null || echo bench-gate-findings.txt)"
notes="$(mktemp 2>/dev/null || echo bench-gate-notes.txt)"
gate_rc=0
awk -F, \
  -v t="$THRESHOLD" -v at="$ALLOC_THRESHOLD" -v gb="$GATE_BYTES" -v notes="$notes" '
  NF >= 7 && $(NF-1) == "vs base" { metric = $2; next }   # metric table header
  # A benchmark present in only one of the two runs has no delta columns at all.
  # It is not a failure (benchmarks get added and renamed), but it is also not
  # covered — say so, so a benchmark that stopped running cannot hide a regression.
  NF > 1 && NF < 7 && $1 != "geomean" {
    if (!seen[$1]++) printf "  note: %s ran in only one of the two runs — not compared\n", $1 > notes
    next
  }
  NF < 7  { next }                                        # preamble and blank lines
  $1 == ""        { next }                                # the file-name header row
  $1 == "geomean" { next }                                # aggregate, no significance test
  {
    old = $(NF-5) + 0; new = $(NF-3) + 0; delta = $(NF-1); p = $NF
    name = $1; for (i = 2; i <= NF - 6; i++) name = name "," $i

    if (delta == "") next                   # no comparison on this row
    rows++                                  # a row the gate actually looked at
    if (delta == "~") next                  # benchstat cannot distinguish the samples

    gated = 1
    if (metric == "B/op" && gb + 0 != 1) gated = 0
    limit = (metric == "allocs/op") ? at + 0 : t + 0

    if (delta == "?") {
      # Undefined percentage — one side is zero. Still a real regression for a
      # deterministic counter, so compare the medians directly.
      if (gated && (metric == "allocs/op" || metric == "B/op") && new > old)
        printf "  %-10s %-40s %g -> %g  (%s)  limit +%g%%\n", metric, name, old, new, p, limit
      else if (!gated)
        printf "  note: %s %s %g -> %g not gated (%s)\n", metric, name, old, new, p > notes
      next
    }

    pct = delta; sub(/%$/, "", pct); pct = pct + 0
    if (pct <= 0) next                      # improvement or no change

    if (!gated) {
      printf "  note: %s %s %s not gated (%s)\n", metric, name, delta, p > notes
      next
    }
    if (pct > limit)
      printf "  %-10s %-40s %s  (%s)  limit +%g%%\n", metric, name, delta, p, limit
  }
  # A gate that parses nothing passes everything. Refuse to be that gate.
  END { if (rows + 0 == 0) exit 3 }
' "$csv" >"$findings" || gate_rc=$?

# Rows the gate deliberately did not judge. Never a failure, always said out loud.
if [ -s "$notes" ]; then cat "$notes" >&2; fi

if [ "$gate_rc" -eq 3 ]; then
  echo "bench-gate: ERROR — benchstat produced no comparable benchmark rows." >&2
  echo "bench-gate: baseline and current run share no benchmarks, or benchstat's CSV format changed." >&2
  exit 2
elif [ "$gate_rc" -ne 0 ]; then
  echo "bench-gate: ERROR — could not parse benchstat output (awk exit $gate_rc)." >&2
  exit 2
fi

if [ -s "$findings" ]; then
  echo "bench-gate: FAIL — significant regressions beyond the limit for their metric:" >&2
  cat "$findings" >&2
  exit 1
fi

echo "bench-gate: PASS — no significant regression beyond the limit for its metric."
