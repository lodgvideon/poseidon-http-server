#!/usr/bin/env bash
# coverage-gate.sh — fail the build if total statement coverage is below a threshold.
#
# Usage: scripts/coverage-gate.sh [MIN_PERCENT] [PROFILE]
#   MIN_PERCENT  minimum total coverage % (default: $COVERAGE_MIN, else 80)
#   PROFILE      coverage profile file (default: cover.out)
#
# Invoked by `make coverage-gate`, which generates cover.out immediately before
# calling this script. Pure POSIX + awk — no bc dependency (works in CI and Git Bash).
set -euo pipefail

MIN="${1:-${COVERAGE_MIN:-80}}"
PROFILE="${2:-cover.out}"
GO="${GO:-go}"

if [ ! -f "$PROFILE" ]; then
  echo "coverage-gate: profile '$PROFILE' not found — run 'make coverage' first" >&2
  exit 1
fi

# Scope the gate to library packages: exclude non-testable main packages
# (examples/*, cmd/*, loadtest/* tooling) which carry no unit tests and would
# otherwise drag the total below the gate. The "mode:" header line is preserved.
# Override the pattern via COVERAGE_EXCLUDE.
EXCLUDE="${COVERAGE_EXCLUDE:-/(examples|cmd|loadtest)/}"
filtered="$(mktemp 2>/dev/null || echo cover.filtered.out)"
grep -vE "$EXCLUDE" "$PROFILE" > "$filtered" || true

# `go tool cover -func` prints a trailing line like: "total:  (statements)  87.7%"
total_pct="$("$GO" tool cover -func="$filtered" \
  | awk '/^total:/ { gsub(/%/, "", $NF); print $NF }' \
  | tail -n1)"

if [ -z "${total_pct:-}" ]; then
  echo "coverage-gate: could not parse total coverage from '$PROFILE'" >&2
  exit 1
fi

# Fail when coverage < minimum (float-safe comparison via awk exit status).
if awk -v c="$total_pct" -v m="$MIN" 'BEGIN { exit !(c+0 < m+0) }'; then
  printf 'coverage-gate: FAIL — total coverage %s%% is below minimum %s%%\n' "$total_pct" "$MIN" >&2
  exit 1
fi

printf 'coverage-gate: PASS — total coverage %s%% meets minimum %s%%\n' "$total_pct" "$MIN"
